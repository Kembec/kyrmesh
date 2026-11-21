package hscontrol

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

// Pairing from Safari (KEM-471). On iPhone the Tailscale app opens the login
// page in a browser that does not see the invitation Safari stored, so the
// device reached /register without it and the person was shown an admin
// command (measured on the first real iPhone, 20/11). Now that page tells the
// person to go back to Safari and shows a code; the invitation page in Safari
// lists the devices waiting from the same network, each with its code, and
// connecting one happens there, where the invitation is.
const (
	pairPath       = "/join/pair"
	waitingTTL     = 10 * time.Minute
	waitingSize    = 1024
	waitingListMax = 5
)

type waitingDevice struct {
	authID types.AuthID
	ip     string
	code   string
	device string
	since  time.Time
}

// clientIP is the address the request came from; behind a trusted proxy the
// real-IP middleware has already rewritten RemoteAddr.
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}

	return host
}

// pairCode is what the app's page shows and Safari repeats next to the device.
func pairCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return "", fmt.Errorf("generating pairing code: %w", err)
	}

	return strconv.FormatInt(n.Int64()+1000, 10), nil
}

// deviceLabel names the device for a person. iOS reports "localhost" as its
// hostname, so the model and the system go first.
func deviceLabel(data *types.RegistrationData) string {
	if data == nil {
		return "Dispositivo"
	}

	var parts []string

	if hi := data.Hostinfo; hi != nil {
		if hi.DeviceModel != "" {
			parts = append(parts, hi.DeviceModel)
		}

		if hi.OS != "" {
			parts = append(parts, hi.OS)
		}
	}

	if data.Hostname != "" && !strings.EqualFold(data.Hostname, "localhost") {
		parts = append(parts, data.Hostname)
	}

	if len(parts) == 0 {
		return "Dispositivo"
	}

	return strings.Join(parts, " · ")
}

// returnToSafari answers /register without an invitation. A web-auth
// registration gets the "finish in Safari" page with its code; anything else
// (OIDC, SSH check) goes to the provider, unchanged.
func (f *inviteFlow) returnToSafari(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	if !f.webProvider {
		next(w, req)

		return
	}

	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(w, err)

		return
	}

	authReq, ok := f.h.state.GetAuthCacheEntry(authID)
	if !ok || !authReq.IsRegistration() {
		next(w, req)

		return
	}

	wd, ok := f.waiting.Get(authID)
	if !ok {
		code, err := pairCode()
		if err != nil {
			httpUserError(w, err)

			return
		}

		wd = waitingDevice{
			authID: authID,
			ip:     clientIP(req),
			code:   code,
			device: deviceLabel(authReq.RegistrationData()),
			since:  time.Now(),
		}
		f.waiting.Add(authID, wd)
	}

	renderInvite(w, http.StatusOK, templates.InviteReturn(templates.InviteReturnInfo{
		Code:         wd.code,
		AdminCommand: "headscale auth register --auth-id " + authID.String() + " --user USUARIO",
	}))
}

// waitingFrom lists the devices still waiting from ip, newest first.
func (f *inviteFlow) waitingFrom(ip string) []waitingDevice {
	var out []waitingDevice

	for _, id := range f.waiting.Keys() {
		wd, ok := f.waiting.Peek(id)
		if !ok || wd.ip != ip {
			continue
		}

		if _, pending := f.h.state.GetAuthCacheEntry(id); !pending {
			continue
		}

		out = append(out, wd)
	}

	slices.SortFunc(out, func(a, b waitingDevice) int { return b.since.Compare(a.since) })

	return out[:min(len(out), waitingListMax)]
}

// addWaiting puts the devices waiting from this network on the invitation
// page, with a form token bound to the invitation's key.
func (f *inviteFlow) addWaiting(w http.ResponseWriter, req *http.Request, pak *types.PreAuthKey, info *templates.InviteStepsInfo) error {
	waiting := f.waitingFrom(clientIP(req))
	if len(waiting) == 0 {
		return nil
	}

	random, err := util.GenerateRandomStringURLSafe(32)
	if err != nil {
		return err
	}

	csrf := random + "." + strconv.FormatUint(pak.ID, 10)
	f.setCookie(w, req, inviteCSRFCookie, pairPath, csrf, inviteCSRFMaxAge)

	for _, wd := range waiting {
		info.Waiting = append(info.Waiting, templates.InviteWaitingDevice{
			Device:        wd.device,
			Code:          wd.code,
			FormAction:    pairPath + "/" + wd.authID.String(),
			CSRFTokenName: inviteCSRFCookie,
			CSRFToken:     csrf,
		})
	}

	return nil
}

// PairHandler serves POST /join/pair/{auth_id}: from Safari, the person
// connects the device that is waiting from the same network.
func (f *inviteFlow) PairHandler(w http.ResponseWriter, req *http.Request) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(w, err)

		return
	}

	token, ok := f.confirmed(w, req)
	if !ok {
		renderInvite(w, http.StatusForbidden, templates.InviteError(templates.InviteNotConfirmed))

		return
	}

	pak, problem := f.stored(req)
	if problem != "" {
		f.clearCookie(w, req, inviteCookie, "/")
		renderInvite(w, http.StatusForbidden, templates.InviteError(problem))

		return
	}

	if !strings.HasSuffix(token, "."+strconv.FormatUint(pak.ID, 10)) {
		renderInvite(w, http.StatusForbidden, templates.InviteError(templates.InviteNotConfirmed))

		return
	}

	// Only a device that is waiting from this same network can be paired.
	wd, ok := f.waiting.Get(authID)
	if !ok || wd.ip != clientIP(req) {
		renderInvite(w, http.StatusForbidden, templates.InviteError(templates.InviteDeviceUnknown))

		return
	}

	cookie, _ := req.Cookie(inviteCookie)
	f.finish(w, req, authID, pak, cookie.Value, pairPath)
}
