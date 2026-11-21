package hscontrol

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"regexp"
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
// person to go back to Safari and shows a code; there the person types it,
// and the device waiting from the same network with that code is connected,
// where the invitation is.
//
// The code is what tells devices apart, never the list: an iPad and an iPhone
// of one home wait from the same address, both named «iOS», and the iPad
// connected the iPhone from a list of buttons (measured 21/11).
const (
	pairPath      = "/join/pair"
	pairCodeField = "code"
	waitingTTL    = 10 * time.Minute
	waitingSize   = 1024
	// Codes are 4 digits; after this many wrong ones from an address, pairing
	// from it stops until its waits expire, so guessing a neighbour's device
	// on a shared network is 5 tries in 9000.
	pairMaxWrong = 5
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

// appleModel matches Apple's hardware identifiers ("iPhone15,4", "iPad13,4").
var appleModel = regexp.MustCompile(`^(iPhone|iPad|iPod|Mac|Watch)\d+,\d+$`)

// freeCode is a pairing code no other device waiting from ip shows, so a
// code names one device on that network.
func (f *inviteFlow) freeCode(ip string) (string, error) {
	for {
		code, err := pairCode()
		if err != nil {
			return "", err
		}

		if _, taken := f.waitingWith(ip, code); !taken {
			return code, nil
		}
	}
}

// deviceModel names the model for a person: "iPhone" rather than
// "iPhone15,4". When the app does not report one, the login browser does:
// an iPhone says so, and iPadOS browses as a Mac, so iOS plus "Macintosh" is
// an iPad.
func deviceModel(os, model, userAgent string) string {
	if m := appleModel.FindStringSubmatch(model); m != nil {
		return m[1]
	}

	if model != "" {
		return model
	}

	switch {
	case strings.Contains(userAgent, "iPad"):
		return "iPad"
	case strings.Contains(userAgent, "iPhone"):
		return "iPhone"
	case os == "iOS" && strings.Contains(userAgent, "Macintosh"):
		return "iPad"
	}

	return ""
}

// deviceLabel names the device for a person. iOS reports "localhost" as its
// hostname, so the model and the system go first.
func deviceLabel(data *types.RegistrationData, userAgent string) string {
	if data == nil {
		return ""
	}

	var parts []string

	if hi := data.Hostinfo; hi != nil {
		if model := deviceModel(hi.OS, hi.DeviceModel, userAgent); model != "" {
			parts = append(parts, model)
		}

		if hi.OS != "" {
			parts = append(parts, hi.OS)
		}
	}

	if data.Hostname != "" && !strings.EqualFold(data.Hostname, "localhost") {
		parts = append(parts, data.Hostname)
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, " · ")
}

// returnToSafari answers /register without an invitation. A web-auth
// registration gets the "finish in Safari" page with its code; anything else
// (OIDC, SSH check) goes to the provider, unchanged.
func (f *inviteFlow) returnToSafari(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	if _, web := f.h.authProvider.(*AuthProviderWeb); !web {
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
		ip := clientIP(req)

		code, err := f.freeCode(ip)
		if err != nil {
			httpUserError(w, err)

			return
		}

		wd = waitingDevice{
			authID: authID,
			ip:     ip,
			code:   code,
			device: deviceLabel(authReq.RegistrationData(), req.UserAgent()),
			since:  time.Now(),
		}
		f.waiting.Add(authID, wd)
	}

	renderInvite(w, http.StatusOK, templates.InviteReturn(templates.InviteReturnInfo{
		Device:       wd.device,
		Code:         wd.code,
		AdminCommand: "headscale auth register --auth-id " + authID.String() + " --user USUARIO",
	}))
}

// waitingFrom lists the devices still waiting from ip.
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

	return out
}

// waitingWith is the device waiting from ip whose app shows code.
func (f *inviteFlow) waitingWith(ip, code string) (waitingDevice, bool) {
	for _, wd := range f.waitingFrom(ip) {
		if subtle.ConstantTimeCompare([]byte(wd.code), []byte(code)) == 1 {
			return wd, true
		}
	}

	return waitingDevice{}, false
}

// addPairForm puts the code form on the invitation page when a device waits
// from this network, with a form token bound to the invitation's key.
func (f *inviteFlow) addPairForm(w http.ResponseWriter, req *http.Request, pak *types.PreAuthKey, info *templates.InviteStepsInfo, wrongCode bool) error {
	if len(f.waitingFrom(clientIP(req))) == 0 {
		return nil
	}

	random, err := util.GenerateRandomStringURLSafe(32)
	if err != nil {
		return err
	}

	csrf := random + "." + strconv.FormatUint(pak.ID, 10)
	f.setCookie(w, req, inviteCSRFCookie, pairPath, csrf, inviteCSRFMaxAge)

	info.Pair = &templates.InvitePair{
		FormAction:    pairPath,
		CSRFTokenName: inviteCSRFCookie,
		CSRFToken:     csrf,
		CodeName:      pairCodeField,
		WrongCode:     wrongCode,
	}

	return nil
}

type pairResult int

const (
	pairMatched pairResult = iota
	pairWrong
	pairLocked
)

// tryCode is one pairing attempt from ip. Reading the wrong count, comparing
// and writing the count happen under one lock: the form token serves many
// attempts, so parallel POSTs would otherwise all read the same count. The
// wrong count is never reset by time inside the window, so attempt number
// pairMaxWrong+1 and every one after it is locked.
func (f *inviteFlow) tryCode(ip, code string) (waitingDevice, pairResult) {
	f.pairMu.Lock()
	defer f.pairMu.Unlock()

	wrong, _ := f.wrongCodes.Get(ip)
	if wrong >= pairMaxWrong {
		return waitingDevice{}, pairLocked
	}

	wd, ok := f.waitingWith(ip, code)
	if !ok {
		f.wrongCodes.Add(ip, wrong+1)

		return waitingDevice{}, pairWrong
	}

	f.wrongCodes.Remove(ip)

	return wd, pairMatched
}

// PairHandler serves POST /join/pair: from Safari, the person types the code
// the app shows, and only the device waiting from this same network with
// that code is connected.
func (f *inviteFlow) PairHandler(w http.ResponseWriter, req *http.Request) {
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

	wd, status := f.tryCode(clientIP(req), strings.TrimSpace(req.PostFormValue(pairCodeField))) //nolint:gosec // bounded by confirmed

	switch status {
	case pairLocked:
		renderInvite(w, http.StatusTooManyRequests, templates.InviteError(templates.InvitePairLocked))

		return
	case pairWrong:
		f.showSteps(w, req, pak, http.StatusUnprocessableEntity, true)

		return
	}

	cookie, _ := req.Cookie(inviteCookie)
	f.finish(w, req, wd.authID, pak, cookie.Value, pairPath)
}
