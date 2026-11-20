package hscontrol

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// An invitation is a single-use pre-auth key delivered as a link,
// <server_url>/join?code=<key>. Opening it stores the key in an HttpOnly
// cookie; when the Tailscale app later opens /register/{auth_id} in the same
// browser, the person confirms and the device registers with that key, so
// its user, tags, expiry and revocation are the key's (KEM-456).
//
// The key travels in the query string because the request log records
// r.URL.Path only; the landing page redirects to /join at once, so the key
// does not stay in the address bar or the browser history.
const (
	inviteCookie     = "kyrmesh_invite"
	inviteCSRFCookie = "kyrmesh_invite_csrf"
	inviteCodeParam  = types.InviteCodeParam
	inviteKeyPrefix  = "hskey-auth-"

	// A pre-auth key is ~80 characters; anything far longer is not one and
	// never reaches the database.
	inviteCodeMaxLen = 256
	// Two hours covers installing the app; after that the person opens the
	// link again. A longer life kept /register showing the invitation's
	// confirmation for days on that browser (independent review, 20/11).
	inviteCookieMaxAge = 2 * time.Hour
	inviteCSRFMaxAge   = 15 * time.Minute
	// The status page keeps answering for a finished registration this long.
	inviteDoneTTL  = 15 * time.Minute
	inviteDoneSize = 1024
)

type inviteFlow struct {
	h         *Headscale
	serverURL string
	// done maps a finished auth_id to the node it registered.
	done *expirable.LRU[types.AuthID, types.NodeID]
}

func newInviteFlow(h *Headscale, serverURL string) *inviteFlow {
	return &inviteFlow{
		h:         h,
		serverURL: strings.TrimSuffix(serverURL, "/"),
		done:      expirable.NewLRU[types.AuthID, types.NodeID](inviteDoneSize, nil, inviteDoneTTL),
	}
}

// check returns the invitation's key, or the problem that makes it unusable.
func (f *inviteFlow) check(code string) (*types.PreAuthKey, string) {
	if code == "" || len(code) > inviteCodeMaxLen || !strings.HasPrefix(code, inviteKeyPrefix) {
		return nil, templates.InviteInvalid
	}

	pak, err := f.h.state.GetPreAuthKey(code)
	if err != nil {
		return nil, templates.InviteInvalid
	}

	// A reusable key would let one link register any number of devices.
	if pak.Reusable {
		return nil, templates.InviteInvalid
	}

	if pak.Used {
		return nil, templates.InviteUsed
	}

	if pak.Expiration != nil && !pak.Expiration.After(time.Now()) {
		return nil, templates.InviteExpired
	}

	if err := pak.Validate(); err != nil { //nolint:noinlineerr
		return nil, templates.InviteInvalid
	}

	return pak, ""
}

// JoinHandler serves /join: with ?code= it validates the invitation, stores
// it and redirects to the bare page; without it, it shows the steps for the
// stored invitation.
func (f *inviteFlow) JoinHandler(w http.ResponseWriter, req *http.Request) {
	if code := req.URL.Query().Get(inviteCodeParam); code != "" {
		pak, problem := f.check(code)
		if problem != "" {
			f.clearCookie(w, req, inviteCookie, "/")
			renderInvite(w, http.StatusForbidden, templates.InviteError(problem))

			return
		}

		maxAge := inviteCookieMaxAge
		if pak.Expiration != nil {
			maxAge = min(maxAge, time.Until(*pak.Expiration))
		}

		f.setCookie(w, req, inviteCookie, "/", code, maxAge)
		http.Redirect(w, req, "/join", http.StatusSeeOther)

		return
	}

	pak, problem := f.stored(req)
	if problem != "" {
		renderInvite(w, http.StatusOK, templates.InviteError(problem))

		return
	}

	expires := ""
	if pak.Expiration != nil {
		expires = pak.Expiration.Local().Format(" y vence el 02/01/2006 a las 15:04")
	}

	renderInvite(w, http.StatusOK, templates.InviteSteps(templates.InviteStepsInfo{
		User:      inviteOwner(pak),
		Expires:   expires,
		ServerURL: f.serverURL,
	}))
}

// stored returns the invitation kept in the cookie, or why there is none.
func (f *inviteFlow) stored(req *http.Request) (*types.PreAuthKey, string) {
	cookie, err := req.Cookie(inviteCookie)
	if err != nil || cookie.Value == "" {
		return nil, templates.InviteMissing
	}

	return f.check(cookie.Value)
}

// RegisterHandler wraps the provider's /register/{auth_id}: with an
// invitation in the browser it shows the confirmation instead; without one
// the provider's own page answers, unchanged.
func (f *inviteFlow) RegisterHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if cookie, err := req.Cookie(inviteCookie); err != nil || cookie.Value == "" {
			next(w, req)

			return
		}

		authID, err := authIDFromRequest(req)
		if err != nil {
			httpUserError(w, err)

			return
		}

		pak, problem := f.stored(req)
		if problem != "" {
			f.clearCookie(w, req, inviteCookie, "/")
			renderInvite(w, http.StatusForbidden, templates.InviteError(problem))

			return
		}

		authReq, ok := f.h.state.GetAuthCacheEntry(authID)
		if !ok {
			renderInvite(w, http.StatusGone, templates.InviteError(templates.InviteRequestExpired))

			return
		}

		if !authReq.IsRegistration() {
			next(w, req)

			return
		}

		random, err := util.GenerateRandomStringURLSafe(32)
		if err != nil {
			httpUserError(w, err)

			return
		}

		// The token names the key the page showed, so swapping the stored
		// invitation before the click cannot register with another one.
		csrf := random + "." + strconv.FormatUint(pak.ID, 10)
		action := "/join/register/" + authID.String()
		f.setCookie(w, req, inviteCSRFCookie, action, csrf, inviteCSRFMaxAge)

		regData := authReq.RegistrationData()

		os := ""
		if regData.Hostinfo != nil {
			os = regData.Hostinfo.OS
		}

		renderInvite(w, http.StatusOK, templates.InviteConfirm(templates.InviteConfirmInfo{
			FormAction:    action,
			CSRFTokenName: inviteCSRFCookie,
			CSRFToken:     csrf,
			User:          inviteOwner(pak),
			Hostname:      regData.Hostname,
			OS:            os,
			ForgetURL:     "/join/forget/" + authID.String(),
		}))
	}
}

// ForgetHandler serves /join/forget/{auth_id}: "this is not my invitation".
// It drops the stored invitation and sends the browser back to the
// provider's own /register page.
func (f *inviteFlow) ForgetHandler(w http.ResponseWriter, req *http.Request) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(w, err)

		return
	}

	f.clearCookie(w, req, inviteCookie, "/")
	http.Redirect(w, req, "/register/"+authID.String(), http.StatusSeeOther)
}

// JoinRegisterHandler serves POST /join/register/{auth_id}: the person
// confirmed, so the waiting device registers with the stored invitation.
func (f *inviteFlow) JoinRegisterHandler(w http.ResponseWriter, req *http.Request) {
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

	cookie, _ := req.Cookie(inviteCookie)

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

	node, nodeChange, err := f.h.state.HandleNodeFromInvite(authID, cookie.Value)
	if err != nil {
		f.registerFailed(w, req, err)

		return
	}

	if !node.Valid() {
		f.h.Change(nodeChange)
		renderInvite(w, http.StatusInternalServerError, templates.InviteError(templates.InviteFailed))

		return
	}

	routeChange, err := f.h.state.AutoApproveRoutes(node)
	if err != nil {
		log.Error().Err(err).Uint64("node.id", node.ID().Uint64()).Msg("invite: auto approving routes")
	}

	f.h.Change(nodeChange, routeChange)

	log.Info().
		Uint64("node.id", node.ID().Uint64()).
		Uint64("authkey.id", pak.ID).
		Str("node.hostname", node.Hostname()).
		Msg("invite: node registered")

	f.clearCookie(w, req, inviteCookie, "/")
	f.clearCookie(w, req, inviteCSRFCookie, "/join/register/"+authID.String())
	f.done.Add(authID, node.ID())
	http.Redirect(w, req, "/join/status/"+authID.String(), http.StatusSeeOther)
}

// confirmed checks the POST came from the confirmation page this server
// rendered: same origin when the browser says it, and the form token equal
// to its cookie, which is scoped by Path to this auth_id. It returns the
// token, which also names the key the page showed.
func (f *inviteFlow) confirmed(w http.ResponseWriter, req *http.Request) (string, bool) {
	if origin := req.Header.Get("Origin"); origin != "" && !f.sameOrigin(origin) {
		return "", false
	}

	// The form is one hidden field; 4 KiB keeps ParseForm bounded.
	req.Body = http.MaxBytesReader(w, req.Body, 4*1024)
	if err := req.ParseForm(); err != nil { //nolint:noinlineerr,gosec // bounded above
		return "", false
	}

	form := req.PostFormValue(inviteCSRFCookie) //nolint:gosec // bounded above

	cookie, err := req.Cookie(inviteCSRFCookie)
	if err != nil || form == "" || cookie.Value == "" {
		return "", false
	}

	return form, subtle.ConstantTimeCompare([]byte(form), []byte(cookie.Value)) == 1
}

func (f *inviteFlow) sameOrigin(origin string) bool {
	want, err := url.Parse(f.serverURL)
	if err != nil {
		return false
	}

	got, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host)
}

// registerFailed turns a registration error into the page that says what to
// do. The invitation cookie stays unless the key itself is spent.
func (f *inviteFlow) registerFailed(w http.ResponseWriter, req *http.Request, err error) {
	var pakErr types.PAKError

	switch {
	case errors.Is(err, state.ErrInviteNotRegistration):
		renderInvite(w, http.StatusBadRequest, templates.InviteError(templates.InviteFailed))
	case errors.Is(err, db.ErrNodeNotFoundRegistrationCache):
		renderInvite(w, http.StatusGone, templates.InviteError(templates.InviteRequestExpired))
	case errors.As(err, &pakErr), errors.Is(err, gorm.ErrRecordNotFound):
		f.clearCookie(w, req, inviteCookie, "/")

		problem := templates.InviteInvalid
		if strings.Contains(pakErr.Error(), "used") {
			problem = templates.InviteUsed
		} else if strings.Contains(pakErr.Error(), "expired") {
			problem = templates.InviteExpired
		}

		renderInvite(w, http.StatusForbidden, templates.InviteError(problem))
	default:
		log.Error().Err(err).Msg("invite: registering node")
		renderInvite(w, http.StatusInternalServerError, templates.InviteError(templates.InviteFailed))
	}
}

// JoinStatusHandler serves /join/status/{auth_id}: whether the device the
// invitation registered is online yet.
func (f *inviteFlow) JoinStatusHandler(w http.ResponseWriter, req *http.Request) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(w, err)

		return
	}

	nodeID, ok := f.done.Get(authID)
	if !ok {
		renderInvite(w, http.StatusNotFound, templates.InviteError(templates.InviteDeviceUnknown))

		return
	}

	node, ok := f.h.state.GetNodeByID(nodeID)
	if !ok {
		renderInvite(w, http.StatusNotFound, templates.InviteError(templates.InviteDeviceUnknown))

		return
	}

	renderInvite(w, http.StatusOK, templates.InviteStatus(templates.InviteStatusInfo{
		User:       node.Owner().TailscaleUser().DisplayName,
		Hostname:   node.Hostname(),
		Online:     node.Online(),
		RefreshURL: "/join/status/" + authID.String(),
	}))
}

func (f *inviteFlow) cookiesSecure(req *http.Request) bool {
	return strings.HasPrefix(f.serverURL, "https://") || req.TLS != nil
}

func (f *inviteFlow) setCookie(w http.ResponseWriter, req *http.Request, name, path, value string, maxAge time.Duration) {
	//nolint:gosec // G124: Secure from server_url scheme or req.TLS; HttpOnly + SameSite set
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   max(1, int(maxAge.Seconds())),
		Secure:   f.cookiesSecure(req),
		HttpOnly: true,
		// Lax, not Strict: the app opens /register/{auth_id} as a fresh
		// top-level navigation, which must carry the invitation. Lax never
		// rides a cross-site POST, so the confirmation stays protected.
		SameSite: http.SameSiteLaxMode,
	})
}

func (f *inviteFlow) clearCookie(w http.ResponseWriter, req *http.Request, name, path string) {
	//nolint:gosec // G124: clearing only
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		Secure:   f.cookiesSecure(req),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// inviteOwner is who a device registered with pak belongs to, as shown to
// the person.
func inviteOwner(pak *types.PreAuthKey) string {
	if pak.IsTagged() || pak.User == nil {
		return "dispositivo de la organización"
	}

	return pak.User.Display()
}

func renderInvite(w http.ResponseWriter, code int, page interface{ Render() string }) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Invitation pages hold per-person state; no cache may keep them.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)

	if _, err := w.Write([]byte(page.Render())); err != nil { //nolint:noinlineerr
		util.LogErr(err, "invite: writing response")
	}
}
