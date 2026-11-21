package hscontrol

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
)

// The admin console is the browser page where an administrator creates,
// shares and revokes invitations without a terminal (KEM-464).
//
// Access opens no new door: there is no password and no new kind of
// credential. Whoever can already run the CLI on the server gets, with
// `kyr admin link`, a link that carries an API key ten minutes long.
// Opening it (GET) only shows a one-button form, so a link previewer spends
// nothing; pressing the button (POST) expires that key and starts a browser
// session, so the same link never opens a second one. Every /admin route
// answers 403 to anyone else. An API key already grants full control
// through /api/v1, so the console grants nothing an API key does not.
//
// Sessions live in memory: a restart signs the administrator out.
const (
	adminCookie    = "kyrmesh_admin"
	adminPath      = "/admin"
	adminCSRFField = "csrf"
	adminKeyPrefix = "hskey-api-"

	// An API key is ~86 characters; anything far longer never reaches the
	// database.
	adminCodeMaxLen = 256
	// The CLI makes a key exactly [types.AdminLinkLife] long; the margin
	// covers a slow clock, not a key made for anything else.
	adminLinkMaxLife = types.AdminLinkLife + 5*time.Minute
	// A working day; the administrator asks for a new link after that.
	adminSessionTTL = 12 * time.Hour
	// Beyond this, opening a new link drops the oldest session.
	adminSessionMax = 32
	// The forms are a few short fields; 4 KiB keeps ParseForm bounded.
	adminFormMaxBytes = 4 * 1024
)

type adminSession struct {
	expires time.Time
	csrf    string
	// last is the invitation this session created most recently. The
	// database keeps only its hash, so this is the one place the link can
	// still be shared from.
	last *templates.AdminShareInfo
	// lastID is the pre-auth key behind last.
	lastID uint64
}

type adminConsole struct {
	h         *Headscale
	serverURL string

	// burnMu makes checking and expiring a login key one step, so two
	// requests racing with the same link cannot both get a session.
	burnMu sync.Mutex

	mu       sync.Mutex
	sessions map[string]*adminSession
}

func newAdminConsole(h *Headscale, serverURL string) *adminConsole {
	return &adminConsole{
		h:         h,
		serverURL: strings.TrimSuffix(serverURL, "/"),
		sessions:  make(map[string]*adminSession),
	}
}

// routes mounts the console. Only the login link is reachable without a
// session, and it needs a live admin link.
func (a *adminConsole) routes(r chi.Router) {
	r.Get(types.AdminLoginPath, a.LoginConfirmHandler)
	r.Post(types.AdminLoginPath, a.LoginHandler)
	r.Get(adminPath, a.authed(a.page))
	r.Post(adminPath+"/invites", a.posted(a.create))
	r.Post(adminPath+"/invites/{id}/revoke", a.posted(a.revoke))
	r.Post(adminPath+"/logout", a.posted(a.logout))
}

// LoginConfirmHandler serves GET /admin/login?code=<api key>. It only shows
// a one-button form and spends nothing: link previewers (chat apps, mail
// scanners) fetch links before the administrator does, and must not burn the
// key or receive a session. Like /join, the key is spent by a POST.
func (a *adminConsole) LoginConfirmHandler(w http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get(types.InviteCodeParam)
	if !wellFormedAdminCode(code) || a.liveKey(code) == nil {
		renderAdmin(w, http.StatusForbidden, templates.AdminDenied(templates.AdminLinkInvalid))

		return
	}

	renderAdmin(w, http.StatusOK, templates.AdminLoginConfirm(types.AdminLoginPath, types.InviteCodeParam, code))
}

// wellFormedAdminCode filters what is echoed into the confirmation form:
// the key prefix, a bounded length and only the characters an API key has.
func wellFormedAdminCode(code string) bool {
	if len(code) > adminCodeMaxLen || !strings.HasPrefix(code, adminKeyPrefix) {
		return false
	}

	for _, r := range code {
		isKeyChar := r == '-' || r == '_' || r == '.' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !isKeyChar {
			return false
		}
	}

	return true
}

// LoginHandler serves POST /admin/login: it spends the key and starts a
// session, then redirects to the bare console so the key does not stay in
// the address bar or the browser history.
func (a *adminConsole) LoginHandler(w http.ResponseWriter, req *http.Request) {
	if origin := req.Header.Get("Origin"); origin != "" && origin != "null" && !sameOriginAs(a.serverURL, origin) {
		renderAdmin(w, http.StatusForbidden, templates.AdminDenied(templates.AdminBadForm))

		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, adminFormMaxBytes)
	if err := req.ParseForm(); err != nil { //nolint:noinlineerr,gosec // bounded above
		renderAdmin(w, http.StatusBadRequest, templates.AdminDenied(templates.AdminBadForm))

		return
	}

	if !a.burn(req.PostFormValue(types.InviteCodeParam)) {
		renderAdmin(w, http.StatusForbidden, templates.AdminDenied(templates.AdminLinkInvalid))

		return
	}

	id, err := a.newSession()
	if err != nil {
		log.Error().Err(err).Msg("admin: starting session")
		renderAdmin(w, http.StatusInternalServerError, templates.AdminDenied(templates.AdminFailed))

		return
	}

	a.setCookie(w, req, id, adminSessionTTL)
	http.Redirect(w, req, adminPath, http.StatusSeeOther)
}

// liveKey returns the key when code would be accepted as an admin link
// (prefix, still valid, bounded life), and spends nothing. It is the single
// set of conditions shared by the GET check and the POST that burns.
func (a *adminConsole) liveKey(code string) *types.APIKey {
	if len(code) > adminCodeMaxLen || !strings.HasPrefix(code, adminKeyPrefix) {
		return nil
	}

	ok, err := a.h.state.ValidateAPIKey(code)
	if err != nil || !ok {
		return nil
	}

	key, err := a.h.state.GetAPIKey(code)
	if err != nil || key.CreatedAt == nil || key.Expiration == nil {
		return nil
	}

	// Expiring sets Expiration to now, so a second request with the same
	// link fails here even within the same clock tick.
	if !key.Expiration.After(time.Now()) || key.Expiration.Sub(*key.CreatedAt) > adminLinkMaxLife {
		return nil
	}

	return key
}

// burn reports whether code is a live admin link, and expires it.
func (a *adminConsole) burn(code string) bool {
	a.burnMu.Lock()
	defer a.burnMu.Unlock()

	key := a.liveKey(code)
	if key == nil {
		return false
	}

	if err := a.h.state.ExpireAPIKey(key); err != nil { //nolint:noinlineerr
		log.Error().Err(err).Msg("admin: expiring login key")

		return false
	}

	return true
}

func (a *adminConsole) newSession() (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}

	csrf, err := randomToken()
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for sid, s := range a.sessions {
		if !s.expires.After(now) {
			delete(a.sessions, sid)
		}
	}

	if len(a.sessions) >= adminSessionMax {
		a.dropOldestLocked()
	}

	a.sessions[id] = &adminSession{expires: now.Add(adminSessionTTL), csrf: csrf}

	return id, nil
}

func (a *adminConsole) dropOldestLocked() {
	var (
		oldest  string
		soonest time.Time
	)

	for sid, s := range a.sessions {
		if oldest == "" || s.expires.Before(soonest) {
			oldest, soonest = sid, s.expires
		}
	}

	delete(a.sessions, oldest)
}

// session returns the live session the request's cookie names, a copy the
// handler may read without holding the lock.
func (a *adminConsole) session(req *http.Request) (string, adminSession, bool) {
	cookie, err := req.Cookie(adminCookie)
	if err != nil || cookie.Value == "" {
		return "", adminSession{}, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	s, ok := a.sessions[cookie.Value]
	if !ok {
		return "", adminSession{}, false
	}

	if !s.expires.After(time.Now()) {
		delete(a.sessions, cookie.Value)

		return "", adminSession{}, false
	}

	return cookie.Value, *s, true
}

// update changes a live session under the lock.
func (a *adminConsole) update(id string, change func(*adminSession)) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if s, ok := a.sessions[id]; ok {
		change(s)
	}
}

// authed wraps a handler that needs an administrator; everyone else gets
// 403 and the page that says how to get a link.
func (a *adminConsole) authed(next func(http.ResponseWriter, *http.Request, string, adminSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		id, s, ok := a.session(req)
		if !ok {
			renderAdmin(w, http.StatusForbidden, templates.AdminDenied(templates.AdminNoSession))

			return
		}

		next(w, req, id, s)
	}
}

// posted wraps a form handler: it needs an administrator, and the form must
// carry that session's token. Origin is checked when the browser sends a
// real one; with the server's no-referrer policy browsers send "null" on a
// POST, so the token is what protects the form.
func (a *adminConsole) posted(next func(http.ResponseWriter, *http.Request, string, adminSession)) http.HandlerFunc {
	return a.authed(func(w http.ResponseWriter, req *http.Request, id string, s adminSession) {
		if origin := req.Header.Get("Origin"); origin != "" && origin != "null" && !sameOriginAs(a.serverURL, origin) {
			renderAdmin(w, http.StatusForbidden, templates.AdminDenied(templates.AdminBadForm))

			return
		}

		req.Body = http.MaxBytesReader(w, req.Body, adminFormMaxBytes)
		if err := req.ParseForm(); err != nil { //nolint:noinlineerr,gosec // bounded above
			renderAdmin(w, http.StatusBadRequest, templates.AdminDenied(templates.AdminBadForm))

			return
		}

		token := req.PostFormValue(adminCSRFField) //nolint:gosec // bounded above
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.csrf)) != 1 {
			renderAdmin(w, http.StatusForbidden, templates.AdminDenied(templates.AdminBadForm))

			return
		}

		next(w, req, id, s)
	})
}

// logout serves POST /admin/logout: it ends the session at once.
func (a *adminConsole) logout(w http.ResponseWriter, req *http.Request, id string, _ adminSession) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()

	a.setCookie(w, req, "", -1)
	renderAdmin(w, http.StatusOK, templates.AdminDenied(templates.AdminSignedOut))
}

func (a *adminConsole) setCookie(w http.ResponseWriter, req *http.Request, value string, maxAge time.Duration) {
	seconds := -1
	if maxAge > 0 {
		seconds = int(maxAge.Seconds())
	}

	//nolint:gosec // G124: Secure from server_url scheme or req.TLS; HttpOnly + SameSite set
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookie,
		Value:    value,
		Path:     adminPath,
		MaxAge:   seconds,
		Secure:   strings.HasPrefix(a.serverURL, "https://") || req.TLS != nil,
		HttpOnly: true,
		// Lax keeps the session on a top-level navigation from a chat or the
		// terminal; it never rides a cross-site POST, and every form also
		// carries the session's token.
		SameSite: http.SameSiteLaxMode,
	})
}

func sameOriginAs(serverURL, origin string) bool {
	want, err := url.Parse(serverURL)
	if err != nil {
		return false
	}

	got, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return strings.EqualFold(got.Scheme, want.Scheme) && strings.EqualFold(got.Host, want.Host)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil { //nolint:noinlineerr
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func renderAdmin(w http.ResponseWriter, code int, page interface{ Render() string }) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The console shows live invitation links; no cache may keep it.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)

	if _, err := w.Write([]byte(page.Render())); err != nil { //nolint:noinlineerr
		util.LogErr(err, "admin: writing response")
	}
}
