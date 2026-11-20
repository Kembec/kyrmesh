package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	grpcRuntime "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// inviteEnv is a real Headscale with its router, a user and a pending web
// registration: what a phone that tapped "Log in" leaves on the server.
type inviteEnv struct {
	t      *testing.T
	app    *Headscale
	router http.Handler
	user   *types.User
}

func newInviteEnv(t *testing.T) *inviteEnv {
	t.Helper()

	app := createTestApp(t)
	t.Cleanup(func() { _ = app.state.Close() })

	return &inviteEnv{
		t:      t,
		app:    app,
		router: app.createRouter(grpcRuntime.NewServeMux()),
		user:   app.state.CreateUserForTest("bob"),
	}
}

func (e *inviteEnv) newKey(reusable bool, expiry time.Duration) string {
	e.t.Helper()

	exp := time.Now().Add(expiry)
	pak, err := e.app.state.CreatePreAuthKey(e.user.TypedID(), reusable, false, &exp, nil)
	require.NoError(e.t, err)

	return pak.Key
}

func (e *inviteEnv) pendingDevice(hostname string) types.AuthID {
	e.t.Helper()

	resp, err := e.app.handleRegisterInteractive(tailcfg.RegisterRequest{
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname, OS: "iOS"},
	}, key.NewMachine().Public())
	require.NoError(e.t, err)

	u, err := url.Parse(resp.AuthURL)
	require.NoError(e.t, err)

	authID, err := types.AuthIDFromString(strings.TrimPrefix(u.Path, "/register/"))
	require.NoError(e.t, err)

	return authID
}

func (e *inviteEnv) do(req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)

	return rec
}

func (e *inviteEnv) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	return e.do(httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil), cookies...)
}

func (e *inviteEnv) confirm(authID types.AuthID, form string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/join/register/"+authID.String(), strings.NewReader(inviteCSRFCookie+"="+form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return e.do(req, cookies...)
}

// join opens the invitation link and returns the cookie the browser keeps.
func (e *inviteEnv) join(code string) *http.Cookie {
	e.t.Helper()

	rec := e.get("/join?code=" + url.QueryEscape(code))
	require.Equal(e.t, http.StatusSeeOther, rec.Code, rec.Body.String())
	require.Equal(e.t, "/join", rec.Header().Get("Location"))

	return cookieNamed(e.t, rec, inviteCookie)
}

// openConfirm loads the confirmation page and returns its CSRF cookie.
func (e *inviteEnv) openConfirm(authID types.AuthID, invite *http.Cookie) *http.Cookie {
	e.t.Helper()

	rec := e.get("/register/"+authID.String(), invite)
	require.Equal(e.t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(e.t, rec.Body.String(), `data-kyrmesh="invite-confirm"`)

	return cookieNamed(e.t, rec, inviteCSRFCookie)
}

func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()

	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}

	require.FailNow(t, "cookie not set", name)

	return nil
}

func marker(body string) string {
	m := regexp.MustCompile(`data-kyrmesh="([a-z-]+)"`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}

	return m[1]
}

func TestInviteJoinStoresTheInvitationOutOfTheAddressBar(t *testing.T) {
	e := newInviteEnv(t)

	invite := e.join(e.newKey(false, time.Hour))

	assert.True(t, invite.HttpOnly, "page scripts must not read the key")
	assert.Equal(t, http.SameSiteLaxMode, invite.SameSite)
	assert.Equal(t, "/", invite.Path)
	assert.LessOrEqual(t, invite.MaxAge, int(time.Hour.Seconds()), "the cookie dies with the key")

	rec := e.get("/join", invite)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "invite-steps", marker(rec.Body.String()))
	assert.Contains(t, rec.Body.String(), "bob")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

func TestInviteJoinRejectsUnusableInvitations(t *testing.T) {
	e := newInviteEnv(t)

	revoked := e.newKey(false, time.Hour)
	pak, err := e.app.state.GetPreAuthKey(revoked)
	require.NoError(t, err)
	require.NoError(t, e.app.state.ExpirePreAuthKey(pak.ID))

	valid := e.newKey(false, time.Hour)

	cases := map[string]struct {
		code string
		want string
	}{
		"revoked":   {revoked, templates.InviteExpired},
		"reusable":  {e.newKey(true, time.Hour), templates.InviteInvalid},
		"forged":    {valid[:len(valid)-6] + "aaaaaa", templates.InviteInvalid},
		"not a key": {"hello", templates.InviteInvalid},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.get("/join?code=" + url.QueryEscape(tc.code))
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, tc.want, marker(rec.Body.String()))
			assert.Empty(t, rec.Header().Get("Location"))
		})
	}

	rec := e.get("/join")
	assert.Equal(t, templates.InviteMissing, marker(rec.Body.String()), "no invitation stored")
}

func TestInviteRegisterWithoutInvitationKeepsTheProviderPage(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("laptop")

	rec := e.get("/register/" + authID.String())

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "headscale auth register")
	assert.Empty(t, marker(rec.Body.String()))
}

func TestInviteConfirmRegistersTheDeviceAsTheKeySays(t *testing.T) {
	e := newInviteEnv(t)
	code := e.newKey(false, time.Hour)
	authID := e.pendingDevice("bobs-iphone")

	invite := e.join(code)

	// Opening the confirmation registers nothing by itself.
	csrf := e.openConfirm(authID, invite)
	_, pending := e.app.state.GetAuthCacheEntry(authID)
	require.True(t, pending)

	rec := e.confirm(authID, csrf.Value, invite, csrf)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, "/join/status/"+authID.String(), rec.Header().Get("Location"))
	assert.Equal(t, -1, cookieNamed(t, rec, inviteCookie).MaxAge, "a spent invitation leaves the browser")

	_, pending = e.app.state.GetAuthCacheEntry(authID)
	assert.False(t, pending, "the waiting device got its verdict")

	pak, err := e.app.state.GetPreAuthKey(code)
	require.NoError(t, err)
	assert.True(t, pak.Used, "the invitation is single use")

	nodes := e.app.state.ListNodes()
	require.Equal(t, 1, nodes.Len())
	node := nodes.At(0)
	assert.Equal(t, "bobs-iphone", node.Hostname())
	assert.Equal(t, e.user.ID, node.User().ID(), "owned by the key's user, nobody else")
	assert.True(t, node.AuthKeyID().Valid())
	assert.Equal(t, pak.ID, node.AuthKeyID().Get())

	status := e.get("/join/status/" + authID.String())
	require.Equal(t, http.StatusOK, status.Code)
	assert.Equal(t, "waiting", marker(status.Body.String()), "registered but not yet online")
	assert.Contains(t, status.Body.String(), `http-equiv="refresh"`)
}

func TestInviteCannotBeReusedForASecondDevice(t *testing.T) {
	e := newInviteEnv(t)
	code := e.newKey(false, time.Hour)

	first := e.pendingDevice("first")
	invite := e.join(code)
	csrf := e.openConfirm(first, invite)
	require.Equal(t, http.StatusSeeOther, e.confirm(first, csrf.Value, invite, csrf).Code)

	// Someone forwarded the same link: it no longer opens.
	rec := e.get("/join?code=" + url.QueryEscape(code))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, templates.InviteUsed, marker(rec.Body.String()))

	// And a browser that kept the old cookie cannot confirm a new device.
	second := e.pendingDevice("second")
	rec = e.get("/register/"+second.String(), invite)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, templates.InviteUsed, marker(rec.Body.String()))

	rec = e.confirm(second, "x", invite, &http.Cookie{Name: inviteCSRFCookie, Value: "x"})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 1, e.app.state.ListNodes().Len(), "no second node")
}

func TestInviteRevokedAfterOpeningIsRefusedAndTheDeviceKeepsWaiting(t *testing.T) {
	e := newInviteEnv(t)
	code := e.newKey(false, time.Hour)
	authID := e.pendingDevice("late")

	invite := e.join(code)
	csrf := e.openConfirm(authID, invite)

	pak, err := e.app.state.GetPreAuthKey(code)
	require.NoError(t, err)
	require.NoError(t, e.app.state.ExpirePreAuthKey(pak.ID))

	rec := e.confirm(authID, csrf.Value, invite, csrf)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, templates.InviteExpired, marker(rec.Body.String()))
	assert.Equal(t, 0, e.app.state.ListNodes().Len())

	_, pending := e.app.state.GetAuthCacheEntry(authID)
	assert.True(t, pending, "a new invitation can still finish this login")
}

func TestInviteConfirmNeedsTheFormTokenAndTheSameOrigin(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("target")
	invite := e.join(e.newKey(false, time.Hour))
	csrf := e.openConfirm(authID, invite)

	assert.Equal(t, http.StatusForbidden, e.confirm(authID, "wrong", invite, csrf).Code, "token mismatch")
	assert.Equal(t, http.StatusForbidden, e.confirm(authID, csrf.Value, invite).Code, "no token cookie")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/join/register/"+authID.String(), strings.NewReader(inviteCSRFCookie+"="+csrf.Value))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	assert.Equal(t, http.StatusForbidden, e.do(req, invite, csrf).Code, "cross-origin POST")

	assert.Equal(t, 0, e.app.state.ListNodes().Len())

	_, pending := e.app.state.GetAuthCacheEntry(authID)
	assert.True(t, pending)
}

func TestInviteForAnExpiredLoginSaysToTapLogInAgain(t *testing.T) {
	e := newInviteEnv(t)
	invite := e.join(e.newKey(false, time.Hour))

	rec := e.get("/register/"+types.MustAuthID().String(), invite)

	assert.Equal(t, http.StatusGone, rec.Code)
	assert.Equal(t, templates.InviteRequestExpired, marker(rec.Body.String()))
}

func TestInviteStatusOfAnUnknownDevice(t *testing.T) {
	e := newInviteEnv(t)

	rec := e.get("/join/status/" + types.MustAuthID().String())

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, templates.InviteDeviceUnknown, marker(rec.Body.String()))
}

func TestInviteSwappedBeforeTheClickIsRefused(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("target")

	shown := e.join(e.newKey(false, time.Hour))
	csrf := e.openConfirm(authID, shown)

	// Another site opens a second invitation in this browser before the click.
	other := e.app.state.CreateUserForTest("mallory")
	exp := time.Now().Add(time.Hour)
	pak, err := e.app.state.CreatePreAuthKey(other.TypedID(), false, false, &exp, nil)
	require.NoError(t, err)

	swapped := e.join(pak.Key)

	rec := e.confirm(authID, csrf.Value, swapped, csrf)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, templates.InviteNotConfirmed, marker(rec.Body.String()))
	assert.Equal(t, 0, e.app.state.ListNodes().Len(), "the device was confirmed for bob, not for mallory")
}

func TestInviteForgetGoesBackToTheProviderPage(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("shared-laptop")
	invite := e.join(e.newKey(false, time.Hour))

	rec := e.get("/join/forget/"+authID.String(), invite)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/register/"+authID.String(), rec.Header().Get("Location"))
	assert.Equal(t, -1, cookieNamed(t, rec, inviteCookie).MaxAge)
}
