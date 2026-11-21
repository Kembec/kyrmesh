package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The default httptest address; another network gets another one.
const otherNetwork = "198.51.100.7:5555"

func pageCode(t *testing.T, body string) string {
	t.Helper()

	m := regexp.MustCompile(`data-kyrmesh-code="(\d{4})"`).FindStringSubmatch(body)
	require.NotNil(t, m, "no pairing code on the page")

	return m[1]
}

func (e *inviteEnv) getFromNetwork(path, addr string) *httptest.ResponseRecorder {
	e.t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	req.RemoteAddr = addr

	return e.do(req)
}

func (e *inviteEnv) pair(path, form string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path,
		strings.NewReader(inviteCSRFCookie+"="+form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return e.do(req, cookies...)
}

// The iPhone case measured on 20/11: the app opens /register without the
// invitation; the person goes back to Safari and connects it there.
func TestPairFromSafariConnectsTheWaitingDevice(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("localhost")

	appPage := e.get("/register/" + authID.String())
	require.Equal(t, "invite-return", marker(appPage.Body.String()))
	code := pageCode(t, appPage.Body.String())

	invite := e.join(e.newKey(false, time.Hour))
	safari := e.get("/join", invite)
	require.Equal(t, http.StatusOK, safari.Code)
	assert.Equal(t, code, pageCode(t, safari.Body.String()), "Safari shows the same code as the app")
	assert.Contains(t, safari.Body.String(), "/join/pair/"+authID.String())
	assert.Contains(t, safari.Body.String(), "iOS", "the device is named by its system, not «localhost»")

	csrf := cookieNamed(t, safari, inviteCSRFCookie)
	assert.Equal(t, pairPath, csrf.Path)

	rec := e.pair("/join/pair/"+authID.String(), csrf.Value, invite, csrf)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, "/join/status/"+authID.String(), rec.Header().Get("Location"))

	nodes := e.app.state.ListNodes()
	require.Equal(t, 1, nodes.Len())
	assert.Equal(t, e.user.ID, nodes.At(0).User().ID())

	assert.Empty(t, e.app.invites.waitingFrom("192.0.2.1"), "a connected device stops waiting")
}

func TestPairIgnoresDevicesFromAnotherNetwork(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("stranger")

	appPage := e.getFromNetwork("/register/"+authID.String(), otherNetwork)
	code := pageCode(t, appPage.Body.String())

	invite := e.join(e.newKey(false, time.Hour))
	safari := e.get("/join", invite)
	// Match the listed code, not bare digits: the page's logo SVG has numbers too.
	assert.NotContains(t, safari.Body.String(), `data-kyrmesh-code="`+code+`"`, "a device on another network is not listed")
	assert.NotContains(t, safari.Body.String(), "/join/pair/")

	// Forging the POST from this network does not reach it either.
	forged := &http.Cookie{Name: inviteCSRFCookie, Value: "x.1"}
	rec := e.pair("/join/pair/"+authID.String(), "x.1", invite, forged)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, 0, e.app.state.ListNodes().Len())
}

func TestPairNeedsTheTokenOfThisInvitation(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("phone")
	e.get("/register/" + authID.String())

	invite := e.join(e.newKey(false, time.Hour))
	safari := e.get("/join", invite)
	csrf := cookieNamed(t, safari, inviteCSRFCookie)

	assert.Equal(t, http.StatusForbidden, e.pair("/join/pair/"+authID.String(), "wrong", invite, csrf).Code)
	assert.Equal(t, http.StatusForbidden, e.pair("/join/pair/"+authID.String(), csrf.Value, invite).Code, "no token cookie")
	assert.Equal(t, 0, e.app.state.ListNodes().Len())

	used := e.newKey(false, time.Hour)
	assert.Equal(t, templates.InviteInvalid, marker(e.pair("/join/pair/"+authID.String(), csrf.Value, &http.Cookie{Name: inviteCookie, Value: used + "x"}, csrf).Body.String()))
}
