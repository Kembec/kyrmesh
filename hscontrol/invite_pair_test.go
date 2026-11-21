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

	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The default httptest address; another network gets another one.
const (
	thisNetwork  = "192.0.2.1"
	otherNetwork = "198.51.100.7:5555"
)

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

// appPage opens /register the way the iOS app's login browser does, without
// the invitation.
func (e *inviteEnv) appPage(authID types.AuthID, userAgent string) string {
	e.t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/register/"+authID.String(), nil)
	req.Header.Set("User-Agent", userAgent)

	page := e.do(req)
	require.Equal(e.t, "invite-return", marker(page.Body.String()))

	return page.Body.String()
}

// appCode is the code the app's page shows.
func (e *inviteEnv) appCode(authID types.AuthID) string {
	e.t.Helper()

	return pageCode(e.t, e.appPage(authID, ""))
}

func (e *inviteEnv) pair(csrf, code string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	form := url.Values{inviteCSRFCookie: {csrf}, pairCodeField: {code}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pairPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return e.do(req, cookies...)
}

// safari opens the invitation page and returns its pairing token cookie.
func (e *inviteEnv) safari(invite *http.Cookie) (*httptest.ResponseRecorder, *http.Cookie) {
	e.t.Helper()

	page := e.get("/join", invite)
	require.Equal(e.t, http.StatusOK, page.Code)

	return page, cookieNamed(e.t, page, inviteCSRFCookie)
}

// The iPhone case measured on 20/11: the app opens /register without the
// invitation; the person goes back to Safari and types the code there.
func TestPairFromSafariConnectsTheWaitingDevice(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("localhost")
	code := e.appCode(authID)

	invite := e.join(e.newKey(false, time.Hour))
	safari, csrf := e.safari(invite)
	body := safari.Body.String()
	assert.Contains(t, body, `data-kyrmesh-pair`, "Safari asks for the code")
	assert.Contains(t, body, `action="`+pairPath+`"`)
	assert.NotContains(t, body, `data-kyrmesh-code="`, "Safari never shows the codes")
	assert.NotContains(t, body, authID.String(), "nor which devices wait")
	assert.Equal(t, pairPath, csrf.Path)

	rec := e.pair(csrf.Value, code, invite, csrf)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, "/join/status/"+authID.String(), rec.Header().Get("Location"))

	nodes := e.app.state.ListNodes()
	require.Equal(t, 1, nodes.Len())
	assert.Equal(t, e.user.ID, nodes.At(0).User().ID())

	assert.Empty(t, e.app.invites.waitingFrom(thisNetwork), "a connected device stops waiting")
}

// The iPad case measured on 21/11: an iPhone and an iPad of one home wait
// from the same address, both «iOS»; the iPad connected the iPhone. Only the
// device whose code is typed connects.
func TestPairConnectsOnlyTheDeviceWhoseCodeMatches(t *testing.T) {
	e := newInviteEnv(t)
	iphone := e.pendingDevice("localhost")
	ipad := e.pendingDevice("localhost")
	iphonePage := e.appPage(iphone, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)")
	ipadPage := e.appPage(ipad, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	assert.Contains(t, iphonePage, "iPhone · iOS", "each page names its model, not «localhost»")
	assert.Contains(t, ipadPage, "iPad · iOS")

	iphoneCode, ipadCode := pageCode(t, iphonePage), pageCode(t, ipadPage)
	require.NotEqual(t, iphoneCode, ipadCode, "two waits of one network never share a code")

	invite := e.join(e.newKey(false, time.Hour))
	_, csrf := e.safari(invite)

	wrong := e.pair(csrf.Value, "0000", invite, csrf)
	assert.Equal(t, http.StatusUnprocessableEntity, wrong.Code)
	assert.Contains(t, wrong.Body.String(), "data-kyrmesh-wrong-code", "a code that is no one's says so")
	assert.Equal(t, 0, e.app.state.ListNodes().Len())

	csrf = cookieNamed(t, wrong, inviteCSRFCookie)
	rec := e.pair(csrf.Value, ipadCode, invite, csrf)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, "/join/status/"+ipad.String(), rec.Header().Get("Location"), "the iPad, not the iPhone")
	assert.Equal(t, 1, e.app.state.ListNodes().Len())

	left := e.app.invites.waitingFrom(thisNetwork)
	require.Len(t, left, 1)
	assert.Equal(t, iphone, left[0].authID, "the iPhone still waits for its own code")
}

func TestPairIgnoresDevicesFromAnotherNetwork(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("stranger")

	appPage := e.getFromNetwork("/register/"+authID.String(), otherNetwork)
	code := pageCode(t, appPage.Body.String())

	invite := e.join(e.newKey(false, time.Hour))
	safari := e.get("/join", invite)
	assert.NotContains(t, safari.Body.String(), "data-kyrmesh-pair", "nothing waits from this network")

	// Its code, typed from this network with a forged token, does not reach it.
	forged := &http.Cookie{Name: inviteCSRFCookie, Value: "x.1"}
	rec := e.pair("x.1", code, invite, forged)
	assert.NotEqual(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, 0, e.app.state.ListNodes().Len())
}

func TestPairNeedsTheTokenOfThisInvitation(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("phone")
	code := e.appCode(authID)

	invite := e.join(e.newKey(false, time.Hour))
	_, csrf := e.safari(invite)

	assert.Equal(t, http.StatusForbidden, e.pair("wrong", code, invite, csrf).Code)
	assert.Equal(t, http.StatusForbidden, e.pair(csrf.Value, code, invite).Code, "no token cookie")
	assert.Equal(t, 0, e.app.state.ListNodes().Len())

	used := e.newKey(false, time.Hour)
	assert.Equal(t, templates.InviteInvalid, marker(e.pair(csrf.Value, code, &http.Cookie{Name: inviteCookie, Value: used + "x"}, csrf).Body.String()))
}

// Guessing a neighbour's code on a shared network stops after a few tries,
// even if the next one is right.
func TestPairStopsAfterTooManyWrongCodes(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("localhost")
	code := e.appCode(authID)

	invite := e.join(e.newKey(false, time.Hour))
	_, csrf := e.safari(invite)

	for range pairMaxWrong {
		require.Equal(t, http.StatusUnprocessableEntity, e.pair(csrf.Value, "0000", invite, csrf).Code)
	}

	rec := e.pair(csrf.Value, code, invite, csrf)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, templates.InvitePairLocked, marker(rec.Body.String()))
	assert.Equal(t, 0, e.app.state.ListNodes().Len())
}

// Safari sends Origin: null on these POSTs (Referrer-Policy: no-referrer);
// the iPad pairing failed on it (21/11). A foreign origin is still refused.
func TestPairAcceptsTheNullOriginSafariSends(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("ipad")
	code := e.appCode(authID)

	invite := e.join(e.newKey(false, time.Hour))
	_, csrf := e.safari(invite)

	post := func(origin string) *httptest.ResponseRecorder {
		form := url.Values{inviteCSRFCookie: {csrf.Value}, pairCodeField: {code}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pairPath,
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)

		return e.do(req, invite, csrf)
	}

	assert.Equal(t, http.StatusForbidden, post("https://evil.example").Code, "foreign origin")
	rec := post("null")
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, 1, e.app.state.ListNodes().Len())
}

func TestDeviceModelNamesTheModelForAPerson(t *testing.T) {
	for _, tc := range []struct{ os, model, ua, want string }{
		{"iOS", "iPhone15,4", "", "iPhone"},
		{"iOS", "iPad13,4", "", "iPad"},
		{"macOS", "Mac15,6", "", "Mac"},
		{"linux", "NVIDIA Jetson Orin Nano", "", "NVIDIA Jetson Orin Nano"},
		{"iOS", "", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", "iPhone"},
		{"iOS", "", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "iPad"},
		{"macOS", "", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", ""},
		{"iOS", "", "", ""},
	} {
		assert.Equal(t, tc.want, deviceModel(tc.os, tc.model, tc.ua), "%+v", tc)
	}
}
