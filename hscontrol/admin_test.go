package hscontrol

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminLink mints what `kyr admin link` prints: an API key that lives
// life, as a login link.
func (e *inviteEnv) adminLink(life time.Duration) (string, string) {
	e.t.Helper()

	exp := time.Now().Add(life)
	key, _, err := e.app.state.CreateAPIKey(&exp)
	require.NoError(e.t, err)

	return key, types.AdminLinkURL("", key)
}

// adminLogin opens a fresh admin link and returns the session cookie.
func (e *inviteEnv) adminLogin() *http.Cookie {
	e.t.Helper()

	_, link := e.adminLink(types.AdminLinkLife)
	rec := e.adminOpen(link)
	require.Equal(e.t, http.StatusSeeOther, rec.Code, rec.Body.String())
	require.Equal(e.t, adminPath, rec.Header().Get("Location"))

	return cookieNamed(e.t, rec, adminCookie)
}

// adminOpen does what the administrator's browser does with a login link:
// GET it, then press the button, which POSTs the key from the form.
func (e *inviteEnv) adminOpen(link string) *httptest.ResponseRecorder {
	e.t.Helper()

	page := e.get(link)
	if page.Code != http.StatusOK {
		return page
	}

	require.Equal(e.t, "admin-login-confirm", marker(page.Body.String()))

	return e.adminPost(types.AdminLoginPath, url.Values{types.InviteCodeParam: {attrOf(e.t, page.Body.String(), types.InviteCodeParam)}})
}

func (e *inviteEnv) adminPost(path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return e.do(req, cookies...)
}

// adminConsole loads the console and returns its body and form token.
func (e *inviteEnv) adminConsole(session *http.Cookie) (string, string) {
	e.t.Helper()

	rec := e.get(adminPath, session)
	require.Equal(e.t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(e.t, "admin-console", marker(rec.Body.String()))

	return rec.Body.String(), attrOf(e.t, rec.Body.String(), "csrf")
}

// attrOf is the value of the input named name.
func attrOf(t *testing.T, body, name string) string {
	t.Helper()

	m := regexp.MustCompile(`<input[^>]*name="` + name + `"[^>]*value="([^"]+)"`).FindStringSubmatch(body)
	require.NotNil(t, m, "input %s not found", name)

	return html.UnescapeString(m[1])
}

func TestAdminDeniesWithoutSession(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	bogus := &http.Cookie{Name: adminCookie, Value: "not-a-session"}
	for _, rec := range []*httptest.ResponseRecorder{
		e.get(adminPath),
		e.get(adminPath, bogus),
		e.adminPost(adminPath+"/invites", url.Values{"user": {"1"}, "expires": {"24h"}}),
		e.adminPost(adminPath+"/invites/1/revoke", url.Values{}, bogus),
		e.adminPost(adminPath+"/logout", url.Values{}),
	} {
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, templates.AdminNoSession, marker(rec.Body.String()))
	}

	keys, err := e.app.state.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Empty(t, keys, "a denied request must not create anything")
}

func TestAdminLinkOpensOneSessionOnly(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	key, link := e.adminLink(types.AdminLinkLife)

	// A previewer that only GETs the link spends nothing and gets no session.
	for range 3 {
		preview := e.get(link)
		require.Equal(t, http.StatusOK, preview.Code)
		assert.Equal(t, "admin-login-confirm", marker(preview.Body.String()))
		assert.Empty(t, preview.Result().Cookies(), "a GET must not start a session")
	}

	valid, err := e.app.state.ValidateAPIKey(key)
	require.NoError(t, err)
	assert.True(t, valid, "a GET must not spend the key")

	first := e.adminOpen(link)
	require.Equal(t, http.StatusSeeOther, first.Code)
	session := cookieNamed(t, first, adminCookie)
	assert.True(t, session.HttpOnly)
	assert.Equal(t, adminPath, session.Path)

	second := e.adminOpen(link)
	assert.Equal(t, http.StatusForbidden, second.Code)
	assert.Equal(t, templates.AdminLinkInvalid, marker(second.Body.String()))
	assert.Empty(t, second.Result().Cookies(), "a spent link must not start a session")

	valid, err = e.app.state.ValidateAPIKey(key)
	require.NoError(t, err)
	assert.False(t, valid, "the POST spends its API key")

	e.adminConsole(session)
}

func TestAdminLinkRaceGivesOneSession(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	key, _ := e.adminLink(types.AdminLinkLife)
	form := url.Values{types.InviteCodeParam: {key}}.Encode()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)

	for range 8 {
		wg.Go(func() {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, types.AdminLoginPath, strings.NewReader(form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			e.router.ServeHTTP(rec, req)

			if rec.Code == http.StatusSeeOther {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}

	wg.Wait()
	assert.Equal(t, 1, wins)
}

func TestAdminLinkRefusesOtherKeys(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	// A key made for a REST client is not an admin link and is not burned.
	key, link := e.adminLink(90 * 24 * time.Hour)
	rec := e.adminOpen(link)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, templates.AdminLinkInvalid, marker(rec.Body.String()))

	valid, err := e.app.state.ValidateAPIKey(key)
	require.NoError(t, err)
	assert.True(t, valid, "a refused key keeps working for its client")

	for _, code := range []string{"", "hskey-api-short", "hskey-auth-whatever", strings.Repeat("a", 300)} {
		rec := e.get(types.AdminLoginPath + "?code=" + url.QueryEscape(code))
		assert.Equal(t, http.StatusForbidden, rec.Code, code)
	}
}

func TestAdminFormsNeedTheSessionToken(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	session := e.adminLogin()
	_, token := e.adminConsole(session)
	form := url.Values{"user": {strconv.FormatUint(uint64(e.user.ID), 10)}, "expires": {"24h"}}

	rec := e.adminPost(adminPath+"/invites", form, session)
	assert.Equal(t, http.StatusForbidden, rec.Code, "no token")
	assert.Equal(t, templates.AdminBadForm, marker(rec.Body.String()))

	form.Set(adminCSRFField, "wrong")
	rec = e.adminPost(adminPath+"/invites", form, session)
	assert.Equal(t, http.StatusForbidden, rec.Code, "wrong token")

	// Another session's token does not work either.
	_, other := e.adminConsole(e.adminLogin())
	form.Set(adminCSRFField, other)
	rec = e.adminPost(adminPath+"/invites", form, session)
	assert.Equal(t, http.StatusForbidden, rec.Code, "token of another session")

	form.Set(adminCSRFField, token)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, adminPath+"/invites",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	rec = e.do(req, session)
	assert.Equal(t, http.StatusForbidden, rec.Code, "foreign origin")

	keys, err := e.app.state.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAdminCreatesSharesAndRevokes(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	session := e.adminLogin()
	_, token := e.adminConsole(session)

	rec := e.adminPost(adminPath+"/invites", url.Values{
		adminCSRFField: {token},
		"user":         {strconv.FormatUint(uint64(e.user.ID), 10)},
		"expires":      {"24h"},
	}, session)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())

	body, _ := e.adminConsole(session)
	link := attrOf(t, body, "link")
	require.True(t, strings.HasPrefix(link, "http://localhost:8080/join?code=hskey-auth-"), link)

	escaped := strings.ReplaceAll(url.QueryEscape(link), "+", "%20")
	assert.Regexp(t, `<a data-kyrmesh="share-whatsapp" href="https://wa.me/\?text=[^"]+" rel="noreferrer noopener"`, body)
	assert.Regexp(t, `<a data-kyrmesh="share-email" href="mailto:\?subject=[^"]+&body=[^"]+" rel="noreferrer noopener"`, body)
	assert.Equal(t, 2, strings.Count(body, escaped), "both buttons carry the link")
	assert.Contains(t, body, "vence en 24 horas")
	assert.Equal(t, 1, strings.Count(body, `data-kyrmesh="admin-pending"`))

	// The link works as any invitation does.
	code := strings.TrimPrefix(link, "http://localhost:8080/join?code=")
	e.join(code)

	revoke := regexp.MustCompile(`action="(/admin/invites/\d+/revoke)"`).FindStringSubmatch(body)
	require.NotNil(t, revoke)

	rec = e.adminPost(revoke[1], url.Values{adminCSRFField: {token}}, session)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())

	// Revoked from the page is refused exactly like expired from the CLI.
	rec = e.get("/join?code=" + url.QueryEscape(code))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, templates.InviteExpired, marker(rec.Body.String()))

	body, _ = e.adminConsole(session)
	assert.NotContains(t, body, `data-kyrmesh="admin-share"`, "a revoked link is not offered again")
	assert.NotContains(t, body, `data-kyrmesh="admin-pending"`)

	rec = e.adminPost(revoke[1], url.Values{adminCSRFField: {token}}, session)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), templates.AdminNoticeGone)
}

func TestAdminRejectsBadChoices(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	session := e.adminLogin()
	_, token := e.adminConsole(session)

	for _, tc := range []struct {
		user, expires, notice string
	}{
		{"", "24h", templates.AdminNoticeBadUser},
		{"999", "24h", templates.AdminNoticeBadUser},
		{strconv.FormatUint(uint64(e.user.ID), 10), "100y", templates.AdminNoticeBadExpiry},
	} {
		rec := e.adminPost(adminPath+"/invites", url.Values{
			adminCSRFField: {token}, "user": {tc.user}, "expires": {tc.expires},
		}, session)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), `data-kyrmesh="`+tc.notice+`"`)
	}

	keys, err := e.app.state.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestAdminLogoutEndsTheSession(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	session := e.adminLogin()
	_, token := e.adminConsole(session)

	rec := e.adminPost(adminPath+"/logout", url.Values{adminCSRFField: {token}}, session)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, templates.AdminSignedOut, marker(rec.Body.String()))

	rec = e.get(adminPath, session)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestUntilText(t *testing.T) {
	t.Parallel()

	now := time.Now()
	for d, want := range map[time.Duration]string{
		30 * time.Second:           "menos de un minuto",
		45 * time.Minute:           "45 minutos",
		time.Hour:                  "1 hora",
		24 * time.Hour:             "24 horas",
		7 * 24 * time.Hour:         "7 días",
		36*time.Hour + time.Minute: "2 días",
	} {
		assert.Equal(t, want, templates.UntilText(now.Add(d+2*time.Second)), d.String())
	}
}

func TestAdminLoginPostRefusesForeignOrigin(t *testing.T) {
	t.Parallel()
	e := newInviteEnv(t)

	key, _ := e.adminLink(types.AdminLinkLife)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, types.AdminLoginPath,
		strings.NewReader(url.Values{types.InviteCodeParam: {key}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://elsewhere.invalid")

	rec := e.do(req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	valid, err := e.app.state.ValidateAPIKey(key)
	require.NoError(t, err)
	assert.True(t, valid, "a refused POST must not spend the key")
}

func TestAdminPageEscapesHostileNames(t *testing.T) {
	t.Parallel()

	hostile := `<script>alert("x")</script>' & "q"`
	page := templates.AdminPage(templates.AdminPageInfo{
		CSRFField: "csrf",
		CSRFToken: "t",
		Share: &templates.AdminShareInfo{
			Link:    `https://example.invalid/join?code=a<script>"b'`,
			Owner:   hostile,
			Expires: time.Now().Add(time.Hour),
		},
		Pending: []templates.AdminPendingInfo{{Owner: hostile, RevokeAction: "/admin/invites/1/revoke"}},
	}).Render()

	// The name is text: escaped in the success box and in the pending list.
	assert.Contains(t, page, "Invitación lista para &lt;script&gt;")
	assert.NotContains(t, page, "<script>alert")

	// Whatever reaches the share links is percent-encoded, never raw.
	for _, prefix := range []string{"https://wa.me/?text=", "mailto:?subject="} {
		_, rest, ok := strings.Cut(page, `href="`+prefix)
		require.True(t, ok, prefix)

		href, _, _ := strings.Cut(rest, `"`)
		for _, raw := range []string{"<", ">", "'", " ", "\n"} {
			assert.NotContains(t, href, raw, prefix)
		}
	}

	assert.Contains(t, page, "%3Cscript%3E")
}
