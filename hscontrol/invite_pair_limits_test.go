package hscontrol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (e *inviteEnv) pairWithOrigin(origin, csrfForm, code string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()

	form := url.Values{inviteCSRFCookie: {csrfForm}, pairCodeField: {code}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pairPath,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)

	return e.do(req, cookies...)
}

// The token serves many attempts, so parallel POSTs must not read the same
// wrong count: past the limit nothing connects, not even the right code.
func TestPairLimitHoldsUnderParallelAttempts(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("localhost")
	code := e.appCode(authID)

	invite := e.join(e.newKey(false, time.Hour))
	_, csrf := e.safari(invite)

	const attempts = 40

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		wrongs  int
		lockeds int
	)

	for range attempts {
		wg.Add(1)

		go func() {
			defer wg.Done()

			rec := e.pair(csrf.Value, "0000", invite, csrf)

			mu.Lock()
			defer mu.Unlock()

			switch rec.Code {
			case http.StatusUnprocessableEntity:
				wrongs++
			case http.StatusTooManyRequests:
				lockeds++
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, pairMaxWrong, wrongs, "only pairMaxWrong attempts are answered as wrong")
	assert.Equal(t, attempts-pairMaxWrong, lockeds)
	assert.Equal(t, http.StatusTooManyRequests, e.pair(csrf.Value, code, invite, csrf).Code)
	assert.Equal(t, 0, e.app.state.ListNodes().Len())
}

// Origin: null says nothing, so only a valid token lets it through.
func TestPairNullOriginNeedsAValidToken(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("ipad")
	code := e.appCode(authID)

	invite := e.join(e.newKey(false, time.Hour))
	_, csrf := e.safari(invite)

	assert.Equal(t, http.StatusForbidden, e.pairWithOrigin("null", "", code, invite).Code, "no token")
	assert.Equal(t, http.StatusForbidden, e.pairWithOrigin("null", "", code, invite, csrf).Code, "empty form token")
	assert.Equal(t, http.StatusForbidden, e.pairWithOrigin("null", "wrong", code, invite, csrf).Code, "invalid token")
	assert.Equal(t, 0, e.app.state.ListNodes().Len())
}

// The invitation pages keep the Origin real; elsewhere no Referer leaves.
func TestInvitePagesSendSameOriginReferrerPolicy(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("phone")

	invite := e.join(e.newKey(false, time.Hour))
	assert.Equal(t, "same-origin", e.get("/join", invite).Header().Get("Referrer-Policy"))
	assert.Equal(t, "same-origin", e.get("/register/"+authID.String(), invite).Header().Get("Referrer-Policy"))
	assert.Equal(t, "no-referrer", referrerPolicy("/register/confirm/"+authID.String()))
	assert.Equal(t, "no-referrer", referrerPolicy("/health"))
}

// Filling the per-address LRU with other addresses must not reset the count
// of an invitation: its own cap stays, and the right code is still locked.
func TestPairInviteCapSurvivesManyAddresses(t *testing.T) {
	e := newInviteEnv(t)
	authID := e.pendingDevice("localhost")
	code := e.appCode(authID)

	exp := time.Now().Add(time.Hour)
	pak, err := e.app.state.CreatePreAuthKey(e.user.TypedID(), false, false, &exp, nil)
	require.NoError(t, err)

	invite := e.join(pak.Key)
	_, csrf := e.safari(invite)

	for i := range 2*waitingSize + 1 {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
		_, res := e.app.invites.tryCode(ip, pak.ID, "0000")
		require.NotEqual(t, pairMatched, res)
	}

	rec := e.pair(csrf.Value, code, invite, csrf)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, 0, e.app.state.ListNodes().Len())
}
