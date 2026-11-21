package dnscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	testWildcard = "*.z.example.com"
	testServer   = "h4.z.example.com"
)

// selfSigned writes a certificate for names, valid until notAfter, into dir.
func selfSigned(t *testing.T, dir string, notAfter time.Time, names ...string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := storeCert(dir, [][]byte{der}, key); err != nil {
		t.Fatal(err)
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()

	m, err := New(Config{Wildcard: testWildcard, ServerName: testServer, CacheDir: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}

	return m
}

func TestCoversExactlyOneLabel(t *testing.T) {
	cases := map[string]bool{
		"h4.z.example.com":    true,
		"H4.Z.EXAMPLE.COM":    true,
		"a.b.z.example.com":   false,
		"z.example.com":       false,
		"h4.z.example.com.io": false,
		"h4.example.com":      false,
	}
	for name, want := range cases {
		if got := Covers(testWildcard, name); got != want {
			t.Errorf("Covers(%q, %q) = %v, want %v", testWildcard, name, got, want)
		}
	}

	if Covers("z.example.com", testServer) {
		t.Error("a name without *. is not a wildcard")
	}
}

func TestNewRefusesANameTheWildcardDoesNotCover(t *testing.T) {
	if _, err := New(Config{Wildcard: testWildcard, ServerName: "other.example.com"}, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTLSAnswersOnlyTheExactServerName(t *testing.T) {
	m := newTestManager(t)
	selfSigned(t, m.cfg.CacheDir, time.Now().Add(80*24*time.Hour), testWildcard)

	m.Start(t.Context())

	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: testServer}); err != nil {
		t.Fatalf("server name refused: %v", err)
	}

	for _, sni := range []string{"", "other.z.example.com", "203.0.113.7", "z.example.com"} {
		if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: sni}); err == nil {
			t.Errorf("SNI %q got a certificate; a scanner must get none", sni)
		}
	}
}

func TestNoCertificateMeansNoTLSYet(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: testServer}); err == nil {
		t.Fatal("expected no certificate before issuance")
	}
}

func TestRenewsThirtyDaysBeforeExpiry(t *testing.T) {
	for _, tc := range []struct {
		left time.Duration
		want bool
	}{{10 * 24 * time.Hour, true}, {29 * 24 * time.Hour, true}, {60 * 24 * time.Hour, false}} {
		m := newTestManager(t)
		selfSigned(t, m.cfg.CacheDir, time.Now().Add(tc.left), testWildcard)

		cert, err := loadCached(m.cfg.CacheDir, testWildcard)
		if err != nil {
			t.Fatal(err)
		}

		m.set(cert)

		if got := m.needsRenewal(); got != tc.want {
			t.Errorf("%s left: needsRenewal = %v, want %v", tc.left, got, tc.want)
		}
	}

	if !newTestManager(t).needsRenewal() {
		t.Error("no certificate must need one")
	}
}

func TestCachedCertificateForAnotherNameIsIgnored(t *testing.T) {
	dir := t.TempDir()
	selfSigned(t, dir, time.Now().Add(80*24*time.Hour), "*.other.example.com")

	if _, err := loadCached(dir, testWildcard); err == nil {
		t.Fatal("a certificate for another wildcard must not be served")
	}

	for _, f := range []string{pairFile} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}

		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v, want 0600", f, info.Mode().Perm())
		}
	}
}

// fakeCloudflare records what the client sends.
type fakeCloudflare struct {
	auth     []string
	created  map[string]any
	deleted  []string
	failNext bool
}

func (f *fakeCloudflare) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.auth = append(f.auth, r.Header.Get("Authorization"))

		if f.failNext {
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)

			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone123","name":"`+r.URL.Query().Get("name")+`"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone123/dns_records":
			_ = json.NewDecoder(r.Body).Decode(&f.created)
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"rec456"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone123/dns_records":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"old1","comment":"`+challengeComment+`"},{"id":"human","comment":"site verification"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone123/dns_records/"):
			f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/zones/zone123/dns_records/"))
			_, _ = io.WriteString(w, `{"success":true,"result":{}}`)
		default:
			http.NotFound(w, r)
		}
	})
}

func newFakeClient(t *testing.T) (*Cloudflare, *fakeCloudflare) {
	t.Helper()

	fake := &fakeCloudflare{}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)

	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("s3cr3t-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return &Cloudflare{Zone: "example.com", TokenPath: tokenPath, BaseURL: srv.URL}, fake
}

func TestCloudflarePublishesAndRemovesTheChallenge(t *testing.T) {
	cf, fake := newFakeClient(t)
	ctx := context.Background()

	id, err := cf.SetTXT(ctx, "_acme-challenge.z.example.com", "token-value")
	if err != nil {
		t.Fatal(err)
	}

	if id != "rec456" {
		t.Fatalf("record id = %q", id)
	}

	if fake.created["type"] != "TXT" || fake.created["name"] != "_acme-challenge.z.example.com" || fake.created["content"] != "token-value" {
		t.Fatalf("created %v", fake.created)
	}

	if err := cf.DeleteRecord(ctx, id); err != nil {
		t.Fatal(err)
	}

	if len(fake.deleted) != 1 || fake.deleted[0] != "rec456" {
		t.Fatalf("deleted %v", fake.deleted)
	}

	for _, a := range fake.auth {
		if a != "Bearer s3cr3t-token" {
			t.Fatalf("authorization header %q", a)
		}
	}
}

func TestCloudflareErrorsNeverCarryTheToken(t *testing.T) {
	cf, fake := newFakeClient(t)
	fake.failNext = true

	_, err := cf.SetTXT(context.Background(), "_acme-challenge.z.example.com", "v")
	if err == nil {
		t.Fatal("expected an error")
	}

	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error leaks the token: %v", err)
	}

	if !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("error hides Cloudflare's reason: %v", err)
	}
}

func TestCleanTXTRemovesOnlyItsOwnRecords(t *testing.T) {
	cf, fake := newFakeClient(t)

	if err := cf.CleanTXT(context.Background(), "_acme-challenge.z.example.com"); err != nil {
		t.Fatal(err)
	}

	if len(fake.deleted) != 1 || fake.deleted[0] != "old1" {
		t.Fatalf("deleted %v; a record without the mark must stay", fake.deleted)
	}
}

func TestAnUnreadableAccountKeyIsNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, accountKeyFile)

	// A directory in its place: reading fails with something other than "not found".
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := loadOrCreateKey(path); err == nil {
		t.Fatal("expected an error instead of a new key")
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatal("the unreadable key was replaced")
	}
}

func TestARecentOrderBlocksAnotherOne(t *testing.T) {
	m := newTestManager(t)

	if err := writeFile(filepath.Join(m.cfg.CacheDir, attemptFile), []byte("x\n")); err != nil {
		t.Fatal(err)
	}

	// Without the guard this would reach the CA: a restart loop reissuing.
	err := m.obtain(context.Background())

	var tooSoon orderTooSoon
	if !errors.As(err, &tooSoon) || !errors.Is(err, errOrderTooSoon) {
		t.Fatalf("obtain = %v, want orderTooSoon", err)
	}

	if tooSoon.wait <= 0 || tooSoon.wait > minOrderGap {
		t.Fatalf("wait = %s, want what is left of %s", tooSoon.wait, minOrderGap)
	}
}

func TestOrderWaitIsWhatIsLeftAndNeverForever(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	cases := map[string]struct {
		mark time.Time
		want time.Duration
	}{
		"59 minutes ago":  {now.Add(-59 * time.Minute), time.Minute},
		"an hour ago":     {now.Add(-time.Hour), 0},
		"clock went back": {now.Add(3 * time.Hour), 0},
	}
	for name, tc := range cases {
		if got := orderWait(tc.mark, now); got != tc.want {
			t.Errorf("%s: orderWait = %s, want %s", name, got, tc.want)
		}
	}
}

func TestRetryAfterReadsAWrappedRateLimit(t *testing.T) {
	header := http.Header{}
	header.Set("Retry-After", "3600")

	limited := &acme.Error{StatusCode: http.StatusTooManyRequests, ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: header}
	wrapped := fmt.Errorf("creating order: %w", limited)

	wait, ok := retryAfter(wrapped)
	if !ok || wait < 59*time.Minute {
		t.Fatalf("retryAfter = %s, %v; want about an hour", wait, ok)
	}

	if _, ok := retryAfter(errors.New("boom")); ok {
		t.Fatal("a plain error is not a rate limit")
	}
}
