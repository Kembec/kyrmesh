package dnscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// fakeCA is an RFC 8555 CA that, like Pebble, answers the finalize request
// with a "processing" order and no Location header. Signatures are not
// checked: the test is about the order flow, not about JWS.
type fakeCA struct {
	t    *testing.T
	base string

	mu        sync.Mutex
	chain     [][]byte
	finalized bool
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()

	ca := &fakeCA{t: t}
	srv := httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(srv.Close)
	ca.base = srv.URL

	return ca
}

func (ca *fakeCA) reply(w http.ResponseWriter, code int, location string, body any) {
	w.Header().Set("Content-Type", "application/json")

	if location != "" {
		w.Header().Set("Location", location)
	}

	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func (ca *fakeCA) order() map[string]any {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	o := map[string]any{
		"status":         "ready",
		"identifiers":    []map[string]string{{"type": "dns", "value": testWildcard}},
		"authorizations": []string{},
		"finalize":       ca.base + "/finalize/1",
	}
	if ca.finalized {
		o["status"] = "valid"
		o["certificate"] = ca.base + "/cert/1"
	}

	return o
}

func (ca *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "nonce")

	switch r.URL.Path {
	case "/dir":
		ca.reply(w, http.StatusOK, "", map[string]string{
			"newNonce": ca.base + "/nonce", "newAccount": ca.base + "/acct", "newOrder": ca.base + "/order-new",
		})
	case "/nonce":
		w.WriteHeader(http.StatusOK)
	case "/acct":
		ca.reply(w, http.StatusCreated, ca.base+"/acct/1", map[string]any{"status": "valid"})
	case "/order-new":
		ca.reply(w, http.StatusCreated, ca.base+"/order/1", ca.order())
	case "/order/1":
		ca.reply(w, http.StatusOK, "", ca.order())
	case "/finalize/1":
		ca.finalize(r)

		o := ca.order()
		o["status"] = "processing"
		delete(o, "certificate")
		ca.reply(w, http.StatusOK, "", o)
	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")

		ca.mu.Lock()
		for _, der := range ca.chain {
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		ca.mu.Unlock()
	default:
		http.NotFound(w, r)
	}
}

// finalize issues a certificate for the CSR inside the JWS payload.
func (ca *fakeCA) finalize(r *http.Request) {
	var jws struct{ Payload string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		ca.t.Errorf("finalize body: %v", err)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		ca.t.Errorf("finalize payload: %v", err)
		return
	}

	var req struct{ CSR string }
	if err := json.Unmarshal(payload, &req); err != nil {
		ca.t.Errorf("finalize request: %v", err)
		return
	}

	raw, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		ca.t.Errorf("csr encoding: %v", err)
		return
	}

	csr, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		ca.t.Errorf("csr: %v", err)
		return
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ca.t.Errorf("ca key: %v", err)
		return
	}

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		ca.t.Errorf("ca cert: %v", err)
		return
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, csr.PublicKey, caKey)
	if err != nil {
		ca.t.Errorf("leaf cert: %v", err)
		return
	}

	ca.mu.Lock()
	ca.chain = [][]byte{leafDER, caDER}
	ca.finalized = true
	ca.mu.Unlock()
}

// Pebble and RFC 8555 do not require a Location header on the finalize
// response. Following it, instead of the order URL already known, sent the
// e2e on Lima to `Post ""` and left the order mark holding the retry 1 h.
func TestFinalizeWithoutLocationStillIssues(t *testing.T) {
	ca := newFakeCA(t)

	m, err := New(Config{Wildcard: testWildcard, ServerName: testServer, CacheDir: t.TempDir(), DirectoryURL: ca.base + "/dir"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := m.obtain(ctx); err != nil {
		t.Fatalf("obtain = %v, want the certificate", err)
	}

	cert := m.current()
	if cert == nil || !slices.Contains(cert.Leaf.DNSNames, testWildcard) {
		t.Fatalf("served certificate = %v, want one for %s", cert, testWildcard)
	}
}
