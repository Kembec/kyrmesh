package dnscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
)

const (
	accountKeyFile = "account.key"
	// Chain and key in one file, written in one rename: a crash can never
	// leave a key that does not match its certificate (review, 20/11).
	pairFile = "wildcard.pem"
	// Mark of the last order: a restart loop must not reissue (5 duplicate
	// certificates per week lock the name out).
	attemptFile = "last-order"
	minOrderGap = time.Hour
	// Cloudflare publishes a record in seconds; the wait covers a slow edge.
	propagationTimeout = 3 * time.Minute
)

var (
	errNoDNS01      = errors.New("authorization offers no dns-01 challenge")
	errOrderTooSoon = errors.New("last order was less than an hour ago")
)

// orderTooSoon says how long until the next order is allowed.
type orderTooSoon struct{ wait time.Duration }

func (e orderTooSoon) Error() string        { return fmt.Sprintf("%s; next in %s", errOrderTooSoon, e.wait) }
func (e orderTooSoon) Is(target error) bool { return target == errOrderTooSoon }

// orderWait is how long the mark still blocks an order: zero without a mark,
// once the gap has passed, or when the mark is in the future (the clock went
// back) — a mark must never block forever (second review, 20/11).
func orderWait(markTime, now time.Time) time.Duration {
	elapsed := now.Sub(markTime)
	if elapsed < 0 || elapsed >= minOrderGap {
		return 0
	}

	return minOrderGap - elapsed
}

// retryAfter is the CA's own wait on a rate limit. obtain wraps errors, and
// acme.RateLimit only accepts the bare *acme.Error, so it is unwrapped here.
func retryAfter(err error) (time.Duration, bool) {
	var aerr *acme.Error
	if !errors.As(err, &aerr) {
		return 0, false
	}

	return acme.RateLimit(aerr)
}

// obtain runs one DNS-01 order for the wildcard and installs the result.
func (m *Manager) obtain(ctx context.Context) error {
	if err := os.MkdirAll(m.cfg.CacheDir, 0o700); err != nil { //nolint:noinlineerr
		return fmt.Errorf("creating cache dir: %w", err)
	}

	mark := filepath.Join(m.cfg.CacheDir, attemptFile)
	if info, err := os.Stat(mark); err == nil {
		if wait := orderWait(info.ModTime(), m.now()); wait > 0 {
			return orderTooSoon{wait: wait}
		}
	}

	accountKey, err := loadOrCreateKey(filepath.Join(m.cfg.CacheDir, accountKeyFile))
	if err != nil {
		return err
	}

	client := &acme.Client{Key: accountKey, DirectoryURL: m.cfg.DirectoryURL}

	account := &acme.Account{}
	if m.cfg.Email != "" {
		account.Contact = []string{"mailto:" + m.cfg.Email}
	}

	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) { //nolint:noinlineerr
		return fmt.Errorf("registering acme account: %w", err)
	}

	// The mark goes right before the order, once the CA answered: a network
	// failure before this point placed no order and must not hold the next one.
	if err := writeFile(mark, []byte(m.now().UTC().Format(time.RFC3339)+"\n")); err != nil { //nolint:noinlineerr
		return err
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.cfg.Wildcard))
	if err != nil {
		return fmt.Errorf("creating order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := m.authorize(ctx, client, authzURL); err != nil { //nolint:noinlineerr
			return err
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return fmt.Errorf("waiting for order: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating certificate key: %w", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{m.cfg.Wildcard}}, certKey)
	if err != nil {
		return fmt.Errorf("building csr: %w", err)
	}

	// CreateOrderCert follows the Location of the finalize response, which
	// RFC 8555 does not require: Pebble omits it and the e2e sent `Post ""`.
	// CreateCertFromOrder polls the order URL already known.
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return fmt.Errorf("finalizing order: %w", err)
	}

	pairPEM, err := encodePair(chain, certKey)
	if err != nil {
		return err
	}

	cert, err := parsePair(pairPEM)
	if err != nil {
		return err
	}

	// Serve it even if the cache write fails: reissuing for that would burn
	// the weekly duplicate limit (review, 20/11).
	m.set(cert)
	log.Info().Time("not_after", cert.Leaf.NotAfter).Msg("dnscert: certificate obtained")

	if err := writeFile(filepath.Join(m.cfg.CacheDir, pairFile), pairPEM); err != nil { //nolint:noinlineerr
		log.Error().Err(err).Msg("dnscert: caching certificate; it is served from memory until the next restart")
	}

	return nil
}

// authorize answers one authorization with a TXT record, removed afterwards
// whatever the outcome.
func (m *Manager) authorize(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("reading authorization: %w", err)
	}

	if authz.Status == acme.StatusValid {
		return nil
	}

	idx := slices.IndexFunc(authz.Challenges, func(c *acme.Challenge) bool { return c.Type == "dns-01" })
	if idx < 0 {
		return errNoDNS01
	}

	chal := authz.Challenges[idx]

	value, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("computing dns-01 record: %w", err)
	}

	fqdn := "_acme-challenge." + authz.Identifier.Value

	// A record left by a lost response would otherwise stay published.
	if err := m.dns.CleanTXT(ctx, fqdn); err != nil { //nolint:noinlineerr
		log.Warn().Err(err).Str("record", fqdn).Msg("dnscert: removing stale dns-01 records")
	}

	recordID, err := m.dns.SetTXT(ctx, fqdn, value)
	if err != nil {
		return fmt.Errorf("publishing dns-01 record: %w", err)
	}

	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()

		if err := m.dns.DeleteRecord(cleanup, recordID); err != nil { //nolint:noinlineerr
			log.Warn().Err(err).Str("record", fqdn).Msg("dnscert: removing dns-01 record")
		}
	}()

	if err := m.wait(ctx, fqdn, value); err != nil { //nolint:noinlineerr
		return err
	}

	if _, err := client.Accept(ctx, chal); err != nil { //nolint:noinlineerr
		return fmt.Errorf("accepting challenge: %w", err)
	}

	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil { //nolint:noinlineerr
		return fmt.Errorf("waiting for authorization: %w", err)
	}

	return nil
}

// waitForTXT polls a public resolver until the record is visible.
func waitForTXT(ctx context.Context, fqdn, value string) error {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer

			return d.DialContext(ctx, network, "1.1.1.1:53")
		},
	}

	deadline := time.Now().Add(propagationTimeout)
	for time.Now().Before(deadline) {
		if txts, err := resolver.LookupTXT(ctx, fqdn); err == nil && slices.Contains(txts, value) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	return fmt.Errorf("dns-01 record %s not visible after %s", fqdn, propagationTimeout)
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s holds no PEM block", path)
		}

		return x509.ParseECPrivateKey(block.Bytes)
	}

	// Only a missing key is created: any other error must not replace the
	// account key (review, 20/11).
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding account key: %w", err)
	}

	if err := writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil { //nolint:noinlineerr
		return nil, err
	}

	return key, nil
}

// encodePair is the chain followed by its key, as one PEM document.
func encodePair(chain [][]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding certificate key: %w", err)
	}

	return append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})...), nil
}

// storeCert writes chain and key in one file and returns the parsed pair.
func storeCert(dir string, chain [][]byte, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	data, err := encodePair(chain, key)
	if err != nil {
		return nil, err
	}

	if err := writeFile(filepath.Join(dir, pairFile), data); err != nil { //nolint:noinlineerr
		return nil, err
	}

	return parsePair(data)
}

// loadCached returns the cached pair if it is for this wildcard.
func loadCached(dir, wildcard string) (*tls.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(dir, pairFile))
	if err != nil {
		return nil, err
	}

	cert, err := parsePair(data)
	if err != nil {
		return nil, err
	}

	if !slices.ContainsFunc(cert.Leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, wildcard) }) {
		return nil, fmt.Errorf("cached certificate is not for %s", wildcard)
	}

	return cert, nil
}

// parsePair reads the certificates and the key from one PEM document.
func parsePair(data []byte) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}

	pair.Leaf = leaf

	return &pair, nil
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint:noinlineerr
		return fmt.Errorf("writing %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil { //nolint:noinlineerr
		return fmt.Errorf("installing %s: %w", path, err)
	}

	return nil
}
