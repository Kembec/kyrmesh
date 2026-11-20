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
	certFile       = "wildcard.crt"
	keyFile        = "wildcard.key"
	// Cloudflare publishes a record in seconds; the wait covers a slow edge.
	propagationTimeout = 3 * time.Minute
)

var errNoDNS01 = errors.New("authorization offers no dns-01 challenge")

// obtain runs one DNS-01 order for the wildcard and installs the result.
func (m *Manager) obtain(ctx context.Context) error {
	if err := os.MkdirAll(m.cfg.CacheDir, 0o700); err != nil { //nolint:noinlineerr
		return fmt.Errorf("creating cache dir: %w", err)
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

	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalizing order: %w", err)
	}

	cert, err := storeCert(m.cfg.CacheDir, chain, certKey)
	if err != nil {
		return err
	}

	m.set(cert)
	log.Info().Time("not_after", cert.Leaf.NotAfter).Msg("dnscert: certificate obtained")

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
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s holds no PEM block", path)
		}

		return x509.ParseECPrivateKey(block.Bytes)
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

// storeCert writes chain and key atomically and returns the parsed pair.
func storeCert(dir string, chain [][]byte, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding certificate key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	if err := writeFile(filepath.Join(dir, keyFile), keyPEM); err != nil { //nolint:noinlineerr
		return nil, err
	}

	if err := writeFile(filepath.Join(dir, certFile), certPEM); err != nil { //nolint:noinlineerr
		return nil, err
	}

	return parsePair(certPEM, keyPEM)
}

// loadCached returns the cached pair if it is for this wildcard.
func loadCached(dir, wildcard string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}

	cert, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	if !slices.ContainsFunc(cert.Leaf.DNSNames, func(n string) bool { return strings.EqualFold(n, wildcard) }) {
		return nil, fmt.Errorf("cached certificate is not for %s", wildcard)
	}

	return cert, nil
}

func parsePair(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
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
