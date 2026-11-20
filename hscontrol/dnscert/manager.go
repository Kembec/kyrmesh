// Package dnscert keeps a wildcard certificate for the control server,
// obtained with the ACME DNS-01 challenge and renewed inside the process.
//
// Why a wildcard: every publicly trusted certificate is published in the
// Certificate Transparency logs, so a certificate for the server's own name
// announces the server to anyone who watches them. A wildcard for a
// dedicated subzone publishes only "*.<subzone>"; the server's name never
// appears (KEM-460). The server also answers TLS only for that exact name,
// so a scanner that reaches the address without it gets no certificate.
package dnscert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
)

// TXTProvider publishes the DNS-01 TXT record and removes it afterwards.
type TXTProvider interface {
	SetTXT(ctx context.Context, name, value string) (string, error)
	DeleteRecord(ctx context.Context, id string) error
	// CleanTXT removes TXT records for name that this package left behind.
	CleanTXT(ctx context.Context, name string) error
}

// Config is what the manager needs; it holds no secret.
type Config struct {
	// Wildcard is the certificate name, "*.<subzone>".
	Wildcard string
	// ServerName is the only name TLS answers for; it must be covered by Wildcard.
	ServerName   string
	CacheDir     string
	DirectoryURL string
	Email        string
}

const (
	renewBefore  = 30 * 24 * time.Hour
	checkEvery   = 12 * time.Hour
	retryInitial = time.Minute
	retryMax     = time.Hour
)

var (
	errNoCertificate = errors.New("no certificate yet")
	errUnknownName   = errors.New("unknown server name")
)

// Manager serves the cached certificate and renews it in the background.
type Manager struct {
	cfg  Config
	dns  TXTProvider
	now  func() time.Time
	wait func(ctx context.Context, fqdn, value string) error

	mu   sync.RWMutex
	cert *tls.Certificate
}

// Covers reports whether wildcard ("*.zone") is valid for name: exactly one
// label in front of zone, as a TLS wildcard matches.
func Covers(wildcard, name string) bool {
	zone, ok := strings.CutPrefix(strings.ToLower(wildcard), "*.")
	if !ok || zone == "" {
		return false
	}

	label, rest, ok := strings.Cut(strings.ToLower(name), ".")

	return ok && label != "" && rest == zone
}

// New returns a manager; Start loads the cache and begins renewing.
func New(cfg Config, dns TXTProvider) (*Manager, error) {
	if !Covers(cfg.Wildcard, cfg.ServerName) {
		return nil, fmt.Errorf("dnscert: %q is not covered by %q", cfg.ServerName, cfg.Wildcard)
	}

	return &Manager{cfg: cfg, dns: dns, now: time.Now, wait: waitForTXT}, nil
}

// TLSConfig answers only for the configured server name.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: m.getCertificate,
	}
}

func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if !strings.EqualFold(hello.ServerName, m.cfg.ServerName) {
		return nil, errUnknownName
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cert == nil {
		return nil, errNoCertificate
	}

	return m.cert, nil
}

func (m *Manager) current() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.cert
}

func (m *Manager) set(cert *tls.Certificate) {
	m.mu.Lock()
	m.cert = cert
	m.mu.Unlock()
}

// needsRenewal: no certificate, or one that expires within renewBefore.
func (m *Manager) needsRenewal() bool {
	cert := m.current()
	if cert == nil || cert.Leaf == nil {
		return true
	}

	return m.now().Add(renewBefore).After(cert.Leaf.NotAfter)
}

// Start loads the cached certificate and keeps it renewed until ctx ends.
// A failed issuance is retried with backoff, never in a tight loop: ACME
// rate limits would lock the name out for a week.
func (m *Manager) Start(ctx context.Context) {
	if cert, err := loadCached(m.cfg.CacheDir, m.cfg.Wildcard); err == nil {
		m.set(cert)
		log.Info().Time("not_after", cert.Leaf.NotAfter).Msg("dnscert: loaded cached certificate")
	}

	go m.loop(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	retry := retryInitial

	for {
		next := checkEvery

		if m.needsRenewal() {
			if err := m.obtain(ctx); err != nil {
				next = retry
				// The CA's own wait wins over ours (Retry-After on a rate limit).
				if wait, ok := acme.RateLimit(err); ok {
					next = max(next, wait)
				}

				if errors.Is(err, errOrderTooSoon) {
					next = max(next, minOrderGap)
				}

				log.Error().Err(err).Dur("retry_in", next).Msg("dnscert: obtaining certificate")
				retry = min(retry*2, retryMax)
			} else {
				retry = retryInitial
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}
