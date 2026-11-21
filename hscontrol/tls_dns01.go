package hscontrol

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"

	"github.com/juanfont/headscale/hscontrol/dnscert"
)

// dns01TLSConfig serves a wildcard certificate renewed in-process through
// Cloudflare DNS-01, answering TLS only for the server_url host (KEM-460).
func (h *Headscale) dns01TLSConfig() (*tls.Config, error) {
	u, err := url.Parse(h.cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parsing server_url: %w", err)
	}

	cfg := h.cfg.TLS.DNS01

	mgr, err := dnscert.New(dnscert.Config{
		Wildcard:     cfg.Wildcard,
		ServerName:   u.Hostname(),
		CacheDir:     cfg.CacheDir,
		DirectoryURL: h.cfg.ACMEURL,
		Email:        h.cfg.ACMEEmail,
	}, &dnscert.Cloudflare{Zone: cfg.CloudflareZone, TokenPath: cfg.CloudflareTokenPath})
	if err != nil {
		return nil, err
	}

	mgr.Start(context.Background())

	return mgr.TLSConfig(), nil
}
