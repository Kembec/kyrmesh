package hscontrol

import (
	"context"
	"testing"

	"github.com/juanfont/headscale/hscontrol/dnscert"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// newNodeChallenges is nil unless nodes can get certificates for their own
// MagicDNS names through the Cloudflare zone the server edits (KEM-465).
func newNodeChallenges(cfg *types.Config) *dnscert.NodeChallenges {
	zone := cfg.NodeCertZone()
	if zone == "" {
		return nil
	}

	log.Info().Str("zone", zone).Msg("dnscert: node certificates on for nodes with the https attribute")

	return dnscert.NewNodeChallenges(zone, &dnscert.Cloudflare{
		Zone:      cfg.TLS.DNS01.CloudflareZone,
		TokenPath: cfg.TLS.DNS01.CloudflareTokenPath,
	})
}

// SetNodeCertDNSForTest publishes node challenges through dns and treats a
// written record as served.
func (h *Headscale) SetNodeCertDNSForTest(tb testing.TB, dns dnscert.TXTProvider) {
	tb.Helper()

	certs := dnscert.NewNodeChallenges(h.cfg.NodeCertZone(), dns)
	certs.Wait = func(context.Context, string, string, string) error { return nil }
	h.nodeCerts = certs
}
