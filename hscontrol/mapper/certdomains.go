package mapper

import (
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// withCertDomains offers the node a certificate for its own MagicDNS name
// when the policy gives it the "https" attribute and the server can
// publish the ACME record in the zone of base_domain. Clients read
// CertDomains to decide what `tailscale cert` and `serve` may ask for
// (KEM-465).
func withCertDomains(
	dnsConfig *tailcfg.DNSConfig,
	cfg *types.Config,
	node types.NodeView,
	capMap tailcfg.NodeCapMap,
) *tailcfg.DNSConfig {
	if cfg.NodeCertZone() == "" {
		return dnsConfig
	}

	if _, ok := capMap[nodecap.HTTPS]; !ok {
		return dnsConfig
	}

	fqdn, err := node.GetFQDN(cfg.BaseDomain)
	if err != nil {
		return dnsConfig
	}

	dnsConfig.CertDomains = []string{strings.TrimSuffix(fqdn, ".")}

	return dnsConfig
}
