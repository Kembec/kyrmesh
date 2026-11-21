package types

import (
	"net/url"
	"strings"

	"github.com/juanfont/headscale/hscontrol/dnscert"
	"github.com/spf13/viper"
)

// validateDNS01 returns the config errors of the tls_dns01_* block, or "".
func validateDNS01() string {
	wildcard := viper.GetString("tls_dns01_wildcard")
	if wildcard == "" {
		return ""
	}

	var errs string

	if viper.GetString("tls_letsencrypt_hostname") != "" || viper.GetString("tls_cert_path") != "" {
		errs += "Fatal config error: tls_dns01_wildcard excludes tls_letsencrypt_hostname and tls_cert_path\n"
	}

	if viper.GetString("tls_dns01_cloudflare_zone") == "" || viper.GetString("tls_dns01_cloudflare_token_path") == "" {
		errs += "Fatal config error: tls_dns01_wildcard needs tls_dns01_cloudflare_zone and tls_dns01_cloudflare_token_path\n"
	}

	if viper.GetString("tls_dns01_cache_dir") == "" {
		errs += "Fatal config error: tls_dns01_wildcard needs tls_dns01_cache_dir\n"
	}

	u, err := url.Parse(viper.GetString("server_url"))
	if err != nil || u.Scheme != "https" {
		return errs + "Fatal config error: tls_dns01_wildcard needs an https server_url\n"
	}

	if !dnscert.Covers(wildcard, u.Hostname()) {
		errs += "Fatal config error: tls_dns01_wildcard must cover the server_url host with exactly one label\n"
	}

	zone := strings.ToLower(viper.GetString("tls_dns01_cloudflare_zone"))
	if zone != "" && !strings.HasSuffix(strings.ToLower(wildcard), "."+zone) && strings.ToLower(wildcard) != "*."+zone {
		errs += "Fatal config error: tls_dns01_wildcard must be inside tls_dns01_cloudflare_zone\n"
	}

	return errs
}

// NodeCertZone is the Cloudflare zone in which a node may publish the
// DNS-01 record for a certificate of its own MagicDNS name, or "" when node
// certificates are off. base_domain must sit strictly below the zone and
// belong to the tailnet alone: every <node>.<base_domain> becomes a name a
// node can get a public certificate for (KEM-465).
func (c *Config) NodeCertZone() string {
	dns01 := c.TLS.DNS01
	if dns01.CloudflareZone == "" || dns01.CloudflareTokenPath == "" {
		return ""
	}

	if c.TailcfgDNSConfig == nil || !c.TailcfgDNSConfig.Proxied {
		return ""
	}

	zone := strings.ToLower(strings.TrimSuffix(dns01.CloudflareZone, "."))

	base := strings.ToLower(c.BaseDomain)
	if !strings.HasSuffix(base, "."+zone) {
		return ""
	}

	// A node named like the server would get the server's certificate.
	server, err := url.Parse(c.ServerURL)
	if err != nil || server.Hostname() == "" {
		return ""
	}

	host := strings.ToLower(server.Hostname())
	if host == base || strings.HasSuffix(host, "."+base) {
		return ""
	}

	return zone
}
