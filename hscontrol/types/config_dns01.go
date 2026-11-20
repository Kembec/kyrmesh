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
