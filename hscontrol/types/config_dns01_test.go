package types

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestValidateDNS01(t *testing.T) {
	base := map[string]string{
		"server_url":                      "https://h4.z.example.com",
		"tls_dns01_wildcard":              "*.z.example.com",
		"tls_dns01_cloudflare_zone":       "example.com",
		"tls_dns01_cloudflare_token_path": "/etc/kyrmesh/cloudflare-token",
		"tls_dns01_cache_dir":             "/var/lib/kyrmesh/dnscert",
	}

	cases := map[string]struct {
		change map[string]string
		want   string
	}{
		"valid":             {nil, ""},
		"not covered":       {map[string]string{"server_url": "https://a.b.z.example.com"}, "must cover"},
		"http server url":   {map[string]string{"server_url": "http://h4.z.example.com"}, "https server_url"},
		"zone outside":      {map[string]string{"tls_dns01_cloudflare_zone": "other.com"}, "inside tls_dns01_cloudflare_zone"},
		"no token":          {map[string]string{"tls_dns01_cloudflare_token_path": ""}, "needs tls_dns01_cloudflare_zone"},
		"with letsencrypt":  {map[string]string{"tls_letsencrypt_hostname": "h4.z.example.com"}, "excludes"},
		"off when no value": {map[string]string{"tls_dns01_wildcard": ""}, ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			for k, v := range base {
				viper.Set(k, v)
			}

			for k, v := range tc.change {
				viper.Set(k, v)
			}

			got := validateDNS01()
			if tc.want == "" && got != "" {
				t.Fatalf("unexpected error: %s", got)
			}

			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
