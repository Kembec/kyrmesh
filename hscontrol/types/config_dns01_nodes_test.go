package types

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestNodeCertZone(t *testing.T) {
	type tc struct {
		base, zone, token, server string
		magicOff                  bool
		want                      string
	}

	on := func(base, zone string) tc { return tc{base: base, zone: zone, token: "/t", want: "example.com"} }
	off := func(c tc) tc { c.want = ""; return c }

	cases := map[string]tc{
		"below the zone":       on("red.z.example.com", "example.com"),
		"zone with dot, case":  on("Red.Z.Example.com", "Example.COM."),
		"base is the zone":     off(on("example.com", "example.com")),
		"base outside":         off(on("red.example.org", "example.com")),
		"suffix but not below": off(on("redexample.com", "example.com")),
		"no token":             off(tc{base: "red.z.example.com", zone: "example.com"}),
		"no zone":              off(on("red.z.example.com", "")),
		"magic dns off": func() tc {
			c := off(on("red.z.example.com", "example.com"))
			c.magicOff = true

			return c
		}(),
		// A node named like the server would get the server's certificate.
		"server below base": func() tc {
			c := off(on("red.z.example.com", "example.com"))
			c.server = "https://h.red.z.example.com:443"

			return c
		}(),
		"server is base": func() tc {
			c := off(on("red.z.example.com", "example.com"))
			c.server = "https://red.z.example.com"

			return c
		}(),
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server := c.server
			if server == "" {
				server = "https://h4.z.example.com"
			}

			cfg := Config{
				ServerURL:        server,
				BaseDomain:       c.base,
				TailcfgDNSConfig: &tailcfg.DNSConfig{Proxied: !c.magicOff},
			}
			cfg.TLS.DNS01.CloudflareZone = c.zone
			cfg.TLS.DNS01.CloudflareTokenPath = c.token

			if got := cfg.NodeCertZone(); got != c.want {
				t.Fatalf("NodeCertZone() = %q, want %q", got, c.want)
			}
		})
	}
}
