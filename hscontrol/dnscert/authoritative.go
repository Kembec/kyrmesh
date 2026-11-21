package dnscert

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

const (
	authoritativeTimeout = 90 * time.Second
	authoritativePoll    = 2 * time.Second
)

// waitForAuthoritativeTXT polls every name server of zone until each one
// serves value at fqdn. It asks them directly because the client looks the
// name up before asking for it: a resolver that cached that "no such name"
// would hide the new record for the zone's negative TTL.
func waitForAuthoritativeTXT(ctx context.Context, zone, fqdn, value string) error {
	ctx, cancel := context.WithTimeout(ctx, authoritativeTimeout)
	defer cancel()

	servers, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil {
		return fmt.Errorf("dnscert: looking up the name servers of %s: %w", zone, err)
	}

	if len(servers) == 0 {
		return fmt.Errorf("dnscert: %s has no name servers", zone)
	}

	for {
		if servedByAll(ctx, servers, fqdn, value) {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("dnscert: %s not served by the name servers of %s: %w", fqdn, zone, ctx.Err())
		case <-time.After(authoritativePoll):
		}
	}
}

func servedByAll(ctx context.Context, servers []*net.NS, fqdn, value string) bool {
	for _, ns := range servers {
		if !servedBy(ctx, strings.TrimSuffix(ns.Host, "."), fqdn, value) {
			return false
		}
	}

	return true
}

func servedBy(ctx context.Context, server, fqdn, value string) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer

			return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}

	txts, err := resolver.LookupTXT(ctx, strings.TrimSuffix(fqdn, ".")+".")

	return err == nil && slices.Contains(txts, value)
}
