package servertest_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// zoneTXT is the Cloudflare zone, in memory: what each name holds.
type zoneTXT struct {
	mu      sync.Mutex
	next    int
	records map[string]string // id -> name
}

func (z *zoneTXT) SetTXT(_ context.Context, name, _ string) (string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()

	z.next++
	id := fmt.Sprintf("rec-%d", z.next)
	z.records[id] = name

	return id, nil
}

func (z *zoneTXT) DeleteRecord(_ context.Context, id string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	delete(z.records, id)

	return nil
}

func (z *zoneTXT) CleanTXT(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	for id, n := range z.records {
		if n == name {
			delete(z.records, id)
		}
	}

	return nil
}

func (z *zoneTXT) names() []string {
	z.mu.Lock()
	defer z.mu.Unlock()

	out := make([]string, 0, len(z.records))
	for _, n := range z.records {
		out = append(out, n)
	}

	return out
}

const challengeValue = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"

// setDNS sends what `tailscale cert` sends for the DNS-01 challenge, with
// the node key of keyOf and the Noise session of from.
func setDNS(t *testing.T, from, keyOf *servertest.TestClient, name string) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	return from.Direct().SetDNS(ctx, &tailcfg.SetDNSRequest{
		NodeKey: keyOf.Persist().PrivateNodeKey.Public(),
		Type:    "TXT",
		Name:    name,
		Value:   challengeValue,
	})
}

func selfFQDN(c *servertest.TestClient) string {
	return strings.TrimSuffix(c.Netmap().SelfNode.Name(), ".")
}

// A node gets a certificate for its own name and only for it: the TXT
// record is what proves the name to the CA (KEM-465).
func TestNodeCertificatesOwnNameOnly(t *testing.T) {
	t.Parallel()

	zone := &zoneTXT{records: map[string]string{}}
	srv := servertest.NewServer(t,
		servertest.WithMagicDNS("red.z.example.com"),
		servertest.WithNodeCertificates("example.com", zone))
	user := srv.CreateUser(t, "cert-user")

	mini := servertest.NewClient(t, srv, "mini", servertest.WithUser(user))
	other := servertest.NewClient(t, srv, "other", servertest.WithUser(user))

	mini.WaitForPeers(t, 1, 10*time.Second)
	other.WaitForPeers(t, 1, 10*time.Second)

	miniName, otherName := selfFQDN(mini), selfFQDN(other)

	// Without the https attribute: no CertDomains and no record.
	assert.Empty(t, mini.Netmap().DNS.CertDomains)
	require.ErrorContains(t, setDNS(t, mini, mini, "_acme-challenge."+miniName), "403")
	assert.Empty(t, zone.names())

	reloadPolicy(t, srv, `{
		"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}],
		"nodeAttrs": [{"target": ["*"], "attr": ["https"]}]
	}`)

	mini.WaitForCondition(t, "CertDomains carries the node's own name", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return len(nm.DNS.CertDomains) == 1 && nm.DNS.CertDomains[0] == miniName
		})

	// Its own name is published.
	require.NoError(t, setDNS(t, mini, mini, "_acme-challenge."+miniName))
	assert.Equal(t, []string{"_acme-challenge." + miniName}, zone.names())

	// Another node's name is refused and leaves the zone as it was.
	require.ErrorContains(t, setDNS(t, mini, mini, "_acme-challenge."+otherName), "403")
	require.ErrorContains(t, setDNS(t, mini, mini, "_acme-challenge.z.example.com"), "403")
	assert.Equal(t, []string{"_acme-challenge." + miniName}, zone.names())

	// Presenting the other node's key over its own Noise session gets nowhere.
	require.ErrorContains(t, setDNS(t, mini, other, "_acme-challenge."+otherName), "404")
	assert.Equal(t, []string{"_acme-challenge." + miniName}, zone.names())
}

// Without a zone the server edits, set-dns stays unimplemented, as in Headscale.
func TestNodeCertificatesOffWithoutZone(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithMagicDNS("red.z.example.com"))
	user := srv.CreateUser(t, "nocert-user")
	c := servertest.NewClient(t, srv, "plain", servertest.WithUser(user))
	c.WaitForUpdate(t, 10*time.Second)

	reloadPolicy(t, srv, `{
		"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}],
		"nodeAttrs": [{"target": ["*"], "attr": ["https"]}]
	}`)

	c.WaitForCondition(t, "https attribute delivered", 10*time.Second,
		func(nm *netmap.NetworkMap) bool { return hasCap(nm, "https") })

	assert.Empty(t, c.Netmap().DNS.CertDomains)
	require.ErrorContains(t, setDNS(t, c, c, "_acme-challenge."+selfFQDN(c)), "501")
}
