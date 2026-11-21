package dnscert

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// Errors a node gets back from [NodeChallenges.Publish].
var (
	ErrForeignName  = errors.New("dnscert: a node can only publish the challenge of its own name")
	ErrBadChallenge = errors.New("dnscert: not an ACME DNS-01 TXT record")
	ErrTooMany      = errors.New("dnscert: too many challenge records for this node")
)

const (
	challengePrefix = "_acme-challenge."
	// The CA reads the record within seconds; ten minutes covers a slow order.
	removeChallengeAfter = 10 * time.Minute
	// One certificate takes one record. The burst absorbs the client's own
	// retries; past it, a node cannot spend the token's API quota, which the
	// server's own renewal shares.
	nodeChallengeEvery = 10 * time.Minute
	nodeChallengeBurst = 6
)

// dns01Value is the unpadded base64url SHA-256 of an ACME key
// authorization: nothing else may be written into the zone.
var dns01Value = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// NodeChallenges publishes the DNS-01 record a node needs to obtain a
// certificate for its own MagicDNS name (`tailscale cert`, `tailscale
// serve`). The record proves control of the name to the CA, so a node may
// only publish the one of its own name (KEM-465).
type NodeChallenges struct {
	zone string
	dns  TXTProvider

	// Wait returns once the record is served where the CA will look;
	// it defaults to asking the zone's authoritative servers.
	Wait func(ctx context.Context, zone, fqdn, value string) error
	// RemoveAfter is how long a record stays before it is deleted.
	RemoveAfter time.Duration

	mu       sync.Mutex
	limiters map[uint64]*rate.Limiter
}

// NewNodeChallenges publishes node challenges inside zone through dns.
func NewNodeChallenges(zone string, dns TXTProvider) *NodeChallenges {
	return &NodeChallenges{
		zone:        normalizeName(zone),
		dns:         dns,
		Wait:        waitForAuthoritativeTXT,
		RemoveAfter: removeChallengeAfter,
		limiters:    make(map[uint64]*rate.Limiter),
	}
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Publish writes the TXT record name=value for the node nodeID, whose
// MagicDNS name is fqdn, and returns once the record is served. The record
// is removed after RemoveAfter.
func (n *NodeChallenges) Publish(
	ctx context.Context,
	nodeID uint64,
	fqdn, recordType, name, value string,
) error {
	if recordType != "TXT" || !dns01Value.MatchString(value) {
		return ErrBadChallenge
	}

	own := challengePrefix + normalizeName(fqdn)
	if normalizeName(name) != own || !strings.HasSuffix(own, "."+n.zone) {
		return fmt.Errorf("%w: asked for %q", ErrForeignName, name)
	}

	if !n.limiter(nodeID).Allow() {
		return ErrTooMany
	}

	// No cleanup of the name first: a wildcard order puts two values on it,
	// and the CA accepts the record set if any value matches. Every record
	// is removed on its own timer, and the limiter bounds how many live.
	id, err := n.dns.SetTXT(ctx, own, value)
	if err != nil {
		return err
	}

	time.AfterFunc(n.RemoveAfter, func() { n.remove(own, id) })

	return n.Wait(ctx, n.zone, own, value)
}

func (n *NodeChallenges) limiter(nodeID uint64) *rate.Limiter {
	n.mu.Lock()
	defer n.mu.Unlock()

	l, ok := n.limiters[nodeID]
	if !ok {
		l = rate.NewLimiter(rate.Every(nodeChallengeEvery), nodeChallengeBurst)
		n.limiters[nodeID] = l
	}

	return l
}

func (n *NodeChallenges) remove(name, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := n.dns.DeleteRecord(ctx, id); err != nil { //nolint:noinlineerr
		log.Warn().Err(err).Str("name", name).Msg("dnscert: removing a node challenge record")
	}
}
