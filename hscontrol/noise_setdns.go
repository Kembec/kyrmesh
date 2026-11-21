package hscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/juanfont/headscale/hscontrol/dnscert"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// maxSetDNSBody bounds a set-dns request: a node key, a name and a value.
const maxSetDNSBody = 4 << 10

// SetDNSHandler answers [tailcfg.SetDNSRequest], which `tailscale cert`
// and `tailscale serve` send to publish the ACME DNS-01 record of the
// node's own MagicDNS name. It is on only when the server can edit the zone
// of base_domain; a node also needs the "https" attribute from the policy.
// Otherwise it answers 501, as Headscale does (KEM-465).
func (ns *noiseServer) SetDNSHandler(writer http.ResponseWriter, req *http.Request) {
	certs := ns.headscale.nodeCerts
	if certs == nil {
		ns.NotImplementedHandler(writer, req)

		return
	}

	var setReq tailcfg.SetDNSRequest

	err := json.NewDecoder(io.LimitReader(req.Body, maxSetDNSBody)).Decode(&setReq)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "invalid set-dns request", err))

		return
	}

	// The node key must belong to the machine key of this Noise session.
	nv, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: setReq.NodeKey})
	if err != nil {
		httpError(writer, err)

		return
	}

	err = ns.publishChallenge(req.Context(), certs, nv, setReq)
	if err != nil {
		httpError(writer, err)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(tailcfg.SetDNSResponse{})
}

func (ns *noiseServer) publishChallenge(
	ctx context.Context,
	certs *dnscert.NodeChallenges,
	nv types.NodeView,
	setReq tailcfg.SetDNSRequest,
) error {
	if nv.IsExpired() {
		return NewHTTPError(http.StatusForbidden, "node key expired", nil)
	}

	if _, ok := ns.headscale.state.NodeCapMap(nv.ID())[nodecap.HTTPS]; !ok {
		return NewHTTPError(http.StatusForbidden, "the policy does not give this node the https attribute", nil)
	}

	fqdn, err := nv.GetFQDN(ns.headscale.cfg.BaseDomain)
	if err != nil {
		return NewHTTPError(http.StatusForbidden, "node has no MagicDNS name", err)
	}

	err = certs.Publish(ctx, uint64(nv.ID()), fqdn, setReq.Type, setReq.Name, setReq.Value)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, dnscert.ErrForeignName):
		return NewHTTPError(http.StatusForbidden, "a node can only publish the challenge of its own name", err)
	case errors.Is(err, dnscert.ErrBadChallenge):
		return NewHTTPError(http.StatusBadRequest, "only an ACME DNS-01 TXT record is accepted", err)
	case errors.Is(err, dnscert.ErrTooMany):
		return NewHTTPError(http.StatusTooManyRequests, "too many challenge records, retry later", err)
	default:
		return NewHTTPError(http.StatusBadGateway, "could not publish the challenge record", err)
	}
}
