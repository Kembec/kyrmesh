package state

import (
	"errors"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
)

// ErrInviteNotRegistration is returned when the pending auth request behind
// an invitation is not a node registration (an SSH check, for instance).
var ErrInviteNotRegistration = errors.New("pending auth request is not a node registration")

// HandleNodeFromInvite registers the device waiting on authID with the
// pre-auth key an invitation carries.
//
// It goes through [State.HandleNodeFromPreAuthKey] on purpose: the key's
// user, tags, single use, expiry and revocation decide the outcome exactly
// as they do for `tailscale up --authkey`. The invitation only replaces
// "type the key" with "open the link"; it never grants anything the key
// would not.
//
// On failure the pending request stays in the cache, so the person can fix
// the cause (open a new invitation) and confirm again while the device keeps
// waiting.
func (s *State) HandleNodeFromInvite(
	authID types.AuthID,
	authKey string,
) (types.NodeView, change.Change, error) {
	regEntry, ok := s.GetAuthCacheEntry(authID)
	if !ok {
		return types.NodeView{}, change.Change{}, hsdb.ErrNodeNotFoundRegistrationCache
	}

	if !regEntry.IsRegistration() {
		return types.NodeView{}, change.Change{}, ErrInviteNotRegistration
	}

	regData := regEntry.RegistrationData()

	hostinfo := &tailcfg.Hostinfo{}
	if regData.Hostinfo != nil {
		hostinfo = regData.Hostinfo.Clone()
	}

	hostinfo.Hostname = regData.Hostname

	req := tailcfg.RegisterRequest{
		NodeKey:  regData.NodeKey,
		Hostinfo: hostinfo,
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: authKey},
	}
	if regData.Expiry != nil {
		req.Expiry = *regData.Expiry
	}

	node, nodeChange, err := s.HandleNodeFromPreAuthKey(req, regData.MachineKey)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	regEntry.FinishAuth(types.AuthVerdict{Node: node})
	s.authCache.Remove(authID)

	return node, nodeChange, nil
}
