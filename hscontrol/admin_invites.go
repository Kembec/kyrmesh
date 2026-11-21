package hscontrol

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// The console works on invitations only. An invitation is a single-use
// pre-auth key (invite.go): creating one here is `headscale invites create
// --user`, and revoking one is `headscale preauthkeys expire`, so a revoked
// invitation is refused exactly as one expired from the CLI.

// adminExpiries are the lives the form offers, first the CLI's default.
var adminExpiries = []struct {
	choice templates.AdminChoice
	life   time.Duration
}{
	{templates.AdminChoice{Value: "24h", Label: "1 día"}, 24 * time.Hour},
	{templates.AdminChoice{Value: "1h", Label: "1 hora"}, time.Hour},
	{templates.AdminChoice{Value: "168h", Label: "7 días"}, 7 * 24 * time.Hour},
}

// page serves GET /admin.
func (a *adminConsole) page(w http.ResponseWriter, _ *http.Request, _ string, s adminSession) {
	a.render(w, http.StatusOK, s, "")
}

// create serves POST /admin/invites: a single-use key for the chosen user,
// kept in the session so the console can offer to send it.
func (a *adminConsole) create(w http.ResponseWriter, req *http.Request, id string, s adminSession) {
	userID, err := strconv.ParseUint(req.PostFormValue("user"), 10, 64) //nolint:gosec // bounded by posted
	if err != nil || userID == 0 {
		a.render(w, http.StatusBadRequest, s, templates.AdminNoticeBadUser)

		return
	}

	user, err := a.h.state.GetUserByID(types.UserID(userID))
	if err != nil {
		a.render(w, http.StatusBadRequest, s, templates.AdminNoticeBadUser)

		return
	}

	life, ok := adminExpiry(req.PostFormValue("expires")) //nolint:gosec // bounded by posted
	if !ok {
		a.render(w, http.StatusBadRequest, s, templates.AdminNoticeBadExpiry)

		return
	}

	expires := time.Now().Add(life)

	pak, err := a.h.state.CreatePreAuthKey(user.TypedID(), false, false, &expires, nil)
	if err != nil {
		log.Error().Err(err).Msg("admin: creating invitation")
		renderAdmin(w, http.StatusInternalServerError, templates.AdminDenied(templates.AdminFailed))

		return
	}

	share := &templates.AdminShareInfo{
		Link:    types.InviteURL(a.serverURL, pak.Key),
		Owner:   user.Display(),
		Expires: expires,
	}
	a.update(id, func(s *adminSession) { s.last, s.lastID = share, pak.ID })

	log.Info().Uint64("pre_auth_key_id", pak.ID).Msg("admin: invitation created")
	http.Redirect(w, req, adminPath, http.StatusSeeOther)
}

// revoke serves POST /admin/invites/{id}/revoke: it expires a pending
// invitation's key.
func (a *adminConsole) revoke(w http.ResponseWriter, req *http.Request, id string, s adminSession) {
	keyID, err := strconv.ParseUint(chi.URLParam(req, "id"), 10, 64)
	if err != nil {
		a.render(w, http.StatusNotFound, s, templates.AdminNoticeGone)

		return
	}

	pending, err := a.pending()
	if err != nil {
		log.Error().Err(err).Msg("admin: listing invitations")
		renderAdmin(w, http.StatusInternalServerError, templates.AdminDenied(templates.AdminFailed))

		return
	}

	if !slices.ContainsFunc(pending, func(k types.PreAuthKey) bool { return k.ID == keyID }) {
		a.render(w, http.StatusNotFound, s, templates.AdminNoticeGone)

		return
	}

	if err := a.h.state.ExpirePreAuthKey(keyID); err != nil { //nolint:noinlineerr
		log.Error().Err(err).Msg("admin: revoking invitation")
		renderAdmin(w, http.StatusInternalServerError, templates.AdminDenied(templates.AdminFailed))

		return
	}

	a.update(id, func(s *adminSession) {
		if s.lastID == keyID {
			s.last, s.lastID = nil, 0
		}
	})

	log.Info().Uint64("pre_auth_key_id", keyID).Msg("admin: invitation revoked")
	http.Redirect(w, req, adminPath, http.StatusSeeOther)
}

func (a *adminConsole) render(w http.ResponseWriter, code int, s adminSession, notice string) {
	info, err := a.pageInfo(s)
	if err != nil {
		log.Error().Err(err).Msg("admin: reading invitations")
		renderAdmin(w, http.StatusInternalServerError, templates.AdminDenied(templates.AdminFailed))

		return
	}

	info.Notice = notice
	renderAdmin(w, code, templates.AdminPage(info))
}

func (a *adminConsole) pageInfo(s adminSession) (templates.AdminPageInfo, error) {
	users, err := a.h.state.ListAllUsers()
	if err != nil {
		return templates.AdminPageInfo{}, err
	}

	pending, err := a.pending()
	if err != nil {
		return templates.AdminPageInfo{}, err
	}

	info := templates.AdminPageInfo{
		CSRFField:    adminCSRFField,
		CSRFToken:    s.csrf,
		CreateAction: adminPath + "/invites",
		LogoutAction: adminPath + "/logout",
	}

	for _, u := range users {
		info.Users = append(info.Users, templates.AdminChoice{Value: strconv.FormatUint(uint64(u.ID), 10), Label: u.Display()})
	}

	for _, e := range adminExpiries {
		info.Expiries = append(info.Expiries, e.choice)
	}

	for _, k := range pending {
		info.Pending = append(info.Pending, templates.AdminPendingInfo{
			Owner:        inviteOwner(&k),
			Expires:      k.Expiration,
			RevokeAction: adminPath + "/invites/" + strconv.FormatUint(k.ID, 10) + "/revoke",
		})

		// The link just made is offered while it can still be used.
		if s.last != nil && k.ID == s.lastID {
			info.Share = s.last
		}
	}

	return info, nil
}

// pending lists the keys an invitation link can still use (the ones
// inviteFlow.check accepts), newest first.
func (a *adminConsole) pending() ([]types.PreAuthKey, error) {
	keys, err := a.h.state.ListPreAuthKeys()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	keys = slices.DeleteFunc(keys, func(k types.PreAuthKey) bool {
		return k.Reusable || k.Used || (k.Expiration != nil && !k.Expiration.After(now))
	})

	slices.SortFunc(keys, func(x, y types.PreAuthKey) int {
		if x.CreatedAt == nil || y.CreatedAt == nil {
			return cmp.Compare(y.ID, x.ID)
		}

		return y.CreatedAt.Compare(*x.CreatedAt)
	})

	return keys, nil
}

func adminExpiry(value string) (time.Duration, bool) {
	for _, e := range adminExpiries {
		if e.choice.Value == value {
			return e.life, true
		}
	}

	return 0, false
}
