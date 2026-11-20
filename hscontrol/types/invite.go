package types

import (
	"net/url"
	"strings"
)

// InviteCodeParam is the query parameter of an invitation link that carries
// its pre-auth key (KEM-456).
const InviteCodeParam = "code"

// InviteURL is the link an administrator hands out so a person can join a
// device with a single-use pre-auth key and no terminal. The key goes in the
// query string, which the request log does not record.
func InviteURL(serverURL, key string) string {
	return strings.TrimSuffix(serverURL, "/") + "/join?" + InviteCodeParam + "=" + url.QueryEscape(key)
}
