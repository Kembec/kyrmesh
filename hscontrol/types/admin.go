package types

import (
	"net/url"
	"strings"
	"time"
)

// AdminLinkLife is how long an admin link stays valid before it is opened.
// The link carries an API key created with exactly this life; the console
// accepts only keys that short-lived, so a long-lived key made for a REST
// client is neither accepted nor burned by it (KEM-464).
const AdminLinkLife = 10 * time.Minute

// AdminLoginPath is where an admin link lands.
const AdminLoginPath = "/admin/login"

// AdminLinkURL is the single-use link that opens the admin console in a
// browser. Like an invitation, the key travels in the query string, which
// the request log does not record.
func AdminLinkURL(serverURL, apiKey string) string {
	return strings.TrimSuffix(serverURL, "/") + AdminLoginPath + "?" + InviteCodeParam + "=" + url.QueryEscape(apiKey)
}
