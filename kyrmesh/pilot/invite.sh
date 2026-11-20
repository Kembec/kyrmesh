# shellcheck shell=bash
# S6: a person joins a device from an invitation link, with no terminal (KEM-456).
#
# The device is a real tailscaled: `tailscale up` without a key is what the
# app's "Log in" button does, and it prints the login URL the app would open.
# curl stands in for the person's browser: one cookie jar, the pages and their
# single form. No key is ever typed into the device, and none is printed.

HS_URL="http://127.0.0.1:$HS_PORT"

# invite <user> <expiration> <file>: writes {"id","url"} of a new invitation to a 0600 file.
invite() {
  : >"$3"; chmod 600 "$3"
  hs invites create --user "$(user_id "$1")" --expiration "$2" -o json >"$3" 2>/dev/null
  [[ "$(json "d['url']" <"$3")" == "$HS_URL/join?code=hskey-auth-"* ]]
}
invite_field() { json "d['$2']" <"$1"; }

# browser <jar> <page> <curl args...>: one request as the person's browser; prints "<status> <redirect>".
browser() {
  local jar="$1" page="$2"; shift 2
  curl --silent --max-time 10 --cookie "$jar" --cookie-jar "$jar" --output "$page" \
    --write-out '%{http_code} %{redirect_url}' "$@"
}
page_marker() { sed -n 's/.*data-kyrmesh="\([a-z-]*\)".*/\1/p' "$1" | head -n1; }
page_csrf() {
  python3 -c 'import re,sys; m=re.search(r"<input[^>]*name=\"kyrmesh_invite_csrf\"[^>]*>", open(sys.argv[1]).read()); v=m and re.search(r"value=\"([^\"]*)\"", m.group(0)); print(v.group(1) if v else "")' "$1"
}

# keep_page <page> <name>: keeps what the person saw, as the browsable demo, with the form token blanked.
keep_page() {
  mkdir -p "$RESULTS/pages"
  sed 's/\(name="kyrmesh_invite_csrf"[^>]*value="\)[^"]*"/\1(token)"/; s/\(value="\)[^"]*\("[^>]*name="kyrmesh_invite_csrf"\)/\1(token)\2/' "$1" >"$RESULTS/pages/$2.html"
}

auth_url() { ts "$1" status --json 2>/dev/null | json "d.get('AuthURL','')" 2>/dev/null; }
has_auth_url() { [[ "$(auth_url "$1")" == "$HS_URL/register/"* ]]; }

# tap_login <device>: start a key-less `tailscale up`, as the app's Log in, and print its login URL.
tap_login() {
  start_bg "$RUN/nodes/$1/up.pid" "$RUN/nodes/$1/up.log" "$TAILSCALE_BIN" --socket="$RUN/nodes/$1/ts.sock" \
    up --reset --login-server="$HS_URL" --hostname="$1" --accept-dns=false --accept-routes=false --timeout="${WAIT_S}s"
  wait_for 60 has_auth_url "$1" && auth_url "$1"
}

status_says() { browser "$1" "$RUN/keys/status.html" "$HS_URL/join/status/$2" >/dev/null; [[ "$(page_marker "$RUN/keys/status.html")" == "$3" ]]; }
node_owner() { hs nodes list -o json | json "[(n.get('user') or {}).get('name','') for n in d if n.get('name')=='$1'][0]" 2>/dev/null; }
node_known() { hs nodes list -o json | json "str(any(n.get('name')=='$1' for n in d))"; }

scenario_invite() {
  local jar="$RUN/keys/jar-tablet" page="$RUN/keys/page.html" inv="$RUN/keys/invite-tablet.json"
  local link url id r1 r2 r3 r4 csrf ip got

  start_device tablet
  if ! invite bob 10m "$inv"; then
    record "S6 invite: new device joins from the link, no terminal" FAIL "headscale invites create gave no link"
    return
  fi
  link=$(invite_field "$inv" url)
  : >"$jar"; chmod 600 "$jar"

  r1=$(browser "$jar" "$page" "$link")                                  # opens the link
  r2=$(browser "$jar" "$page" "$HS_URL/join"); local m2; m2=$(page_marker "$page"); keep_page "$page" 1-steps
  url=$(tap_login tablet) || url=""
  id="${url##*/register/}"
  r3=$(browser "$jar" "$page" "$url"); local m3; m3=$(page_marker "$page"); keep_page "$page" 2-confirm
  csrf=$(page_csrf "$page")
  r4=$(browser "$jar" "$page" --data-urlencode "kyrmesh_invite_csrf=$csrf" "$HS_URL/join/register/$id")
  wait_for "$WAIT_S" device_running tablet
  wait_for 30 status_says "$jar" "$id" connected
  keep_page "$RUN/keys/status.html" 3-connected
  verdict "S6 invite: new device joins from the link, no terminal" \
    "link ${r1%% *}→/join, steps page: $m2, login page: $m3, confirm ${r4%% *}→status; tablet $(backend_state tablet), status page: $(page_marker "$RUN/keys/status.html")" \
    test "$r1" = "303 $HS_URL/join" -a "$m2" = invite-steps -a "$m3" = invite-confirm \
      -a "$r4" = "303 $HS_URL/join/status/$id" -a "$(backend_state tablet)" = Running \
      -a "$(page_marker "$RUN/keys/status.html")" = connected

  ip=$(ts_ip resource)
  # A new device's first WireGuard session takes 15-60 s on this host (S1);
  # judge the grant once it is open, not on the first try.
  local t0 opened; t0=$(date +%s)
  wait_for "$WAIT_S" fetch_quiet tablet "$ip" "$RESOURCE_PORT" /marker && opened="$(( $(date +%s) - t0 ))s" || opened=never
  got=$(fetch tablet "$ip" "$RESOURCE_PORT" /marker 2>/dev/null || true)
  local outside=refused; fetch_quiet tablet "$ip" "$OUTSIDE_PORT" /marker && outside=reached
  verdict "S6 invite: device gets only what its user's policy allows" \
    "owner $(node_owner tablet); resource:$RESOURCE_PORT $([[ $got == "$(marker)" ]] && echo fetched || echo refused) (first session after $opened); resource:$OUTSIDE_PORT $outside" \
    test "$(node_owner tablet)" = bob -a "$got" = "$(marker)" -a "$outside" = refused

  stop_pidfile "$RUN/nodes/tablet/up.pid"
  scenario_invite_refused "$link"
}

# The same link a second time, an expired one and one revoked after the
# person opened it: each is refused, and the device behind the last never joins.
scenario_invite_refused() {
  local reused="$1" jar="$RUN/keys/jar-other" page="$RUN/keys/page-other.html" inv="$RUN/keys/invite-other.json"
  local r m url

  : >"$jar"; chmod 600 "$jar"
  r=$(browser "$jar" "$page" "$reused"); m=$(page_marker "$page")
  keep_page "$page" 4-used
  verdict "S6 invite: reused link refused" "${r%% *}, page: $m" test "${r%% *}" = 403 -a "$m" = invite-used

  invite bob 1s "$inv" || true
  sleep 2
  : >"$jar"
  r=$(browser "$jar" "$page" "$(invite_field "$inv" url)"); m=$(page_marker "$page")
  keep_page "$page" 5-expired
  verdict "S6 invite: expired link refused" "${r%% *}, page: $m" test "${r%% *}" = 403 -a "$m" = invite-expired

  start_device late
  invite bob 10m "$inv" || true
  : >"$jar"
  r=$(browser "$jar" "$page" "$(invite_field "$inv" url)")
  url=$(tap_login late) || url=""
  hs preauthkeys expire --id "$(invite_field "$inv" id)" >/dev/null
  r=$(browser "$jar" "$page" "$url"); m=$(page_marker "$page")
  sleep 3
  verdict "S6 invite: revoked after opening, refused and its device never joins" \
    "login page ${r%% *}: $m; late $(backend_state late), in headscale: $(node_known late)" \
    test "${r%% *}" = 403 -a "$m" = invite-expired -a "$(backend_state late)" != Running -a "$(node_known late)" = False
  stop_pidfile "$RUN/nodes/late/up.pid"
}
