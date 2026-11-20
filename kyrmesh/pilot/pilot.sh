#!/usr/bin/env bash
# Kyrmesh Core pilot on Headscale: allowed access, default deny and revocation
# between real tailscaled devices, isolated from the host's own network.
#
#   kyrmesh/pilot/pilot.sh all     up + test + down, exit 1 if any scenario fails
#   kyrmesh/pilot/pilot.sh up      start Headscale, the resource and the devices
#   kyrmesh/pilot/pilot.sh test    run the scenarios against a running pilot
#   kyrmesh/pilot/pilot.sh down    rollback: stop everything and delete the run directory
#
# Binaries: HEADSCALE_BIN (default: built from this checkout), TAILSCALE_BIN and
# TAILSCALED_BIN (default: from PATH). Paths: KYRMESH_RUN, KYRMESH_RESULTS.
set -euo pipefail

# shellcheck source=kyrmesh/pilot/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=kyrmesh/pilot/scenarios.sh
. "$PILOT_DIR/scenarios.sh"
# shellcheck source=kyrmesh/pilot/host.sh
. "$PILOT_DIR/host.sh"

PORTS="$HS_PORT $HS_METRICS_PORT $HS_GRPC_PORT $RESOURCE_PORT $OUTSIDE_PORT 11080 11081 11082 11083 11084"

resolve_bins() {
  need curl python3
  TAILSCALE_BIN="${TAILSCALE_BIN:-$(command -v tailscale || true)}"
  TAILSCALED_BIN="${TAILSCALED_BIN:-$(command -v tailscaled || true)}"
  [[ -x "$TAILSCALE_BIN" && -x "$TAILSCALED_BIN" ]] || die "set TAILSCALE_BIN and TAILSCALED_BIN (tailscale >= 1.80)"
  if [[ -z "${HEADSCALE_BIN:-}" ]]; then
    need go
    HEADSCALE_BIN="$RUN/bin/headscale"
    [[ -x "$HEADSCALE_BIN" ]] || (cd "$PILOT_DIR/../.." && go build -o "$HEADSCALE_BIN" ./cmd/headscale)
  fi
}

ensure_user() { # creating can time out on a loaded host after it succeeded: look before and after
  hs users list -o json | json "[u['name'] for u in d]" | grep -q "\"$1\"" && return 0
  hs users create "$1" >/dev/null 2>&1 || true
  hs users list -o json | json "[u['name'] for u in d]" | grep -q "\"$1\"" || die "could not create user $1"
}

start_resource() {
  mkdir -p "$RUN/www/allowed" "$RUN/www/outside"
  printf 'kyrmesh-%s\n' "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" >"$RUN/www/allowed/marker"
  cp "$RUN/www/allowed/marker" "$RUN/www/outside/marker"
  start_bg "$RUN/www/allowed.pid" "$RUN/www/allowed.log" \
    python3 -m http.server "$RESOURCE_PORT" --bind 127.0.0.1 --directory "$RUN/www/allowed"
  start_bg "$RUN/www/outside.pid" "$RUN/www/outside.log" \
    python3 -m http.server "$OUTSIDE_PORT" --bind 127.0.0.1 --directory "$RUN/www/outside"
  wait_for "$WAIT_S" curl -sf "http://127.0.0.1:$RESOURCE_PORT/marker" || die "resource service did not start"
  wait_for "$WAIT_S" curl -sf "http://127.0.0.1:$OUTSIDE_PORT/marker" || die "outside service did not start"
}

OWNS_RUN=no # set once this invocation created $RUN: only then may the exit trap tear it down

cmd_up() {
  local p dev key t0
  [[ ! -e "$RUN" ]] || die "$RUN exists: run '$0 down' first"
  for p in $PORTS; do port_free "$p" || die "port $p is in use"; done
  resolve_bins
  mkdir -p "$RUN/hs" "$RUN/nodes" "$RUN/keys" "$RESULTS"
  OWNS_RUN=yes
  chmod 700 "$RUN" "$RUN/keys"
  : >"$RUN/.kyrmesh-pilot" # down deletes only a directory that carries this mark
  host_snapshot >"$RESULTS/host-before.txt"
  sed -e "s|@RUN@|$RUN|g" -e "s|@HS_PORT@|$HS_PORT|g" -e "s|@HS_METRICS_PORT@|$HS_METRICS_PORT|g" \
    -e "s|@HS_GRPC_PORT@|$HS_GRPC_PORT|g" "$PILOT_DIR/headscale.tmpl.yaml" >"$RUN/hs/config.yaml"
  cp "$PILOT_DIR/policy.json" "$PILOT_DIR/derp-norelay.yaml" "$RUN/hs/"

  log "headscale $("$HEADSCALE_BIN" version 2>/dev/null | head -n1), tailscale $("$TAILSCALE_BIN" version 2>/dev/null | head -n1)"
  start_bg "$RUN/hs/pid" "$RUN/hs/serve.log" "$HEADSCALE_BIN" -c "$RUN/hs/config.yaml" serve
  wait_for "$WAIT_S" hs users list || die "headscale did not start (see $RUN/hs/serve.log)"
  for dev in svc alice bob mallory; do ensure_user "$dev"; done

  start_resource
  for dev in $DEVICES; do start_device "$dev"; done
  for dev in resource laptop phone outsider; do
    key=$(new_key "$(owner_of "$dev")" --expiration 10m) || die "no valid pre-auth key for $dev"
    mv "$key" "$RUN/keys/$dev"
    # `up` can stop waiting after the server already registered the device:
    # look at the device before calling it a failure.
    join "$dev" "$RUN/keys/$dev" >"$RUN/nodes/$dev/join.log" 2>&1 \
      || wait_for "$WAIT_S" device_running "$dev" \
      || die "$dev could not join (see $RUN/nodes/$dev/join.log and tailscaled.log)"
  done
  for dev in laptop phone; do
    # shellcheck disable=SC2016 # expanded by the inner bash
    wait_for "$WAIT_S" bash -c '"$@" status --json | grep -q "\"$0\""' "$(ts_ip resource)" \
      "$TAILSCALE_BIN" --socket="$RUN/nodes/$dev/ts.sock" || die "$dev never saw the resource"
  done
  # The first WireGuard handshake can take seconds on a loaded host: open each
  # client's session before testing, and keep how long it took.
  for dev in laptop phone; do
    t0=$(date +%s)
    wait_for "$WAIT_S" tsmp_pong "$dev" "$(ts_ip resource)" || die "$dev has no WireGuard session with the resource"
    echo "$(( $(date +%s) - t0 ))s" >"$RUN/nodes/$dev/warmup"
  done
  log "pilot up in $RUN"
}

cmd_test() {
  local policy_out policy_ok
  resolve_bins
  [[ -S "$RUN/hs/headscale.sock" ]] || die "pilot is not up"
  mkdir -p "$RESULTS"
  {
    printf '# Kyrmesh pilot results\n\n'
    printf -- '- run: %s UTC\n- headscale: %s\n- tailscale: %s\n- host: %s\n\n' \
      "$(date -u +%FT%TZ)" "$("$HEADSCALE_BIN" version 2>/dev/null | head -n1)" \
      "$("$TAILSCALE_BIN" version 2>/dev/null | head -n1)" "$(uname -sm)"
    printf '| Scenario | Result | Observed |\n|---|---|---|\n'
  } >"$RESULTS/results.md"

  policy_out=$(hs policy check -f "$RUN/hs/policy.json" 2>&1) && policy_ok=yes || policy_ok=no
  verdict "S0 policy tests (headscale policy check)" "${policy_out:0:90}" test "$policy_ok" = yes
  scenario_allow
  scenario_encryption
  scenario_deny_port
  scenario_deny_device
  scenario_unauthorized
  scenario_revoke
  host_snapshot >"$RESULTS/host-during.txt"
  verdict "S4 host network unchanged while the pilot runs" "$(host_diff host-before.txt host-during.txt)" \
    host_same host-before.txt host-during.txt
}

cmd_down() {
  local f leftover
  [[ -d "$RUN" ]] || { log "nothing to roll back in $RUN"; return 0; }
  [[ -f "$RUN/.kyrmesh-pilot" ]] || die "$RUN was not created by this pilot: not touching it"
  for f in "$RUN"/nodes/*/pid "$RUN"/www/*.pid "$RUN"/hs/pid; do stop_pidfile "$f"; done
  leftover=$(pgrep -f "$RUN" || true)
  [[ -z "$leftover" ]] || die "processes still running from $RUN: $leftover"
  rm -rf "$RUN"
  mkdir -p "$RESULTS"
  host_snapshot >"$RESULTS/host-after.txt"
  log "rolled back: no pilot process, run directory and keys deleted"
}

cmd_all() {
  local p busy=""
  # A failed `up` of this run still rolls back, but a pilot that was already up
  # (and made `up` die) is not ours: the trap does nothing then.
  trap '[[ $OWNS_RUN == yes ]] && cmd_down' EXIT
  cmd_up
  cmd_test || true
  cmd_down
  OWNS_RUN=no
  for p in $PORTS; do port_free "$p" || busy="$busy $p"; done
  verdict "S5 rollback leaves no process, port or state" "ports still busy:${busy:- none}; $RUN removed: $([[ -e $RUN ]] && echo no || echo yes)" \
    test -z "$busy" -a ! -e "$RUN"
  verdict "S4 host network unchanged after rollback" "$(host_diff host-before.txt host-after.txt)" \
    host_same host-before.txt host-after.txt
  printf '\n%s scenario(s) failed. Report: %s/results.md\n' "$FAILS" "$RESULTS" >&2
  (( FAILS == 0 ))
}

case "${1:-}" in
  up) cmd_up ;;
  test) cmd_test ;;
  down) cmd_down ;;
  all) cmd_all ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
