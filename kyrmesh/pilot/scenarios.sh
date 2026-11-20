# shellcheck shell=bash
# Kyrmesh pilot scenarios. Each one records PASS or FAIL with what was
# observed; none prints a pre-auth key or a private key.

RESULTS="${KYRMESH_RESULTS:-$RUN-results}"
FAILS=0

record() { # record <scenario> <PASS|FAIL> <observed>
  [[ "$2" == PASS ]] || FAILS=$((FAILS + 1))
  printf '| %s | %s | %s |\n' "$1" "$2" "$3" >>"$RESULTS/results.md"
  log "$1: $2 — $3"
}

verdict() { # verdict <scenario> <observed> <command...>: PASS if the command succeeds
  local id="$1" observed="$2"; shift 2
  if "$@"; then record "$id" PASS "$observed"; else record "$id" FAIL "$observed"; fi
}

marker() { cat "$RUN/www/allowed/marker"; }
fetch_quiet() { fetch "$@" >/dev/null 2>&1; }

# Peer facts as seen by <device> for <peer ip>: "curaddr|relay|lasthandshake|publickey".
peer_facts() {
  ts "$1" status --json | json "next((p.get('CurAddr','')+'|'+p.get('Relay','')+'|'+p.get('LastHandshake','')+'|'+p.get('PublicKey','') for p in (d.get('Peer') or {}).values() if '$2' in p.get('TailscaleIPs',[])), 'absent')"
}

scenario_allow() {
  local dev body ip
  ip=$(ts_ip resource)
  for dev in laptop phone; do
    body=$(fetch "$dev" "$ip" "$RESOURCE_PORT" /marker 2>&1) || body="error: $body"
    verdict "S1 allow $dev -> resource:$RESOURCE_PORT" \
      "got '${body:0:60}'; first WireGuard session took $(cat "$RUN/nodes/$dev/warmup" 2>/dev/null || echo ?)" \
      test "$body" = "$(marker)"
  done
}

# End-to-end encryption: a WireGuard session (TSMP pong and a handshake) on a
# direct path (the pilot has no reachable relay), keyed to the public key
# Headscale registered for the resource.
# direct_session <device> <peer ip>: a WireGuard pong and a confirmed direct
# address at the same time. Magicsock drops the confirmed address when it goes
# stale and sprays the candidates until a pong confirms one again.
direct_session() { tsmp_pong "$1" "$2" && [[ "$(peer_facts "$1" "$2")" != '|'* ]]; }

scenario_encryption() {
  local dev ip facts curaddr relay handshake pubkey hs_key tsmp
  ip=$(ts_ip resource)
  hs_key=$(node_field resource node_key)
  for dev in laptop phone; do
    tsmp=no
    wait_for "$WAIT_S" direct_session "$dev" "$ip" && tsmp=yes
    facts=$(peer_facts "$dev" "$ip")
    IFS='|' read -r curaddr relay handshake pubkey <<<"$facts"
    verdict "S1 e2e $dev <-> resource" \
      "WireGuard pong $tsmp, handshake ${handshake:-none}, direct path ${curaddr:-none}, relay ${relay:-none} unused, peer key ${pubkey:0:16}… = headscale ${hs_key:0:16}…" \
      bash -c '[[ $1 == yes && -n "$2" && "$3" != 0001-01-01T00:00:00Z && -n "$3" && "$4" == "$5" ]]' _ \
      "$tsmp" "$curaddr" "$handshake" "$pubkey" "$hs_key"
  done
}

scenario_deny_port() {
  local ip local_ok=no
  ip=$(ts_ip resource)
  wait_for 30 curl --silent --fail --max-time 5 "http://127.0.0.1:$OUTSIDE_PORT/marker" && local_ok=yes
  # A refusal only counts if laptop is up and does reach the allowed port.
  if ! device_running laptop || ! fetch_quiet laptop "$ip" "$RESOURCE_PORT" /marker; then
    record "S2 deny resource:$OUTSIDE_PORT (outside policy)" FAIL "laptop $(backend_state laptop) or cannot reach allowed port $RESOURCE_PORT: the refusal proves nothing"
    return
  fi
  if fetch laptop "$ip" "$OUTSIDE_PORT" /marker >/dev/null 2>&1; then
    record "S2 deny resource:$OUTSIDE_PORT (outside policy)" FAIL "laptop reached it"
  else
    verdict "S2 deny resource:$OUTSIDE_PORT (outside policy)" \
      "laptop refused; same service answers locally: $local_ok" test "$local_ok" = yes
  fi
}

scenario_deny_device() {
  local ip seen
  ip=$(ts_ip resource)
  if ! device_running outsider; then
    record "S2 deny outsider (registered, no grant)" FAIL "outsider is $(backend_state outsider), not Running: the refusal proves nothing"
    return
  fi
  seen=$(peer_facts outsider "$ip")
  if fetch outsider "$ip" "$RESOURCE_PORT" /marker >/dev/null 2>&1; then
    record "S2 deny outsider (registered, no grant)" FAIL "outsider reached resource"
  else
    record "S2 deny outsider (registered, no grant)" PASS "refused; resource in its netmap: $([[ $seen == absent ]] && echo no || echo yes)"
  fi
}

# One attempt per fresh intruder: tailscaled keeps retrying a failed login in
# the background, so a reused daemon could answer with the previous key's error.
# The old state stays inside the run directory, which `down` deletes.
fresh_intruder() {
  stop_pidfile "$RUN/nodes/intruder/pid"
  mv "$RUN/nodes/intruder" "$RUN/nodes/intruder.$(date +%s).$$.$RANDOM"
  start_device intruder
}

# attempt <scenario> <expected rejection> <command...>: the device must not
# reach Running, and the reason must be the one under test.
attempt() {
  local id="$1" reason="$2" out state
  shift 2
  fresh_intruder
  if out=$("$@" 2>&1); then record "$id" FAIL "joined"; return; fi
  state=$(backend_state intruder)
  verdict "$id" "rejected: '$(printf '%s' "$out" | grep -o "$reason.\{0,40\}" | head -n1)'; state $state" \
    bash -c '[[ "$1" != Running && "$2" == *"$3"* ]]' _ "$state" "$out" "$reason"
}

# A device without a valid key never joins: forged key, expired key, no key.
scenario_unauthorized() {
  local real forged expired
  # Well formed and naming a real, unused key, with a different secret: the
  # rejection has to come from the secret check, not from the format.
  real=$(new_key alice --expiration 10m) || { record "S2 intruder keys" FAIL "no valid hskey-auth- key could be created"; return; }
  forged="$RUN/keys/forged"
  printf '%s%s\n' "$(head -c 24 "$real")" "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')" >"$forged"
  chmod 600 "$forged"
  rm -f "$real"
  attempt "S2 intruder with forged key" "invalid auth key" join intruder "$forged"

  expired=$(new_key alice --expiration 1s) || { record "S2 intruder with expired key" FAIL "no valid hskey-auth- key could be created"; return; }
  sleep 3
  attempt "S2 intruder with expired key" "expired" join intruder "$expired"

  attempt "S2 intruder without key" "/register/" ts intruder up --reset \
    --login-server="http://127.0.0.1:$HS_PORT" --hostname=intruder --accept-dns=false --timeout=10s
  verdict "S2 intruder absent from headscale" "nodes: $(hs nodes list -o json | json "sorted(n['given_name'] for n in d)")" \
    bash -c 'hs_out=$("$@") && [[ "$hs_out" != *intruder* ]]' _ "$HEADSCALE_BIN" -c "$RUN/hs/config.yaml" nodes list
}

# peer_state <device> <peer ip>: absent, expired or present in the device's netmap.
peer_state() {
  ts "$1" status --json | json "next(('expired' if p.get('Expired') else 'present' for p in (d.get('Peer') or {}).values() if '$2' in p.get('TailscaleIPs',[])), 'absent')"
}

phone_daemon_alive() { local pid; pid=$(cat "$RUN/nodes/phone/pid" 2>/dev/null) && [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; }

# A dead daemon is not a revocation: the phone must still answer, and not as Running.
phone_gone() { # the phone is logged out and the resource no longer trusts it as a peer
  phone_daemon_alive && [[ "$(backend_state phone)" != Running && "$(backend_state phone)" != NoDaemon \
    && "$(peer_state resource "$1")" != present ]]
}

# Revoking the phone cuts its access within seconds, leaves the laptop alone,
# and the phone cannot come back with the key it used before.
scenario_revoke() {
  local ip phone_ip id t0 cut=none kept=no out
  ip=$(ts_ip resource)
  phone_ip=$(ts_ip phone)
  id=$(node_field phone id)
  hs nodes expire --identifier "$id" >/dev/null
  t0=$(date +%s)
  wait_for 30 phone_gone "$phone_ip" && cut="$(( $(date +%s) - t0 ))s"
  if ! phone_daemon_alive; then cut="none (phone tailscaled died: not a revocation)"; fi
  if fetch_quiet phone "$ip" "$RESOURCE_PORT" /marker; then cut="none (phone still fetches)"; fi
  verdict "S3 revoke phone cuts its access" \
    "after $cut: phone $(backend_state phone), phone in resource's netmap: $(peer_state resource "$phone_ip"); phone fetch refused" \
    test "${cut%s}" != "$cut"

  t0=$(date +%s)
  if fetch_quiet laptop "$ip" "$RESOURCE_PORT" /marker; then
    kept="yes, first try"
  elif wait_for 30 fetch_quiet laptop "$ip" "$RESOURCE_PORT" /marker; then
    kept="yes, after $(( $(date +%s) - t0 ))s"
  fi
  verdict "S3 laptop keeps access after phone revocation" "laptop fetched the marker: $kept" test "$kept" != no

  hs nodes delete --identifier "$id" --force >/dev/null
  out=$(ts phone up --reset --login-server="http://127.0.0.1:$HS_PORT" --auth-key="file:$RUN/keys/phone" \
    --hostname=phone --accept-dns=false --force-reauth --timeout=20s 2>&1) \
    && { record "S3 phone rejoins with its used key" FAIL "rejoined"; return; }
  if fetch_quiet phone "$ip" "$RESOURCE_PORT" /marker; then
    record "S3 phone rejoins with its used key" FAIL "rejected but still reaches resource"
  else
    verdict "S3 phone rejoins with its used key" \
      "rejected: '$(printf '%s' "$out" | grep -o 'already used.\{0,20\}' | head -n1)'; no access" \
      bash -c '[[ "$1" == *"already used"* ]]' _ "$out"
  fi
}
