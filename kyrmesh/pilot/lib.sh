# shellcheck shell=bash
# Kyrmesh pilot helpers: one Headscale and several tailscaled "devices", all
# unprivileged. Each device is a tailscaled in userspace-networking mode with
# its own state, socket and SOCKS5 port: no TUN, no routes and no DNS change
# on the host, so an existing Tailscale install keeps running untouched.

PILOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="${KYRMESH_RUN:-${TMPDIR:-/tmp}/kyrmesh-pilot}"
RUN="${RUN%/}"

HS_PORT="${HS_PORT:-18080}"
HS_METRICS_PORT="${HS_METRICS_PORT:-19090}"
HS_GRPC_PORT="${HS_GRPC_PORT:-50444}"
RESOURCE_PORT=28080      # the only port the policy grants
OUTSIDE_PORT=28081       # served on the same device, outside the policy
WAIT_S="${KYRMESH_WAIT_S:-60}"

# Each device: its owner (Headscale user; none for the intruder) and SOCKS5 port.
DEVICES="resource laptop phone outsider intruder"
owner_of() {
  case "$1" in resource) echo svc ;; laptop) echo alice ;; phone) echo bob ;; outsider) echo mallory ;; *) echo "" ;; esac
}
socks_of() {
  case "$1" in resource) echo 11080 ;; laptop) echo 11081 ;; phone) echo 11082 ;; outsider) echo 11083 ;; intruder) echo 11084 ;; esac
}

die() { printf 'pilot: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

need() {
  local bin
  for bin in "$@"; do command -v "$bin" >/dev/null 2>&1 || die "missing $bin in PATH"; done
}

hs() { "$HEADSCALE_BIN" -c "$RUN/hs/config.yaml" "$@"; }
ts() { local dev="$1"; shift; "$TAILSCALE_BIN" --socket="$RUN/nodes/$dev/ts.sock" "$@"; }

# json <python expression over `d`> reads JSON on stdin; Headscale prints
# `null` for an empty list, so `d` is [] then.
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); d=[] if d is None else d; r=eval(sys.argv[1]); print(r if isinstance(r,str) else json.dumps(r))' "$1"; }

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

wait_for() { # wait_for <seconds> <command...>
  local limit="$1" t0; shift
  t0=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    (( $(date +%s) - t0 >= limit )) && return 1
    sleep 0.5
  done
}

start_bg() { # start_bg <pidfile> <logfile> <command...>
  local pidfile="$1" logfile="$2"; shift 2
  nohup "$@" >"$logfile" 2>&1 &
  echo $! >"$pidfile"
  disown $! # stopped by stop_pidfile; the shell need not report it
}

stop_pidfile() {
  local pidfile="$1" pid
  [[ -f "$pidfile" ]] || return 0
  pid=$(cat "$pidfile")
  kill "$pid" 2>/dev/null || true
  wait_for 10 bash -c "! kill -0 $pid" || kill -9 "$pid" 2>/dev/null || true
  rm -f "$pidfile"
}

user_id() { hs users list -o json | json "[u['id'] for u in d if u['name']=='$1'][0]"; }
node_field() { # node_field <hostname> <field>
  hs nodes list -o json | json "[n.get('$2') for n in d if n.get('given_name')=='$1' or n.get('name')=='$1'][0]"
}
ts_ip() { ts "$1" ip -4 2>/dev/null | head -n1; }
backend_state() { ts "$1" status --json 2>/dev/null | json "d.get('BackendState','')" 2>/dev/null || echo NoDaemon; }
device_running() { [[ "$(backend_state "$1")" == Running ]]; }

# fetch <device> <ip> <port> <path>: HTTP over the device's tailnet, exit 0 only on 200.
fetch() {
  curl --silent --show-error --fail --max-time 10 \
    --socks5 "127.0.0.1:$(socks_of "$1")" "http://$2:$3$4"
}

start_device() {
  local dev="$1" dir="$RUN/nodes/$1"
  mkdir -p "$dir"
  chmod 700 "$dir"
  start_bg "$dir/pid" "$dir/tailscaled.log" "$TAILSCALED_BIN" \
    --tun=userspace-networking --statedir="$dir" --socket="$dir/ts.sock" \
    --port=0 --socks5-server="127.0.0.1:$(socks_of "$dev")" --no-logs-no-support
  wait_for "$WAIT_S" test -S "$dir/ts.sock" || die "tailscaled for $dev did not start (see $dir/tailscaled.log)"
}

# tsmp_pong <device> <ip>: a TSMP ping is answered by the peer's WireGuard
# endpoint itself, so a pong proves a working WireGuard session (a plain
# `tailscale ping` is a disco ping and does not).
tsmp_pong() { ts "$1" ping --tsmp --c 1 --timeout 5s "$2" 2>&1 | grep -q 'via TSMP'; }

# join <device> <keyfile>: registers the device with a pre-auth key read from a 0600 file.
# --reset: a failed attempt must fail on the key, not on flags left by the previous one.
join() {
  ts "$1" up --reset --login-server="http://127.0.0.1:$HS_PORT" --auth-key="file:$2" \
    --hostname="$1" --accept-dns=false --accept-routes=false --timeout="${WAIT_S}s"
}

# new_key <user|""> [extra flags]: writes a pre-auth key to a 0600 file and prints its path.
new_key() {
  local user="$1"; shift
  local file
  file=$(mktemp "$RUN/keys/key.XXXXXX")
  chmod 600 "$file"
  if [[ -n "$user" ]]; then
    hs preauthkeys create --user "$(user_id "$user")" "$@" -o json | json "d['key']" >"$file"
  else
    hs preauthkeys create "$@" -o json | json "d['key']" >"$file"
  fi
  printf '%s\n' "$file"
}
