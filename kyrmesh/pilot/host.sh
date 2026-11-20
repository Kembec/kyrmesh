# shellcheck shell=bash
# What the pilot must never change on the host: its interfaces, the routes of
# its tunnels and default gateways, its resolvers, and the state of a Tailscale
# already running there (read through the default socket, never written).
# Only stable, non-secret facts: no keys, no peer traffic counters.

host_tailscale() {
  if ! command -v tailscale >/dev/null 2>&1; then echo "tailscale: not installed"; return; fi
  local raw
  raw=$(tailscale status --json 2>/dev/null) || { echo "tailscale: unreadable"; return; }
  printf '%s' "$raw" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    print("tailscale: unreadable"); sys.exit()
s = d.get("Self") or {}
print("state", d.get("BackendState"))
print("self", s.get("ID"), " ".join(s.get("TailscaleIPs") or []))
print("tailnet", (d.get("CurrentTailnet") or {}).get("Name"))
print("exit node", d.get("ExitNodeStatus"))
print("routes", " ".join(s.get("PrimaryRoutes") or []))
' || echo "tailscale: unreadable"
}

host_snapshot() {
  echo "## interfaces"
  if command -v ip >/dev/null 2>&1; then
    ip -o link show | awk -F': ' '{print $2}' | sort
  else
    ifconfig -l | tr ' ' '\n' | sort
  fi
  echo "## default and tunnel routes"
  if command -v ip >/dev/null 2>&1; then
    ip route show table all 2>/dev/null | grep -E '^default|tailscale|wg|tun' | sort
  else # cloned entries (flag W) come and go with traffic: they are not configuration
    netstat -rn 2>/dev/null | awk '($1 == "default" || $4 ~ /^utun/) && $3 !~ /W/ {print $1, $2, $3, $4}' | sort -u
  fi
  echo "## resolvers"
  if command -v scutil >/dev/null 2>&1; then
    scutil --dns 2>/dev/null | grep -E 'nameserver\[|search domain' | sort -u
  else
    grep -E '^(nameserver|search)' /etc/resolv.conf 2>/dev/null | sort -u
  fi
  echo "## host tailscale"
  host_tailscale
}

# Facts = snapshot lines that are not section headers. A host read that came
# back nearly empty (80 on the reference Mac) proves nothing when "equal".
MIN_HOST_FACTS=20
host_facts() { grep -vc '^##' "$RESULTS/$1" || true; }
host_same() {
  cmp -s "$RESULTS/$1" "$RESULTS/$2" && (( $(host_facts "$1") >= MIN_HOST_FACTS && $(host_facts "$2") >= MIN_HOST_FACTS )) \
    && ! grep -q 'tailscale: unreadable' "$RESULTS/$1" "$RESULTS/$2"
}

host_diff() {
  if host_same "$1" "$2"; then
    echo "identical ($(host_facts "$1") facts: interfaces, routes, resolvers, host tailscale)"
  elif cmp -s "$RESULTS/$1" "$RESULTS/$2"; then
    echo "identical but unreliable: $(host_facts "$1") and $(host_facts "$2") facts (need $MIN_HOST_FACTS), or host tailscale unreadable"
  else
    diff "$RESULTS/$1" "$RESULTS/$2" | grep -E '^[<>]' | head -n 4 | tr '\n' ';'
  fi
}
