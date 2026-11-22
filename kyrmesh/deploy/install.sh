#!/bin/bash
# Installs or upgrades the Kyrmesh control server on a systemd Linux host (amd64 or arm64).
# Self-contained: the units, the configuration template and the default policy live in this file,
# and the binary comes from a published release, checked against its pinned SHA-256.
#
#   sudo KYRMESH_HOST=ctrl.net.example.com KYRMESH_ZONE=example.com \
#     KYRMESH_TOKEN_FILE=/path/to/cloudflare-token bash install.sh
#
# Required: KYRMESH_HOST (the server name), KYRMESH_ZONE (the Cloudflare zone holding it) and a
# Cloudflare API token limited to editing that zone's DNS, in KYRMESH_TOKEN_FILE or on stdin.
# Optional: KYRMESH_VERSION and KYRMESH_SHA256 (default: the release pinned in ./RELEASE),
# KYRMESH_USER (first user, default "admin"), KYRMESH_ACME_URL (default Let's Encrypt
# production), KYRMESH_BASE_DOMAIN (MagicDNS domain, default red.<parent of the host>),
# KYRMESH_PUBLIC_IP (address for the A record when the host cannot discover it),
# KYRMESH_DOWNLOAD_BASE (where releases are fetched from).
set -euo pipefail

die() { echo "kyrmesh-install: $*" >&2; exit 1; }
log() { echo "kyrmesh-install: $*"; }

[[ $EUID -eq 0 ]] || die "must run as root"
command -v systemctl >/dev/null || die "needs systemd"
for tool in curl python3 sha256sum; do command -v "$tool" >/dev/null || die "needs $tool"; done

here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)
if [[ -z "${KYRMESH_VERSION:-}" && -f "$here/RELEASE" ]]; then
  KYRMESH_VERSION=$(sed -n 's/^version=//p' "$here/RELEASE")
fi

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
if [[ -z "${KYRMESH_SHA256:-}" && -f "$here/RELEASE" ]]; then
  KYRMESH_SHA256=$(sed -n "s/^sha256_${arch}=//p" "$here/RELEASE")
fi

host=${KYRMESH_HOST:-}
zone=${KYRMESH_ZONE:-}
version=${KYRMESH_VERSION:-}
sha=${KYRMESH_SHA256:-}
user=${KYRMESH_USER:-admin}
acme=${KYRMESH_ACME_URL:-https://acme-v02.api.letsencrypt.org/directory}
download=${KYRMESH_DOWNLOAD_BASE:-https://github.com/Kembec/kyrmesh/releases/download}

label='[a-z0-9]([a-z0-9-]*[a-z0-9])?'
[[ "$host" =~ ^$label(\.$label)+$ ]] || die "KYRMESH_HOST must be a lowercase DNS name"
[[ "$zone" =~ ^$label(\.$label)+$ ]] || die "KYRMESH_ZONE must be a lowercase DNS name"
parent=${host#*.}
[[ "$parent" == "$zone" || "$parent" == *".$zone" ]] || die "KYRMESH_HOST must sit one label below a name inside KYRMESH_ZONE"
base_domain=${KYRMESH_BASE_DOMAIN:-red.$parent}
[[ "$user" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || die "KYRMESH_USER must be a short lowercase name"
[[ -n "$version" ]] || die "no release version: set KYRMESH_VERSION or pin one in RELEASE"
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no SHA-256 for linux-$arch: set KYRMESH_SHA256 or pin it in RELEASE"
[[ "$acme" == https://* && "$download" == https://* ]] || die "ACME and download URLs must be https"

# Binary first: nothing on the host changes until the pinned release is downloaded and verified.
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 5 --retry-all-errors --max-time 300 -o "$work/kyrmesh" \
  "$download/$version/kyrmesh-linux-$arch"
echo "$sha  $work/kyrmesh" | sha256sum -c --quiet - || die "kyrmesh-linux-$arch does not match its pinned SHA-256"
chmod 0755 "$work/kyrmesh"

id kyrmesh >/dev/null 2>&1 || useradd --system --home-dir /var/lib/kyrmesh --shell /usr/sbin/nologin kyrmesh
install -d -m 0750 -o root -g kyrmesh /etc/kyrmesh

# The token is in place before the first start: a start without it leaves an order mark that holds
# the next certificate order for an hour.
umask 077
if [[ -n "${KYRMESH_TOKEN_FILE:-}" ]]; then
  token=$(head -n1 "$KYRMESH_TOKEN_FILE" | tr -d '[:space:]')
else
  IFS= read -r token || true
  token=$(printf '%s' "${token:-}" | tr -d '[:space:]')
fi
[[ -n "$token" ]] || die "no Cloudflare token (KYRMESH_TOKEN_FILE or stdin)"
printf '%s\n' "$token" > /etc/kyrmesh/cloudflare-token.next; unset token
chown kyrmesh:kyrmesh /etc/kyrmesh/cloudflare-token.next; chmod 0400 /etc/kyrmesh/cloudflare-token.next
mv /etc/kyrmesh/cloudflare-token.next /etc/kyrmesh/cloudflare-token
umask 022

cat > "$work/config.yaml" <<EOF
# Kyrmesh control server. Public on 443/tcp (control, DERP over TLS) and 3478/udp (STUN);
# metrics and gRPC stay on loopback. Written by install.sh: edits are replaced on upgrade.
server_url: https://$host
listen_addr: 0.0.0.0:443
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/kyrmesh/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "kyrmesh"
    region_name: "Kyrmesh"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/kyrmesh/derp_server_private.key
    automatically_add_embedded_derp_region: true
  # Only this server's relay: no dependency on third-party relays.
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
node:
  expiry: 0
database:
  type: sqlite
  sqlite:
    path: /var/lib/kyrmesh/db.sqlite
    write_ahead_log: true
acme_url: $acme
acme_email: ""
tls_letsencrypt_hostname: ""
tls_letsencrypt_cache_dir: /var/lib/kyrmesh/cache
tls_letsencrypt_challenge_type: HTTP-01
# Wildcard over DNS-01: the server's own name never reaches the public CT logs.
tls_dns01_wildcard: "*.$parent"
tls_dns01_cloudflare_zone: $zone
tls_dns01_cloudflare_token_path: /etc/kyrmesh/cloudflare-token
tls_dns01_cache_dir: /var/lib/kyrmesh/dnscert
# /version and /swagger name the software and its version: off.
hide_fingerprint: true
tls_cert_path: ""
tls_key_path: ""
log:
  level: info
  format: text
policy:
  mode: file
  path: /etc/kyrmesh/policy.json
dns:
  magic_dns: true
  base_domain: $base_domain
  override_local_dns: false
  nameservers:
    global: []
unix_socket: /run/kyrmesh/kyrmesh.sock
unix_socket_permission: "0770"
logtail:
  enabled: false
taildrop:
  enabled: true
cli:
  timeout: 30s
EOF

# Deny by default: the first user's devices reach each other and nothing else. An edited policy
# survives upgrades.
if [[ ! -f /etc/kyrmesh/policy.json ]]; then
  printf '{\n  "grants": [\n    {"src": ["%s@"], "dst": ["%s@"], "ip": ["*"]}\n  ]\n}\n' "$user" "$user" \
    > /etc/kyrmesh/policy.json
  chown root:kyrmesh /etc/kyrmesh/policy.json; chmod 0640 /etc/kyrmesh/policy.json
fi

install -m 0640 -o root -g kyrmesh "$work/config.yaml" /etc/kyrmesh/config.next.yaml
"$work/kyrmesh" -c /etc/kyrmesh/config.next.yaml configtest >/dev/null 2>"$work/configtest.err" \
  || { sed -n '1,5p' "$work/configtest.err" >&2; die "configtest failed"; }
mv /etc/kyrmesh/config.next.yaml /etc/kyrmesh/config.yaml
install -m 0755 "$work/kyrmesh" /usr/local/bin/kyrmesh.next && mv /usr/local/bin/kyrmesh.next /usr/local/bin/kyrmesh
printf '%s\n' "${KYRMESH_PUBLIC_IP:-}" > /etc/kyrmesh/public-ip

cat > /usr/local/bin/kyrmesh-dns-a <<'EOF'
#!/bin/bash
# Points the server's A record at this host's public address. Runs once per boot, before the core:
# a cloud VM's ephemeral address changes on stop/start and nothing else re-checks it.
set -euo pipefail
host=$(sed -n 's|^server_url: https://||p' /etc/kyrmesh/config.yaml)
zone_name=$(sed -n 's|^tls_dns01_cloudflare_zone: ||p' /etc/kyrmesh/config.yaml)
api=https://api.cloudflare.com/client/v4
ip=$(head -n1 /etc/kyrmesh/public-ip 2>/dev/null || true)
# A GCE VM knows its external address; any other host asks a public echo service.
[[ -n "$ip" ]] || ip=$(curl -fsS --max-time 5 -H 'Metadata-Flavor: Google' \
  http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip 2>/dev/null || true)
[[ -n "$ip" ]] || ip=$(curl -fsS --max-time 10 https://api.ipify.org)
[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "no public IPv4 address" >&2; exit 1; }
hdr=$(mktemp); chmod 600 "$hdr"; trap 'rm -f "$hdr"' EXIT
printf 'Authorization: Bearer %s\n' "$(cat /etc/kyrmesh/cloudflare-token)" > "$hdr"
cf() { curl -fsS --retry 5 --retry-all-errors --max-time 20 -H @"$hdr" "$@"; }
zone=$(cf "$api/zones?name=$zone_name" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"][0]["id"])')
# The record carries comment "kyrmesh" from its creation: one without it belongs to someone else
# and is never overwritten (review M1, KEM-462).
read -r rec current owner < <(cf "$api/zones/$zone/dns_records?type=A&name=$host" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(" ".join([r[0]["id"], r[0]["content"], r[0].get("comment") or "-"]) if r else "- - -")')
[[ -n "${rec:-}" ]] || { echo "could not read the A record" >&2; exit 1; }
if [[ "$rec" != "-" && "$owner" != "kyrmesh" ]]; then
  echo "$host already has an A record not created by Kyrmesh ($current): left untouched" >&2; exit 1
fi
[[ "$current" == "$ip" ]] && { echo "A record already points here"; exit 0; }
body=$(printf '{"type":"A","name":"%s","content":"%s","ttl":300,"proxied":false,"comment":"kyrmesh"}' "$host" "$ip")
if [[ "$rec" == "-" ]]; then
  cf -X POST -H 'Content-Type: application/json' -d "$body" "$api/zones/$zone/dns_records" >/dev/null
else
  cf -X PUT -H 'Content-Type: application/json' -d "$body" "$api/zones/$zone/dns_records/$rec" >/dev/null
fi
echo "A record updated to this host"
EOF
chmod 0755 /usr/local/bin/kyrmesh-dns-a

cat > /usr/local/bin/kyr <<'EOF'
#!/bin/sh
# Kyrmesh admin CLI for root and members of the kyrmesh group: kyr users list
exec /usr/local/bin/kyrmesh -c /etc/kyrmesh/config.yaml "$@"
EOF
chmod 0755 /usr/local/bin/kyr

cat > /usr/local/bin/kyrmesh-invite <<'EOF'
#!/bin/bash
# Prints a one-time join link for a user: kyrmesh-invite [user] [expiration]
set -euo pipefail
user=${1:-$(sed -n 's/^user=//p' /etc/kyrmesh/install.env)}
id=$(/usr/local/bin/kyr users list -o json | python3 -c \
  'import json,sys; print(next(str(u["id"]) for u in json.load(sys.stdin) if u["name"]==sys.argv[1]))' "$user")
/usr/local/bin/kyr invites create --user "$id" --expiration "${2:-1h}"
EOF
chmod 0755 /usr/local/bin/kyrmesh-invite

cat > /etc/systemd/system/kyrmesh-dns-a.service <<'EOF'
[Unit]
Description=Point the Kyrmesh DNS A record at this host (once per boot)
Wants=network-online.target
After=network-online.target
Before=kyrmesh.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/kyrmesh-dns-a
# Reads the token as its owner, not as root; writes nothing outside its private /tmp.
User=kyrmesh
Group=kyrmesh
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/kyrmesh.service <<'EOF'
[Unit]
Description=Kyrmesh control server
After=network-online.target kyrmesh-dns-a.service
Wants=network-online.target

[Service]
User=kyrmesh
Group=kyrmesh
ExecStart=/usr/local/bin/kyrmesh -c /etc/kyrmesh/config.yaml serve
Restart=always
RestartSec=5
StateDirectory=kyrmesh
StateDirectoryMode=0750
RuntimeDirectory=kyrmesh
RuntimeDirectoryMode=0750
# Binds 443 without root; nothing else is granted.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
# Isolated from the rest of the host: no home directories, read-only system, private /tmp.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
MemoryMax=512M
# The core never needs the metadata server; denied, it cannot mint the VM service account's
# token and read the Cloudflare secret around the 0400 file (review M2, KEM-462).
IPAddressDeny=169.254.169.254/32

[Install]
WantedBy=multi-user.target
EOF

printf 'version=%s\nsha256=%s\nuser=%s\n' "$version" "$sha" "$user" > /etc/kyrmesh/install.env
systemctl daemon-reload
systemctl enable kyrmesh-dns-a.service kyrmesh.service >/dev/null 2>&1
systemctl restart kyrmesh-dns-a.service || die "could not point the A record (journalctl -u kyrmesh-dns-a)"
log "A record points at this host"
since=$(date '+%Y-%m-%d %H:%M:%S')
systemctl restart kyrmesh.service

cert=no
for _ in $(seq 1 150); do
  journalctl -u kyrmesh --no-pager --since "$since" | grep -q 'dnscert: certificate obtained\|dnscert: loaded cached' \
    && { cert=yes; break; }
  sleep 2
done
[[ $cert == yes ]] || die "no certificate after 5 minutes (journalctl -u kyrmesh | grep dnscert)"
for _ in $(seq 1 30); do [[ -S /run/kyrmesh/kyrmesh.sock ]] && break; sleep 1; done
[[ -S /run/kyrmesh/kyrmesh.sock ]] || die "the server did not start (journalctl -u kyrmesh)"
/usr/local/bin/kyr users list -o json | python3 -c \
  'import json,sys; sys.exit(0 if any(u["name"]==sys.argv[1] for u in json.load(sys.stdin)) else 1)' "$user" \
  || /usr/local/bin/kyr users create "$user" >/dev/null
journalctl -u kyrmesh --no-pager --since "$since" | grep -E 'dnscert' | tail -2 | sed -E 's/[0-9]+(\.[0-9]+){3}/<ip>/g'
systemctl is-active --quiet kyrmesh || die "kyrmesh is not active"
log "ready: https://$host (release $version, linux-$arch); first invite: kyrmesh-invite"
