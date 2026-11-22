#!/bin/bash
# Runs as root inside a disposable Debian 12 VM and plays a GCE first boot of the Kyrmesh VM with
# nothing real behind it: Pebble is the CA, challtestsrv the public resolver, mocks.py the GCE
# metadata server, Secret Manager, Cloudflare and the GitHub release. startup.sh and install.sh run
# unchanged. Phases: setup | boot | rerun | tamper | reboot (the last after the VM restarts).
set -euo pipefail
T=/opt/kyrmesh-test
HOST=ctrl.net.example.com ZONE=example.com VERSION=kyrmesh-v0.0.0-test
CF_TOKEN=cf-test-$(cat /proc/sys/kernel/random/uuid)
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; exit 1; }
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac

setup() {
  command -v nft >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null; }
  cd "$T"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=kyrmesh-test-ca \
    -keyout ca.key -out ca.crt 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=kyrmesh-test-mocks \
    -keyout tls.key -out tls.csr 2>/dev/null
  printf 'subjectAltName=DNS:api.cloudflare.com,DNS:secretmanager.googleapis.com,DNS:github.com,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > san.ext
  openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out tls.crt 2>/dev/null
  cp ca.crt /usr/local/share/ca-certificates/kyrmesh-test-ca.crt && update-ca-certificates >/dev/null 2>&1
  mkdir -p release; [[ -f "release/kyrmesh-linux-$arch" ]] || mv "kyrmesh-linux-$arch" release/
  sha=$(sha256sum "release/kyrmesh-linux-$arch" | cut -d' ' -f1)
  python3 - "$sha" <<EOF
import json, sys
json.dump({"gce_token": "gce-test-token", "external_ip": "192.0.2.10", "zone": "$ZONE", "version": "$VERSION",
           "secret": "projects/kyrmesh-test/secrets/prod-kyrmesh-sm-cloudflare-core-01",
           "cloudflare_token": "$CF_TOKEN"}, open("config.json", "w"))
json.dump({"kyrmesh-install": open("install.sh").read(), "kyrmesh-host": "$HOST", "kyrmesh-zone": "$ZONE",
           "kyrmesh-version": "$VERSION", "kyrmesh-sha256-$arch": sys.argv[1], "kyrmesh-user": "admin",
           "kyrmesh-acme-url": "https://localhost:14000/dir",
           "kyrmesh-secret": "projects/kyrmesh-test/secrets/prod-kyrmesh-sm-cloudflare-core-01"},
          open("attributes.json", "w"))
EOF
  printf '{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000","certificate":"%s/tls.crt","privateKey":"%s/tls.key","httpPort":5002,"tlsPort":5001,"externalAccountBindingRequired":false}}\n' "$T" "$T" > pebble.json
  # The fake network: the public names resolve to TEST-NET addresses that nftables hands to the mocks.
  cat > net.sh <<'EOF'
#!/bin/bash
grep -q kyrmesh-test /etc/hosts || printf '203.0.113.10 api.cloudflare.com secretmanager.googleapis.com github.com # kyrmesh-test\n203.0.113.11 metadata.google.internal # kyrmesh-test\n' >> /etc/hosts
nft list table ip kyrmesh_test >/dev/null 2>&1 || nft -f - <<'NFT'
table ip kyrmesh_test {
  chain out {
    type nat hook output priority -100;
    ip daddr 203.0.113.10 tcp dport 443 dnat to 127.0.0.1:8443
    ip daddr 203.0.113.11 tcp dport 80 dnat to 127.0.0.1:8080
    ip daddr 1.1.1.1 udp dport 53 dnat to 127.0.0.1:8053
    ip daddr 1.1.1.1 tcp dport 53 dnat to 127.0.0.1:8053
  }
}
NFT
EOF
  chmod +x net.sh pebble pebble-challtestsrv
  unit() { printf '[Unit]\nBefore=kyrmesh-dns-a.service kyrmesh.service\nAfter=kt-net.service\n[Service]\n%s\n[Install]\nWantedBy=multi-user.target\n' "$2" > "/etc/systemd/system/$1.service"; }
  printf '[Unit]\nBefore=kyrmesh-dns-a.service kyrmesh.service\nAfter=network.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s/net.sh\n[Install]\nWantedBy=multi-user.target\n' "$T" > /etc/systemd/system/kt-net.service
  unit kt-dns "ExecStart=$T/pebble-challtestsrv -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 -http01 '' -https01 '' -tlsalpn01 '' -doh ''"
  unit kt-pebble "Environment=PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=0
ExecStart=$T/pebble -config $T/pebble.json -dnsserver 127.0.0.1:8053"
  # On GCE the metadata server answers before the VM's userspace starts; the stand-ins count as
  # started only once both ports answer, or dns-a can boot first and fall back to a public echo.
  unit kt-mocks "ExecStart=/usr/bin/python3 $T/mocks.py $T
ExecStartPost=/usr/bin/timeout 10 /bin/sh -c 'until curl -s -o /dev/null http://127.0.0.1:8080/ && curl -sk -o /dev/null https://127.0.0.1:8443/; do sleep 0.1; done'"
  systemctl daemon-reload
  systemctl enable kt-net kt-dns kt-pebble kt-mocks >/dev/null 2>&1; systemctl restart kt-net kt-dns kt-pebble kt-mocks
  for _ in $(seq 1 30); do curl -fsS -o /dev/null https://localhost:14000/dir 2>/dev/null && break; sleep 1; done
  curl -fsS -o /dev/null https://localhost:14000/dir || fail "pebble is not up"
  systemctl is-active --quiet kt-dns || fail "challtestsrv is not up"
  curl -fsS -o /dev/null -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/attributes/kyrmesh-host \
    || fail "metadata mock not reachable through the fake network"
  pass "setup: CA, resolver, metadata, Secret Manager, Cloudflare and release stand-ins up ($arch)"
}

checks() {
  systemctl is-active --quiet kyrmesh || fail "kyrmesh not active"
  # Pebble makes a new root every time it starts; the certificate the server caches chains to the
  # root of the first boot, as a real one keeps chaining to a CA root that does not change.
  [[ -s "$T/pebble-root.pem" ]] || curl -fsS "https://localhost:15000/roots/0" -o "$T/pebble-root.pem"
  code=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$T/pebble-root.pem" --resolve "$HOST:443:127.0.0.1" "https://$HOST/health")
  [[ $code == 200 ]] || fail "health over TLS answered $code"
  san=$(echo | openssl s_client -connect 127.0.0.1:443 -servername "$HOST" 2>/dev/null | openssl x509 -noout -ext subjectAltName | tail -1 | tr -d ' ')
  [[ $san == "DNS:*.net.example.com" ]] || fail "served certificate covers '$san'"
  pass "https://$HOST/health 200 with a CA-issued wildcard certificate ($san)"
}

boot() {
  t0=$(date +%s.%N)
  bash "$T/startup.sh" > "$T/boot.log" 2>&1 || { tail -20 "$T/boot.log"; fail "startup.sh failed"; }
  echo "TIME first boot install: $(python3 -c "import time; print(round(time.time()-$t0,1))") s"
  checks
  grep -q "post A $HOST 192.0.2.10" "$T/calls.log" || fail "A record not created"
  grep -q "post TXT _acme-challenge.net.example.com" "$T/calls.log" && grep -q "delete TXT _acme-challenge.net.example.com" "$T/calls.log" \
    || fail "DNS-01 record not created and removed"
  pass "A record created at the VM address; DNS-01 record created and removed"
  [[ "$(stat -c '%a %U' /etc/kyrmesh/cloudflare-token)" == "400 kyrmesh" ]] || fail "token file mode"
  token=$(python3 -c "import json; print(json.load(open('$T/config.json'))['cloudflare_token'])")
  n=$( { journalctl --no-pager -b; cat "$T/boot.log"; } | grep -c "$token" || true)
  [[ $n == 0 ]] || fail "token appears $n times in logs"
  pass "token stored 0400 for kyrmesh only, absent from the journal and the boot log"
  link=$(kyrmesh-invite | grep -Eo "https://$HOST/[^[:space:]]+" | head -n1)
  [[ -n "$link" ]] || fail "no invitation link"
  pass "first invitation: ${link%%code=*}code=<redacted>"
  grep -q '"src": \["admin@"\], "dst": \["admin@"\]' /etc/kyrmesh/policy.json || fail "default policy"
  pass "default policy: admin's devices reach each other, everything else denied"
}

rerun() {
  t0=$(date +%s.%N)
  bash "$T/startup.sh" > "$T/rerun.log" 2>&1 || fail "second startup.sh failed"
  [[ ! -s "$T/rerun.log" ]] || { cat "$T/rerun.log"; fail "second boot did more than the fast path"; }
  echo "TIME later boot (nothing changed): $(python3 -c "import time; print(round(time.time()-$t0,2))") s"
  pass "a later boot with the same metadata leaves the install alone"
}

tamper() {
  before=$(sha256sum /usr/local/bin/kyrmesh)
  if KYRMESH_HOST=$HOST KYRMESH_ZONE=$ZONE KYRMESH_VERSION=$VERSION KYRMESH_SHA256=$(printf '0%.0s' {1..64}) \
     KYRMESH_TOKEN_FILE=/etc/kyrmesh/cloudflare-token bash "$T/install.sh" > "$T/tamper.log" 2>&1; then
    fail "install.sh accepted a binary that does not match its SHA-256"
  fi
  grep -q 'does not match its pinned SHA-256' "$T/tamper.log" || fail "unexpected tamper error: $(tail -1 "$T/tamper.log")"
  [[ "$(sha256sum /usr/local/bin/kyrmesh)" == "$before" ]] || fail "binary changed after a refused install"
  pass "a binary that does not match its pinned SHA-256 is refused before anything changes"
}

# What dns-a saw at this boot, for a failed reboot check: its log, the stand-ins' last calls and
# the stand-in zone (test addresses and challenge names only, nothing secret).
dns_a_diag() {
  echo "--- dns-a, this boot"; journalctl -u kyrmesh-dns-a -b --no-pager -o short-monotonic || true
  echo "--- stand-in calls, last 15"; tail -n 15 "$T/calls.log" || true
  echo "--- stand-in zone"; cat "$T/zone.json" 2>/dev/null || echo "(no zone.json)"
  echo "--- public-ip file"; cat /etc/kyrmesh/public-ip || true
}

reboot_checks() {
  for _ in $(seq 1 60); do systemctl is-active --quiet kyrmesh && break; sleep 2; done
  for _ in $(seq 1 30); do journalctl -u kyrmesh -b --no-pager | grep -q 'dnscert: loaded cached certificate' && break; sleep 2; done
  journalctl -u kyrmesh-dns-a -b --no-pager | grep -q 'A record already points here' \
    || { dns_a_diag; fail "dns-a did not find its A record at boot"; }
  journalctl -u kyrmesh -b --no-pager | grep -q 'dnscert: loaded cached certificate' || fail "certificate not reused after reboot"
  checks
  pass "after a reboot: A record checked, cached certificate reused, server answering"
}

case "${1:-}" in
  setup) setup ;;
  boot) boot ;;
  rerun) rerun ;;
  tamper) tamper ;;
  reboot) reboot_checks ;;
  *) echo "usage: in-vm.sh setup|boot|rerun|tamper|reboot"; exit 2 ;;
esac
