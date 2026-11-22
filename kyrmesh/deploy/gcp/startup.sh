#!/bin/bash
# GCE startup script of the Kyrmesh VM: runs as root on every boot. The installer and its
# parameters come from the instance metadata, the Cloudflare token from Secret Manager. When none
# of them changed since the last boot, it only refreshes the token; otherwise it (re)installs.
set -euo pipefail
md=http://metadata.google.internal/computeMetadata/v1
meta() { curl -fsS --retry 10 --retry-all-errors --max-time 10 -H 'Metadata-Flavor: Google' "$md/$1"; }
attr() { meta "instance/attributes/$1"; }

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo "kyrmesh-startup: unsupported architecture" >&2; exit 1 ;;
esac

work=$(mktemp -d); chmod 700 "$work"; trap 'rm -rf "$work"' EXIT
attr kyrmesh-install > "$work/install.sh"
export KYRMESH_HOST KYRMESH_ZONE KYRMESH_VERSION KYRMESH_SHA256 KYRMESH_USER KYRMESH_ACME_URL
KYRMESH_HOST=$(attr kyrmesh-host)
KYRMESH_ZONE=$(attr kyrmesh-zone)
KYRMESH_VERSION=$(attr kyrmesh-version)
KYRMESH_SHA256=$(attr "kyrmesh-sha256-$arch")
KYRMESH_USER=$(attr kyrmesh-user)
KYRMESH_ACME_URL=$(attr kyrmesh-acme-url)
secret=$(attr kyrmesh-secret)

# The VM's own account reads only this secret; its access token goes in a header file, never argv.
hdr="$work/hdr"
meta instance/service-accounts/default/token \
  | python3 -c 'import json,sys; print("Authorization: Bearer " + json.load(sys.stdin)["access_token"])' > "$hdr"
curl -fsS --retry 10 --retry-all-errors --max-time 20 -H @"$hdr" \
  "https://secretmanager.googleapis.com/v1/$secret/versions/latest:access" \
  | python3 -c 'import base64,json,sys; print(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode().strip())' \
  > "$work/token"
[[ -s "$work/token" ]] || { echo "kyrmesh-startup: empty token in Secret Manager" >&2; exit 1; }

stamp=$( { cat "$work/install.sh"; env | grep '^KYRMESH_' | sort; } | sha256sum | cut -d' ' -f1)
if [[ -f /var/lib/kyrmesh-install.stamp && "$(cat /var/lib/kyrmesh-install.stamp)" == "$stamp" ]]; then
  if ! cmp -s "$work/token" /etc/kyrmesh/cloudflare-token; then
    install -m 0400 -o kyrmesh -g kyrmesh "$work/token" /etc/kyrmesh/cloudflare-token
    systemctl restart kyrmesh-dns-a.service kyrmesh.service
    echo "kyrmesh-startup: token rotated"
  fi
  exit 0
fi

KYRMESH_TOKEN_FILE="$work/token" bash "$work/install.sh"
printf '%s\n' "$stamp" > /var/lib/kyrmesh-install.stamp
