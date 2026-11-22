#!/bin/bash
# Runs gcp/up.sh --plan-only on a copy of the kit, against a stand-in Cloudflare API and with no
# GCP credentials (a plan with only new resources calls no Google API). Checks the operator side up
# to the apply boundary, and that an A record nobody here created stops it before any change.
#
#   kyrmesh/deploy/test/up-plan.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'kill "${stub:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT
# A provider already downloaded next to the kit is reused; state and tfvars are not copied.
rsync -a --exclude '*.tfstate*' --exclude '*.tfvars' --exclude tfplan "$here/../" "$work/deploy/"
printf 'version=kyrmesh-v0.0.0-test\nsha256_amd64=%064d\nsha256_arm64=%064d\n' 0 0 > "$work/deploy/RELEASE"

cat > "$work/cf.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
mode = sys.argv[2]  # free | taken (someone else's A) | ours (an A created by Kyrmesh)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        ok = self.headers.get("Authorization") == "Bearer cf-plan-token"
        if "/dns_records" in self.path:
            result = {"free": [], "taken": [{"id": "r1", "content": "198.51.100.7"}],
                      "ours": [{"id": "r1", "content": "198.51.100.7", "comment": "kyrmesh"}]}[mode]
        else:
            result = [{"id": "zone1", "name": "example.com"}]
        body = json.dumps({"success": ok, "errors": [], "result": result if ok else []}).encode()
        self.send_response(200 if ok else 403); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF

up() {
  CLOUDFLARE_API_TOKEN=cf-plan-token GOOGLE_OAUTH_ACCESS_TOKEN=offline-plan \
    KYRMESH_CLOUDFLARE_API="http://127.0.0.1:$1/client/v4" \
    "$work/deploy/gcp/up.sh" --project example-plan --host ctrl.net.example.com --zone example.com --plan-only
}

python3 "$work/cf.py" 18471 free & stub=$!
sleep 1
t0=$(date +%s)
out=$(up 18471 2>&1) || { echo "$out" | tail -20; echo "FAIL up.sh --plan-only"; exit 1; }
echo "$out" | grep -q 'Plan: 13 to add, 0 to change, 0 to destroy' || { echo "$out" | tail -20; echo "FAIL unexpected plan"; exit 1; }
echo "$out" | grep -q 'cf-plan-token' && { echo "FAIL token printed"; exit 1; }
[[ ! -e "$work/deploy/gcp/terraform.tfstate" ]] || { echo "FAIL plan-only wrote state"; exit 1; }
echo "PASS up.sh --plan-only: 13 to add, 0 to change, 0 to destroy, token never printed ($(( $(date +%s) - t0 )) s)"
kill "$stub"

python3 "$work/cf.py" 18472 taken & stub=$!
sleep 1
if out=$(up 18472 2>&1); then echo "FAIL up.sh went on with a taken name"; exit 1; fi
echo "$out" | grep -q 'already has an A record' || { echo "$out" | tail -5; echo "FAIL unexpected error"; exit 1; }
echo "$out" | grep -q 'terraform plan' && { echo "FAIL reached terraform with a taken name"; exit 1; }
echo "PASS a name that already has an A record stops up.sh before Terraform"
kill "$stub"

# Review M1: any state at all used to skip the guard. A state of another --host must not adopt the name.
state="$work/deploy/gcp/terraform.tfstate"
printf '{"version":4,"outputs":{"server_url":{"value":"https://other.net.example.com","type":"string"}}}\n' > "$state"
for mode in taken ours; do
  [[ $mode == taken ]] && port=18473 || port=18474
  python3 "$work/cf.py" "$port" "$mode" & stub=$!
  sleep 1
  if out=$(up "$port" 2>&1); then echo "FAIL up.sh adopted a $mode A record with a state of another host"; exit 1; fi
  echo "$out" | grep -q 'already has' || { echo "$out" | tail -5; echo "FAIL unexpected error ($mode)"; exit 1; }
  echo "$out" | grep -q 'terraform plan' && { echo "FAIL reached terraform ($mode)"; exit 1; }
  kill "$stub"
done
rm -f "$state"
echo "PASS with a state of another host, a foreign or Kyrmesh A record still stops up.sh before Terraform"
