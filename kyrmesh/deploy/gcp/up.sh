#!/bin/bash
# One command from nothing to a running Kyrmesh server on a free GCP VM, with its DNS record and
# certificate, and a first invitation link. No router, no DNS edits, no compiling, no sudo.
#
#   CLOUDFLARE_API_TOKEN=... ./up.sh --project my-gcp-project --host ctrl.net.example.com --zone example.com
#
# Needs: gcloud signed in (Cloud Shell already is), a GCP project with billing enabled, and a
# Cloudflare token limited to editing the zone's DNS. Terraform is fetched if missing or too old.
# Options: --region R --compute-zone Z --user NAME --staging (Let's Encrypt staging) --plan-only
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
t0=$(date +%s)
step() { printf '\n[%3ss] %s\n' "$(( $(date +%s) - t0 ))" "$*"; }
die() { echo "up.sh: $*" >&2; exit 1; }

project='' host='' zone='' region=us-east1 czone='' user=admin plan_only=no
acme=https://acme-v02.api.letsencrypt.org/directory trust=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) project=$2; shift 2 ;;
    --host) host=$2; shift 2 ;;
    --zone) zone=$2; shift 2 ;;
    --region) region=$2; shift 2 ;;
    --compute-zone) czone=$2; shift 2 ;;
    --user) user=$2; shift 2 ;;
    --staging) acme=https://acme-staging-v02.api.letsencrypt.org/directory trust=(-k); shift ;;
    --plan-only) plan_only=yes; shift ;;
    *) die "unknown option $1 (see the header of this file)" ;;
  esac
done
[[ -n "$project" && -n "$host" && -n "$zone" ]] || die "--project, --host and --zone are required"
czone=${czone:-$region-b}
cf_api=${KYRMESH_CLOUDFLARE_API:-https://api.cloudflare.com/client/v4}

# Terraform 1.11+ for write-only arguments; a pinned build is fetched next to this file otherwise.
tf_version=1.16.4
tf_sum() {
  case "$1" in
    darwin_amd64) echo 2ee4b62064086e4b24b0d6cf2e61718fbaf0556feba990f708a5e32557554b3b ;;
    darwin_arm64) echo 42cfdf97ad722f79085fe2279b06d4b8680172de3534b22eeddd9a0fbbe7b8f1 ;;
    linux_amd64) echo dc94af0eef1147718ad7c8daea792ed199e3e0492eec180d0adafa2a65a879df ;;
    linux_arm64) echo 8263f301cb1a24489a4adeed147bf28504053f77237b3ea97a0ef2972659de30 ;;
  esac
}
ensure_terraform() {
  local have
  if command -v terraform >/dev/null; then
    have=$(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')
    python3 -c 'import sys; v=[int(x) for x in sys.argv[1].split("-")[0].split(".")[:2]]; sys.exit(0 if v>=[1,11] else 1)' "$have" \
      && { tf=terraform; return; }
  fi
  tf="$here/.bin/terraform"
  [[ -x "$tf" ]] && return
  local os arch sum
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m); [[ $arch == x86_64 ]] && arch=amd64; [[ $arch == aarch64 ]] && arch=arm64
  sum=$(tf_sum "${os}_$arch"); [[ -n "$sum" ]] || die "no pinned Terraform for ${os}_$arch: install Terraform 1.11+"
  mkdir -p "$here/.bin"
  curl -fsSL -o "$here/.bin/tf.zip" "https://releases.hashicorp.com/terraform/$tf_version/terraform_${tf_version}_${os}_$arch.zip"
  echo "$sum  $here/.bin/tf.zip" | (sha256sum -c --quiet - 2>/dev/null || shasum -a 256 -c --quiet -) \
    || die "Terraform download does not match its pinned SHA-256"
  python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extract("terraform", sys.argv[2])' "$here/.bin/tf.zip" "$here/.bin"
  chmod 0755 "$tf"; rm -f "$here/.bin/tf.zip"
}

step "1/6 tools and accounts"
command -v python3 >/dev/null && command -v curl >/dev/null || die "needs python3 and curl"
ensure_terraform
if [[ -z "${GOOGLE_OAUTH_ACCESS_TOKEN:-}" ]]; then
  command -v gcloud >/dev/null || die "needs gcloud signed in (or Cloud Shell)"
  GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token --project="$project" 2>/dev/null) \
    || die "gcloud is not signed in: run gcloud auth login"
fi
export GOOGLE_OAUTH_ACCESS_TOKEN
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  [[ -t 0 ]] || die "set CLOUDFLARE_API_TOKEN (Cloudflare > My Profile > API Tokens > Edit zone DNS, zone $zone)"
  # The token lives on an internet-facing VM and Cloudflare scopes it to a whole zone: a dedicated
  # zone (cheap domain or delegated subzone) limits what a compromised server can touch (review M2).
  echo "The token stays on the server to renew its certificate: prefer a zone used only for Kyrmesh." >&2
  read -rsp "Cloudflare token (Edit zone DNS for $zone): " CLOUDFLARE_API_TOKEN; echo
fi
echo "terraform: $("$tf" version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])')"

step "2/6 Cloudflare token and zone $zone"
hdr=$(mktemp); chmod 600 "$hdr"; trap 'rm -f "$hdr"' EXIT
printf 'Authorization: Bearer %s\n' "$CLOUDFLARE_API_TOKEN" > "$hdr"
cf() { curl -fsS --max-time 20 -H @"$hdr" "$cf_api$1"; }
zone_id=$(cf "/zones?name=$zone" | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["id"] if len(r)==1 else "")') \
  || die "Cloudflare rejected the token"
[[ -n "$zone_id" ]] || die "the token does not see the zone $zone"
read -r existing owner < <(cf "/zones/$zone_id/dns_records?type=A&name=$host" \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print((r[0]["content"]+" "+(r[0].get("comment") or "-")) if r else "")') \
  || die "the token cannot read the zone's DNS records"
# An A record is ours only if Kyrmesh created it (comment "kyrmesh") AND this folder's state is the
# deployment of this --host. Any state at all used to skip the check (review M1).
if [[ -n "${existing:-}" ]]; then
  [[ "${owner:-}" == kyrmesh ]] \
    || die "$host already has an A record ($existing) not created by Kyrmesh. Pick another --host or delete that record first"
  [[ -s terraform.tfstate ]] \
    || die "$host already has a Kyrmesh A record ($existing) from another deployment (no state here). Pick another --host"
  # Not the address: an ephemeral IP changes on stop/start and kyrmesh-dns-a follows it, the state does not.
  st_url=$(python3 -c 'import json; print(json.load(open("terraform.tfstate")).get("outputs",{}).get("server_url",{}).get("value","-"))') \
    || die "cannot read terraform.tfstate"
  [[ "$st_url" == "https://$host" ]] \
    || die "$host already has a Kyrmesh A record ($existing) that this folder's state does not own. Pick another --host"
fi
echo "zone visible, $host free or already ours"

step "3/6 terraform plan (new state next to this file)"
# up.sh owns up.auto.tfvars; terraform.tfvars is left to the operator (rotation, deletion_protection).
cat > up.auto.tfvars <<EOF
project_id      = "$project"
region          = "$region"
zone            = "$czone"
server_host     = "$host"
cloudflare_zone = "$zone"
first_user      = "$user"
acme_url        = "$acme"
EOF
export TF_VAR_cloudflare_token=$CLOUDFLARE_API_TOKEN TF_IN_AUTOMATION=1
tflog=$(mktemp); trap 'rm -f "$hdr" "$tflog"' EXIT
tf_run() { "$tf" "$@" -input=false -no-color > "$tflog" 2>&1 || { tail -25 "$tflog" >&2; die "terraform $1 failed"; }; }
tf_run init
tf_run plan -out=tfplan
grep -E '^(Plan:|No changes)' "$tflog"
[[ $plan_only == yes ]] && { rm -f tfplan; step "plan only: nothing was created"; exit 0; }

step "4/6 terraform apply"
tf_run apply tfplan
grep -E '^Apply complete' "$tflog"
rm -f tfplan
ip=$("$tf" output -raw external_ip)
vm=$("$tf" output -raw instance)

step "5/6 waiting for the VM to install itself and get its certificate"
ok=no
for _ in $(seq 1 120); do
  # By address, not by name: asking a resolver before the record exists caches the miss.
  if curl -fsS ${trust[@]+"${trust[@]}"} --max-time 5 --resolve "$host:443:$ip" "https://$host/health" >/dev/null 2>&1; then
    ok=yes; break
  fi
  sleep 5
done
[[ $ok == yes ]] || die "not serving after 10 minutes: gcloud compute instances get-serial-port-output $vm --zone=$czone --project=$project"
record=$(cf "/zones/$zone_id/dns_records?type=A&name=$host" | python3 -c 'import json,sys; r=json.load(sys.stdin)["result"]; print(r[0]["content"] if r else "")')
[[ "$record" == "$ip" ]] || die "the A record of $host is '$record', expected $ip"
echo "https://$host answers over TLS${trust:+ (staging certificate, not trusted by devices)}; its A record points at the VM"

step "6/6 first invitation"
invite=$(gcloud compute ssh "$vm" --zone="$czone" --project="$project" --tunnel-through-iap --quiet \
  --command='sudo kyrmesh-invite' 2>/dev/null | grep -Eo "https://$host/[^[:space:]]+" | head -n1 || true)
echo
echo "Kyrmesh is running at https://$host ($(( $(date +%s) - t0 )) s)."
if [[ -n "$invite" ]]; then
  echo "Open this link on the first device to join it (valid for 1 hour, one use):"
  echo "  $invite"
else
  echo "Create an invitation with:"
  echo "  gcloud compute ssh $vm --zone=$czone --project=$project --tunnel-through-iap --command='sudo kyrmesh-invite'"
fi
