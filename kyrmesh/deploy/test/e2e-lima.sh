#!/bin/bash
# End-to-end test of the GCE boot path in a disposable Lima VM (Debian 12, no mounts, no port
# forwarding), with every external service replaced by a local stand-in (see in-vm.sh). Nothing
# outside the VM is created or changed; the VM is deleted at the end.
#
#   kyrmesh/deploy/test/e2e-lima.sh <kyrmesh-linux-ARCH binary> <dir with pebble binaries> [x86_64|aarch64]
set -euo pipefail
bin=$1 pebble_dir=$2 arch=${3:-aarch64}
here=$(cd "$(dirname "$0")" && pwd)
name="kyrmesh-e2e-$arch-$$"
case $arch in x86_64) goarch=amd64 ;; aarch64) goarch=arm64 ;; *) echo "arch x86_64|aarch64"; exit 2 ;; esac

# KEEP_VM=1 keeps the VM after a failure, to look inside with limactl shell.
cleanup() { [[ -n "${KEEP_VM:-}" && ${ok:-no} == no ]] || limactl delete -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
t0=$(date +%s)
limactl create --tty=false --name="$name" --plain --arch="$arch" --cpus=2 --memory=1 --disk=8 template:debian-12 >/dev/null
limactl start --tty=false "$name" >/dev/null 2>&1
echo "TIME VM up: $(( $(date +%s) - t0 )) s"

stage=$(mktemp -d); trap 'rm -rf "$stage"; cleanup' EXIT
cp "$here/../install.sh" "$here/../gcp/startup.sh" "$here/mocks.py" "$here/in-vm.sh" "$stage/"
cp "$bin" "$stage/kyrmesh-linux-$goarch"
cp "$pebble_dir/pebble" "$pebble_dir/pebble-challtestsrv" "$stage/"
limactl copy -r "$stage" "$name:/tmp/kt" >/dev/null
run() { limactl shell --workdir / "$name" sudo bash -c "$1"; }
run 'rm -rf /opt/kyrmesh-test && mv /tmp/kt /opt/kyrmesh-test && chown -R root:root /opt/kyrmesh-test'

run '/opt/kyrmesh-test/in-vm.sh setup'
run '/opt/kyrmesh-test/in-vm.sh boot'
run '/opt/kyrmesh-test/in-vm.sh rerun'
run '/opt/kyrmesh-test/in-vm.sh tamper'
limactl stop "$name" >/dev/null 2>&1
limactl start --tty=false "$name" >/dev/null 2>&1
run '/opt/kyrmesh-test/in-vm.sh reboot'
echo "TIME whole test: $(( $(date +%s) - t0 )) s"
ok=yes
