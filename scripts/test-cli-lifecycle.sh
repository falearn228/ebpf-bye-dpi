#!/usr/bin/env bash
# Живой тест CLI в изолированных netns (нужен root):
#   doctor -> start (2 интерфейса) -> status -> reload ok -> reload rejected ->
#   doctor с живым демоном -> stop -> проверка, что TC-хуки сняты.
#
#   cargo build && sudo ./scripts/test-cli-lifecycle.sh

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${GBD_BIN_DIR:-${ROOT_DIR}/target/debug}"
CLI="${BIN_DIR}/goodbyedpi"
export GOODBYEDPI_DAEMON="${BIN_DIR}/goodbyedpi-daemon"

NS="gbd-cli"
RUN_DIR="$(mktemp -d)"
PROFILE="${RUN_DIR}/profile.txt"

cleanup() {
    set +e
    ip netns exec "${NS}" "${CLI}" --run-dir "${RUN_DIR}" stop >/dev/null 2>&1
    ip netns del "${NS}" 2>/dev/null
    rm -rf "${RUN_DIR}"
}
trap cleanup EXIT

step() { echo; echo "==> $*"; }
in_ns() { ip netns exec "${NS}" "$@"; }
cli() { in_ns "${CLI}" --run-dir "${RUN_DIR}" "$@"; }

[[ -x "${CLI}" && -x "${GOODBYEDPI_DAEMON}" ]] || {
    echo "ERROR: build first: cargo build" >&2
    exit 1
}

ip netns add "${NS}"
in_ns ip link add gbd0 type veth peer name gbd1
in_ns ip link set lo up
in_ns ip link set gbd0 up
in_ns ip link set gbd1 up

echo "s1 -o1" > "${PROFILE}"

step "doctor before start"
cli doctor -i gbd0,gbd1 -f "${PROFILE}" || true

step "start on two interfaces"
cli start -i gbd0,gbd1 -f "${PROFILE}" -- --metrics-bind 127.0.0.1:19877

step "status"
cli status
cli status --json | python3 -c '
import json, sys
s = json.load(sys.stdin)
assert s["running"], "daemon not running"
for i in s["interfaces"]:
    assert i["egress_attached"] and i["ingress_attached"], i
print("status OK:", [i["name"] for i in s["interfaces"]])
'

step "reload with valid change"
echo "s2 -o1 -d" > "${PROFILE}"
cli reload

step "reload with broken profile (must be refused before SIGHUP)"
echo "s2 -Qx" > "${PROFILE}"
if cli reload; then
    echo "FAIL: broken profile was accepted" >&2
    exit 1
fi

step "reload changing auto flags (daemon must reject, keep old config)"
echo "s2 -Ar" > "${PROFILE}"
if cli reload; then
    echo "FAIL: auto flag change was accepted" >&2
    exit 1
fi
cli status | grep -q "REJECTED"

step "doctor with running daemon"
echo "s2 -o1 -d" > "${PROFILE}"
cli doctor -f "${PROFILE}"

step "stop"
cli stop
for dev in gbd0 gbd1; do
    if in_ns tc filter show dev "${dev}" egress | grep -q dpi_egress; then
        echo "FAIL: egress hook left on ${dev}" >&2
        exit 1
    fi
done
[[ ! -e "${RUN_DIR}/daemon.pid" ]] || { echo "FAIL: pid file left" >&2; exit 1; }

echo
echo "CLI lifecycle test PASSED"
