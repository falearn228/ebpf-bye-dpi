#!/usr/bin/env bash
# Runtime integration test in Linux network namespaces:
# - create netns + veth pair
# - run daemon with eBPF on veth
# - generate IPv6 QUIC-like UDP traffic
# - verify: event delivered, injector sent fragments, no loop on USERSPACE_MARK

set -euo pipefail

NS1="gbd-ns1"
NS2="gbd-ns2"
VETH1="gbd-veth1"
VETH2="gbd-veth2"
DAEMON_LOG="/tmp/goodbyedpi-netns-daemon.log"
TCPDUMP_LOG="/tmp/goodbyedpi-netns-tcpdump.log"
CONFIG="${1:-s1 -g8}"
DAEMON_BIN="${GBD_DAEMON_BIN:-}"

DAEMON_PID=""
TCPDUMP_PID=""

cleanup() {
    set +e

    if [[ -n "${TCPDUMP_PID}" ]]; then
        kill "${TCPDUMP_PID}" 2>/dev/null || true
        wait "${TCPDUMP_PID}" 2>/dev/null || true
    fi

    if [[ -n "${DAEMON_PID}" ]]; then
        kill "${DAEMON_PID}" 2>/dev/null || true
        wait "${DAEMON_PID}" 2>/dev/null || true
    fi

    ip netns del "${NS1}" 2>/dev/null || true
    ip netns del "${NS2}" 2>/dev/null || true
}

trap cleanup EXIT

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: required command not found: ${cmd}" >&2
        exit 1
    fi
}

if [[ "${EUID}" -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

require_cmd ip
require_cmd tc
require_cmd tcpdump
require_cmd python3

if [[ ! -f "./ebpf/src/vmlinux.h" ]]; then
    echo "ERROR: run from repository root" >&2
    exit 1
fi

if [[ -z "${DAEMON_BIN}" ]]; then
    if [[ -x "./target/release/goodbyedpi-daemon" ]]; then
        DAEMON_BIN="./target/release/goodbyedpi-daemon"
    elif [[ -x "./target/debug/goodbyedpi-daemon" ]]; then
        DAEMON_BIN="./target/debug/goodbyedpi-daemon"
    else
        echo "ERROR: daemon binary not found." >&2
        echo "Build it first, for example:" >&2
        echo "  cargo build --release -p goodbyedpi-daemon" >&2
        echo "or set explicit path via GBD_DAEMON_BIN=/path/to/goodbyedpi-daemon" >&2
        exit 1
    fi
fi

if [[ ! -x "${DAEMON_BIN}" ]]; then
    echo "ERROR: daemon binary is not executable: ${DAEMON_BIN}" >&2
    exit 1
fi

echo "[netns-test] using daemon binary: ${DAEMON_BIN}"

rm -f "${DAEMON_LOG}" "${TCPDUMP_LOG}"

echo "[netns-test] setup namespaces and veth pair"
ip netns add "${NS1}"
ip netns add "${NS2}"
ip link add "${VETH1}" type veth peer name "${VETH2}"
ip link set "${VETH1}" netns "${NS1}"
ip link set "${VETH2}" netns "${NS2}"

ip -n "${NS1}" link set lo up
ip -n "${NS2}" link set lo up
ip -n "${NS1}" link set "${VETH1}" up
ip -n "${NS2}" link set "${VETH2}" up

ip -n "${NS1}" addr add 10.200.1.1/24 dev "${VETH1}"
ip -n "${NS2}" addr add 10.200.1.2/24 dev "${VETH2}"
ip -n "${NS1}" -6 addr add fd00:1::1/64 dev "${VETH1}"
ip -n "${NS2}" -6 addr add fd00:1::2/64 dev "${VETH2}"

# Explicitly create clsact as requested by integration scenario
ip netns exec "${NS1}" tc qdisc add dev "${VETH1}" clsact 2>/dev/null || true

echo "[netns-test] start daemon in ${NS1} on ${VETH1}"
ip netns exec "${NS1}" \
    "${DAEMON_BIN}" -i "${VETH1}" -c "${CONFIG}" --debug \
    >"${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 40); do
    if grep -q "Ring buffer polling started" "${DAEMON_LOG}"; then
        break
    fi
    sleep 0.25
done

if ! grep -q "Ring buffer polling started" "${DAEMON_LOG}"; then
    echo "ERROR: daemon did not start BPF ring buffer" >&2
    tail -n 120 "${DAEMON_LOG}" || true
    exit 1
fi

# Capture IPv6 fragments with UDP as upper-layer protocol
# - IPv6 next header at offset 6 must be Fragment (44)
# - Fragment header next header (first byte after base IPv6 header) must be UDP (17)
echo "[netns-test] start tcpdump capture in ${NS2}"
ip netns exec "${NS2}" \
    tcpdump -i "${VETH2}" -nn -l \
    'ip6 and ip6[6] == 44 and ip6[40] == 17' \
    >"${TCPDUMP_LOG}" 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[netns-test] send one IPv6 QUIC-like UDP Initial datagram"
ip netns exec "${NS1}" python3 - <<'PY'
import socket

# QUIC-like Initial payload:
# first byte has Long Header bit + Initial type, version=1, length>20
payload = bytes([0x80, 0x00, 0x00, 0x00, 0x01]) + bytes(range(1, 96))

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.sendto(payload, ("fd00:1::2", 443))
sock.close()
PY

sleep 3

kill "${TCPDUMP_PID}" 2>/dev/null || true
wait "${TCPDUMP_PID}" 2>/dev/null || true
TCPDUMP_PID=""

EVENT_COUNT=$(grep -c "Received event type=8" "${DAEMON_LOG}" || true)
INJECT_COUNT=$(grep -c "\[QUIC FRAG\] Successfully sent" "${DAEMON_LOG}" || true)
FRAG_COUNT=$(grep -Ei -c "ip6|IP6" "${TCPDUMP_LOG}" || true)

echo "[netns-test] event_count=${EVENT_COUNT} inject_count=${INJECT_COUNT} frag_count=${FRAG_COUNT}"

if [[ "${EVENT_COUNT}" -lt 1 ]]; then
    echo "FAIL: no QUIC_FRAGMENT event observed" >&2
    tail -n 120 "${DAEMON_LOG}" || true
    exit 1
fi

if [[ "${INJECT_COUNT}" -lt 1 ]]; then
    echo "FAIL: injector did not report fragment injection" >&2
    tail -n 120 "${DAEMON_LOG}" || true
    exit 1
fi

if [[ "${FRAG_COUNT}" -lt 1 ]]; then
    echo "FAIL: tcpdump did not observe IPv6 UDP fragments" >&2
    cat "${TCPDUMP_LOG}" || true
    exit 1
fi

# No loop criterion: one generated packet should not recursively trigger many events.
# For a single test datagram we expect exactly one trigger.
if [[ "${EVENT_COUNT}" -ne 1 ]]; then
    echo "FAIL: expected exactly 1 QUIC_FRAGMENT event, got ${EVENT_COUNT} (possible loop or duplicate processing)" >&2
    grep "Received event type=8" "${DAEMON_LOG}" || true
    exit 1
fi

echo "PASS: netns integration test passed (event, injection, mark/no-loop)"
