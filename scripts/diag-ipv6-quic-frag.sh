#!/bin/bash
# Runtime-диагностика IPv6 QUIC fragmentation через tcpdump

set -euo pipefail

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    cat <<'EOF'
Usage:
  ./scripts/diag-ipv6-quic-frag.sh [iface] [duration_sec]

Examples:
  ./scripts/diag-ipv6-quic-frag.sh
  ./scripts/diag-ipv6-quic-frag.sh eth0 30

What it checks:
  - IPv6 Fragment Header (Next Header = 44)
  - UDP inside Fragment Header (fragment next header = 17)
EOF
    exit 0
fi

if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

if ! command -v tcpdump >/dev/null 2>&1; then
    echo "ERROR: tcpdump not found. Install tcpdump and retry."
    exit 1
fi

DEFAULT_IFACE="$(ip -6 route show default 2>/dev/null | awk 'NR==1 {print $5}')"
if [ -z "$DEFAULT_IFACE" ]; then
    DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')"
fi

IFACE="${1:-$DEFAULT_IFACE}"
DURATION="${2:-20}"

if [ -z "$IFACE" ]; then
    echo "ERROR: unable to detect interface automatically. Pass iface explicitly."
    exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "ERROR: interface '$IFACE' does not exist."
    exit 1
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [ "$DURATION" -le 0 ]; then
    echo "ERROR: duration must be a positive integer (seconds)."
    exit 1
fi

FILTER='ip6 and ip6[6] == 44 and ip6[40] == 17'
TMP_LOG="$(mktemp /tmp/goodbyedpi-ipv6-frag.XXXXXX.log)"
trap 'rm -f "$TMP_LOG"' EXIT

echo "=============================================="
echo "IPv6 QUIC Fragmentation Runtime Diagnostic"
echo "=============================================="
echo "Interface: $IFACE"
echo "Duration: ${DURATION}s"
echo "tcpdump filter: $FILTER"
echo ""
echo "Before/while capture, ensure daemon runs with fragmentation enabled, e.g.:"
echo "  ./target/release/goodbyedpi-daemon -i $IFACE -c \"s1 -o1 -g8\" --debug"
echo ""
echo "Generate IPv6 QUIC traffic in another terminal (example):"
echo "  curl --http3-only -6 -I https://cloudflare-quic.com/"
echo ""
echo "Capturing..."
echo ""

set +e
timeout "${DURATION}" tcpdump -i "$IFACE" -nn -vv -l "$FILTER" 2>&1 | tee "$TMP_LOG"
TCPDUMP_EXIT=${PIPESTATUS[0]}
set -e

if [ "$TCPDUMP_EXIT" -ne 0 ] && [ "$TCPDUMP_EXIT" -ne 124 ]; then
    echo ""
    echo "ERROR: tcpdump exited with code $TCPDUMP_EXIT"
    exit "$TCPDUMP_EXIT"
fi

MATCHES="$(grep -c 'IP6' "$TMP_LOG" || true)"

echo ""
echo "=============================================="
echo "Diagnostic result"
echo "=============================================="
echo "Matched IPv6 UDP fragments: $MATCHES"

if [ "$MATCHES" -gt 0 ]; then
    echo "PASS: IPv6 fragmentation traffic observed (Fragment Header 44 + UDP next header)."
else
    echo "FAIL: no IPv6 UDP fragments observed."
    echo "Hint: verify daemon config includes -g8/-g16 and generate IPv6 HTTP/3 traffic."
fi

