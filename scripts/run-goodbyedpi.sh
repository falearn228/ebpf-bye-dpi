#!/bin/bash
# Скрипт для запуска GoodByeDPI с диагностикой

set -e

# Определяем интерфейс по умолчанию
DEFAULT_IFACE=$(ip route | grep default | head -1 | awk '{print $5}')
IFACE="${1:-$DEFAULT_IFACE}"
CONFIG="${2:-"s1 -o1 -Ar -f-1 -r1+s -At -As"}"

echo "=============================================="
echo "GoodByeDPI eBPF Launcher"
echo "=============================================="
echo ""
echo "Detected interfaces:"
ip -br addr show | grep -v "DOWN" | grep -v "lo "
echo ""
echo "Default route interface: $DEFAULT_IFACE"
echo "Using interface: $IFACE"
echo "Config: $CONFIG"
echo ""

# Проверяем права root
if [ "$EUID" -ne 0 ]; then 
    echo "⚠️  WARNING: Not running as root! Trying with sudo..."
    exec sudo "$0" "$@"
fi

# Проверяем, существует ли интерфейс
if ! ip link show "$IFACE" &>/dev/null; then
    echo "❌ ERROR: Interface $IFACE does not exist!"
    echo "Available interfaces:"
    ip -br addr show
    exit 1
fi

# Останавливаем предыдущие запуски
echo "Cleaning up previous TC filters..."
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true

# Проверяем наличие bpf объектов
BPF_OBJ="./target/release/build/goodbyedpi-daemon-*/out/goodbyedpi.bpf.o"
if [ ! -f $BPF_OBJ ]; then
    echo "❌ ERROR: BPF object not found at $BPF_OBJ"
    echo "Please build the project first: cargo build --release"
    exit 1
fi

echo "✓ BPF object found"

# Запускаем демон
echo ""
echo "=============================================="
echo "Starting GoodByeDPI daemon..."
echo "=============================================="
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Запускаем с отладкой
./target/release/goodbyedpi-daemon -i "$IFACE" -c "$CONFIG" --debug
