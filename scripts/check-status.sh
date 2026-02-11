#!/bin/bash
# Скрипт для проверки статуса GoodByeDPI

if [ "$EUID" -ne 0 ]; then 
    exec sudo "$0" "$@"
fi

echo "=============================================="
echo "GoodByeDPI Status Check"
echo "=============================================="
echo ""

# Показываем активные интерфейсы
echo "Active network interfaces:"
ip -br addr show | grep -v "DOWN"
echo ""

# Проверяем TC фильтры на всех активных интерфейсах
echo "TC Filters:"
for iface in $(ip -br link show | grep -v "DOWN" | grep -v "lo " | awk '{print $1}'); do
    echo ""
    echo "--- Interface: $iface ---"
    tc filter show dev "$iface" egress 2>/dev/null || echo "  No egress filters"
    tc filter show dev "$iface" ingress 2>/dev/null || echo "  No ingress filters"
done

echo ""
echo "=============================================="
echo "BPF Programs:"
echo "=============================================="
bpftool prog list 2>/dev/null | head -30 || echo "bpftool not available"

echo ""
echo "=============================================="
echo "BPF Maps:"
echo "=============================================="
bpftool map list 2>/dev/null | head -20 || echo "bpftool not available"

echo ""
echo "=============================================="
echo "GoodByeDPI Process:"
echo "=============================================="
ps aux | grep goodbyedpi-daemon | grep -v grep || echo "Not running"
