#!/bin/bash
# Скрипт для просмотра логов BPF программы

if [ "$EUID" -ne 0 ]; then 
    exec sudo "$0" "$@"
fi

echo "=============================================="
echo "BPF Trace Logs (trace_pipe)"
echo "Press Ctrl+C to exit"
echo "=============================================="
echo ""

# Проверяем, смонтирован ли debugfs
if [ ! -d /sys/kernel/debug ]; then
    echo "Mounting debugfs..."
    mount -t debugfs none /sys/kernel/debug
fi

# Показываем логи
cat /sys/kernel/debug/tracing/trace_pipe
