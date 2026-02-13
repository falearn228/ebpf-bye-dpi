#!/bin/bash
echo "=== TCP Test ==="

# Очищаем stats перед тестом
sudo rm -f /tmp/test_log

# Делаем простой HTTP запрос (не HTTPS) - должен triggers HTTP detection
curl -s http://httpbin.org/get > /dev/null &

sleep 3

# Делаем HTTPS запрос
curl -s https://google.com > /dev/null &

sleep 3

echo "Done"
