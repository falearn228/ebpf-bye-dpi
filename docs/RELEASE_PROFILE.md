# Рабочий zapret-профиль для релиза

Этот профиль зафиксирован как production target для текущего релиза:

```bash
sudo ./target/release/goodbyedpi-daemon \
  -i <iface> \
  --config-file profiles/provider-working-zapret.txt \
  --debug
```

## Требуемые файлы

Профиль использует Windows paths из zapret 1.6.x. Daemon автоматически маппит их на локальные файлы:

- `C:\Games\zapret.1.6.2\lists\<file>` -> `lists/<file>`
- `C:\Games\zapret.1.6.2\bin\<file>` -> `bin/<file>`

Обязательные файлы:

- `lists/list-general.txt`
- `lists/list-google.txt`
- `lists/list-exclude.txt`
- `lists/ipset-all.txt`
- `lists/ipset-exclude.txt`
- `bin/quic_initial_www_google_com.bin`

Отсутствующие `*-user.txt` списки считаются пустыми.

## Что покрывает профиль

- UDP 443 QUIC fake с repeats
- UDP Discord/STUN fake по L7 на портах `19294-19344,50000-50100`
- TCP Discord media `hostfakesplit`
- TCP Google list `hostfakesplit` с `ip-id=zero`
- TCP general hostlist `hostfakesplit`
- UDP/TCP ipset branches для port `12`
- `cutoff`, `any-protocol`, `fooling=ts[,md5sig]`

## Runtime smoke

Проверять на целевом Linux kernel/BTF, не на WSL2.

1. Собрать release:

```bash
cargo build --release
```

2. Запустить daemon:

```bash
sudo ./target/release/goodbyedpi-daemon \
  -i <iface> \
  --config-file profiles/provider-working-zapret.txt \
  --debug
```

3. Проверить attach и maps:

```bash
sudo tc filter show dev <iface> egress
sudo tc filter show dev <iface> ingress
ls -la /sys/fs/bpf/goodbyedpi/
sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/stats_map
curl -s http://127.0.0.1:9877/metrics | head
```

4. Проверить трафик:

- сайт из `list-general.txt`
- сайт из `list-google.txt`
- QUIC/YouTube сценарий
- Discord voice/media сценарий
- исключения из `list-exclude.txt`

5. Остановить daemon и проверить cleanup:

```bash
sudo tc filter show dev <iface> egress
sudo tc filter show dev <iface> ingress
```

Ожидание: нет оставленных фильтров GoodByeDPI, daemon shutdown без errors.

## Debug hints

При `--debug` section matching логируется строкой `[SECTION]`. Если трафик не обрабатывается, сначала проверить:

- порт попадает в нужную section;
- host/ip не исключен списком exclude;
- fake payload file найден;
- BPF видит трафик на выбранном interface.
