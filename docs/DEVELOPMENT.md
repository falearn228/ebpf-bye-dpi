# GoodByeDPI eBPF: Development Runbook

Этот документ предназначен для разработки, отладки и безопасного выката изменений.

См. также: `docs/STATE_MACHINE.md` (формальная спецификация переходов, таймаутов и критериев успеха/фейла).

## 1. Быстрый старт

```bash
cargo build --release
cargo test --workspace
```

Запуск демона:

```bash
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -Ar"
```

## 2. Конфиг и семантика

Ключевые поля:

- `split_pos`: `-1` отключено, `>0` позиция split
- `oob_pos`: `-1` отключено, `>0` позиция OOB
- `fake_offset`: `0` отключено, любое другое значение включает fake
- `tlsrec_pos`: `-1` отключено, `0` split в начале SNI, `>0` split от начала SNI, `<-1` split от конца SNI

Примеры:

```bash
# split в начале SNI
-c "s1 -r0"

# split на 1 байт после начала SNI
-c "s1 -r1+s"

# split за 2 байта до конца SNI
-c "s1 -r-2"
```

## 3. Диагностика

Проверка BPF/TC:

```bash
sudo bpftool prog list | grep dpi
sudo tc filter show dev eth0 egress
sudo tc filter show dev eth0 ingress
```

Логи BPF:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Отдельная runtime-диагностика IPv6 QUIC fragmentation:

```bash
# Слушать IPv6 Fragment Header (NH=44) с UDP внутри fragment header
sudo ./scripts/diag-ipv6-quic-frag.sh eth0 30
```

Скрипт считает количество увиденных IPv6 UDP fragments и выводит `PASS/FAIL`.

Интеграционный runtime-тест в `ip netns` (event -> inject -> no-loop по mark):

```bash
# Запускает изолированный стенд: netns + veth + tc clsact + tcpdump
sudo ./scripts/test-netns-integration.sh

# Через cargo-обёртку (ignored test)
sudo GBD_RUN_NETNS_TESTS=1 cargo test -p goodbyedpi-daemon --test netns_integration -- --ignored --nocapture
```

Pinned maps:

```bash
ls -la /sys/fs/bpf/goodbyedpi/
sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/config_map
sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/stats_map
```

## 4. Проверка перед merge

```bash
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings
cargo test --workspace
```

Минимум вручную:

- убедиться, что `SPLIT/OOB/FAKE/TLSREC/DISORDER/QUIC FRAG` корректно генерируют events
- проверить отсутствие кольцевых инъекций (`skb->mark == USERSPACE_MARK`)
- проверить, что при отключенных техниках трафик проходит без деградации

## 5. Релиз и откат

Выкат:

1. Собрать release бинарники.
2. Перезапустить daemon на целевом интерфейсе.
3. Проверить `stats_map` и события ring buffer.

Откат:

1. Остановить daemon.
2. Выполнить `tc` cleanup (или перезапуск службы).
3. Вернуть предыдущий бинарник и конфигурацию.

## 6. Известные операционные риски

- Изменения в eBPF требуют проверки на целевом kernel/BTF.
- При агрессивных техниках (`disorder`, `frag`) возможны деградации на части сетей.
- Любые изменения формата `Config/Event` требуют синхронного обновления C и Rust структур.

## 7. Roadmap: zapret-like rules

Цель: приблизить гибкость конфигурации к профилям zapret/winws без слома текущего `-c` синтаксиса.

### Этап 1: Rule engine v1 (база)

- Добавить список правил (аналог секций `--new`) с полями:
- `proto` (`tcp`/`udp`)
- `ports` (списки и диапазоны)
- `action` (split/oob/fake/tlsrec/disorder/frag)
- `repeats` (повторы инъекции)
- Файлы: `daemon/src/config.rs`, `proto/src/lib.rs`, `daemon/src/ringbuf.rs`

### Этап 2: Port filters

- Поддержка `filter-tcp/filter-udp` с диапазонами (`443,2053,1024-65535`)
- Применение фильтра до инъекции

### Этап 3: Host/IP lists

- Поддержка:
- `hostlist`
- `hostlist-exclude`
- `ipset`
- `ipset-exclude`
- Матчинг по SNI/HTTP Host и dst IP
- Новый модуль правил: `daemon/src/rules.rs`

### Этап 4: Repeats + fake profiles

- `repeats` для fake/disorder/quic-frag
- Загрузка fake payload из файлов (`fake-quic`, `fake-discord`, `fake-stun`)
- Файлы: `daemon/src/injector.rs`, `daemon/src/ringbuf.rs`

### Этап 5: L7 filters (минимум)

- Легковесный детект `stun/discord` по сигнатурам первых байт
- Реализация в userspace или через event-метки из eBPF

### Этап 6: Опционально (v2)

- `fooling ts/md5sig`
- `ip-id zero`
- `autottl`
- `cutoff`

### Приоритет реализации

1. Этапы 1+2 (максимальная польза при минимальном риске)
2. Этап 3 (таргетинг по спискам)
3. Этап 4 (усиление устойчивости обхода)
4. Этапы 5+6 после стабилизации
