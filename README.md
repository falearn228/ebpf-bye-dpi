# GoodByeDPI eBPF

Реализация DPI (Deep Packet Inspection) обхода через eBPF с управлением на Rust.

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    USERSPACE (Rust)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Event        │  │ Raw Socket   │  │ Config       │  │
│  │ Processor    │  │ Injector     │  │ Parser       │  │
│  │ - Auto-logic │  │ (fake, OOB)  │  │ "s1 -o1..."  │  │
│  │ - Ring buf   │  │              │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘  │
└─────────┼─────────────────┼───────────────────────────┘
          │ mpsc channel    │ libbpf-rs
┌─────────▼─────────────────▼───────────────────────────┐
│                    eBPF KERNEL                          │
│  ┌─────────────┐    ┌───────────────┐    ┌──────────┐  │
│  │  TC Egress  │    │   TC Hook     │    │  TC      │  │
│  │  Detection  │───▶│  (libbpf-rs)  │    │  Ingress │  │
│  │  - Events   │    │  - attach     │    │  (auto)  │  │
│  │  - Ring buf │    │  - cleanup    │    └──────────┘  │
│  └─────────────┘    └───────────────┘                  │
│  ┌─────────────────────────────────────────────────┐  │
│  │ BPF Maps: conn_map, events (ringbuf), config_map │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Методы обхода DPI

| Аргумент | Значение          | Статус     | Описание                                           |
|----------|------------------|------------|----------------------------------------------------|
| `s1`     | `--split 1`       | ✅ Ready   | TCP split detection → event → userspace injection |
| `-o1`    | `--oob 1`         | ✅ Ready   | OOB (URG flag) injection via raw socket           |
| `-Ar`    | `--auto rst`      | ✅ Ready   | Auto-detect RST, retry with new strategy          |
| `-At`    | `--auto redirect` | ✅ Ready   | Auto-detect HTTP 301/302 redirect                 |
| `-f-1`   | `--fake -1`       | ✅ Ready   | Fake packet injection via raw socket              |
| `-r1+s`  | `--tlsrec 1+s`    | ✅ Ready   | TLS record split injection with proper headers    |
| `-r-2`   | `--tlsrec -2`     | ✅ Ready   | TLS record split relative to SNI end              |
| `-As`    | `--auto ssl`      | ✅ Ready   | Auto-detect SSL fatal alerts                      |
| `-g8`    | `--frag 8`        | ✅ Ready   | QUIC/UDP IP fragmentation via raw socket          |
| `-g16`   | `--frag 16`       | ✅ Ready   | QUIC/UDP IP fragmentation via raw socket          |



## Требования

- Linux kernel 5.8+ (для BPF CO-RE)
- clang 12+ с поддержкой BPF target
- bpftool
- Rust 1.75+
- libbpf-dev

## Сборка

```bash
# Установка зависимостей (Debian/Ubuntu)
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
    bpftool libelf-dev zlib1g-dev make

# Установка зависимостей (Arch Linux)
sudo pacman -Syu --needed clang llvm libbpf linux-headers bpftool libelf zlib make

# Сборка проекта
cargo build --release
```

### Быстрая установка через скрипт

```bash
# Из корня репозитория:
./scripts/install.sh

# Если зависимости уже установлены:
./scripts/install.sh --no-deps

# Запуск daemon сразу после установки:
./scripts/install.sh --run --iface eth0 --config "s1 -o1 -Ar" --debug
```

## Использование

### Запуск демона

```bash
# Базовый режим с разбиением и OOB
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1"

# С инжекцией фейк-пакетов
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -f-1"

# Расширенный режим с авто-логикой
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -Ar -f-1 -r1+s -At -As"

# TLSREC c отрицательным offset (от конца SNI)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -r-2 -Ar"

# Режим отладки
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --debug

# Включить eBPF trace_printk для диагностики (по умолчанию выключен)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --bpf-printk

# YouTube/QUIC режим (с IP фрагментацией)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 -Ar -At -As"

# Ограничить инъекции только нужными портами (Stage 2: Port filters)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 --filter-tcp=443,2053 --filter-udp=443,1024-65535"

# Zapret-like алиасы для глобальных port filters
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 --wf-tcp=80,443,1024-65535 --wf-udp=443,50000-50100"

# Таргетинг по host/ip спискам (Stage 3: Host/IP lists)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 --hostlist=googlevideo.com,*.youtube.com --hostlist-exclude=music.youtube.com --ipset=142.250.0.0/15 --ipset-exclude=142.250.10.10"

# Fake profiles из файлов (Stage 4: Repeats + fake profiles)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -f-1 --fake-quic=/etc/goodbyedpi/fake-quic.bin --fake-discord=/etc/goodbyedpi/fake-discord.bin --fake-stun=/etc/goodbyedpi/fake-stun.bin --new --action=fake --ports=443 --repeats=3"

# Zapret-like алиасы для fake profiles
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "--dpi-desync=fake --dpi-desync-fake-quic=/etc/goodbyedpi/fake-quic.bin --dpi-desync-fake-discord=/etc/goodbyedpi/fake-discord.bin --dpi-desync-fake-stun=/etc/goodbyedpi/fake-stun.bin --dpi-desync-repeats=6"

# Hostfakesplit host override + unknown UDP fallback profile
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=www.google.com --dpi-desync-fake-unknown-udp=/etc/goodbyedpi/fake-unknown-udp.bin"

# Userspace low-level desync knobs
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "--dpi-desync=fake --dpi-desync-autottl=2 --dpi-desync-cutoff=n2 --dpi-desync-any-protocol=1 --ip-id=zero"

# Импорт profile string из файла (многострочный zapret/winws-like формат)
sudo ./target/release/goodbyedpi-daemon -i eth0 --config-file /etc/goodbyedpi/profile.txt

# Stage 5: L7 filters (минимум) включены автоматически
# Детектируются сигнатуры STUN/Discord по первым байтам payload для выбора fake-профиля.

# Stage 7: явный L7-фильтр + алиас доменного списка
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -f-1 --filter-l7=discord,stun --hostlist-domains=discord.media,*.discord.gg"

# Экспорт метрик Prometheus (по умолчанию http://127.0.0.1:9877/metrics)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --metrics-bind 0.0.0.0:9877

# Отключить endpoint метрик
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --no-metrics
```

### Zapret Mapping

Короткое соответствие `zapret args -> internal config`:

| Arg | Internal mapping |
| --- | --- |
| `--wf-tcp`, `--wf-udp` | Алиасы `--filter-tcp`, `--filter-udp` |
| `--dpi-desync=fake` | `dpi_desync_actions += Fake`, default `fake_offset = -1` |
| `--dpi-desync=split` | `dpi_desync_actions += Split`, default `split_pos = 1` |
| `--dpi-desync=disorder` | `dpi_desync_actions += Disorder`, `use_disorder = true` |
| `--dpi-desync=hostfakesplit` | `Split + Fake`, default `split_pos = 1`, `fake_offset = -1` |
| `--dpi-desync-fake-quic`, `--dpi-desync-fake-discord`, `--dpi-desync-fake-stun` | Алиасы существующих `--fake-*` file profiles |
| `--dpi-desync-hostfakesplit-mod=host=<domain>` | Генерация fake HTTP payload с нужным `Host` |
| `--dpi-desync-fake-unknown-udp=<file>` | Fallback payload для unknown UDP/L7 |
| `--ip-id=zero` | На userspace injection path IPv4 ID ставится в `0` |
| `--dpi-desync-autottl=N` | TTL/Hop Limit для инжекции становится `64 - N`, минимум `1` |
| `--dpi-desync-cutoff=nN` | Лимит инъекций `per-connection/per-action` |
| `--dpi-desync-any-protocol=1` | Расширяет `fake-unknown-udp` fallback за пределы `dst_port=443` |
| `--new ...` | Добавляет rule-engine section |

Полная таблица и ограничения: `docs/DEVELOPMENT.md`.

Практическая совместимость с profile strings:

- `--config-file <path>` загружает профиль из файла и затем дополняет его аргументами из `-c` при наличии.
- Парсер понимает многострочный ввод, quoted values, а также line continuation через `^` и `\`.
- Строки-комментарии с префиксами `#`, `;`, `//`, `::`, `rem` игнорируются.

### Метрики

Демон экспортирует `/metrics` в формате Prometheus (text exposition):

- `goodbyedpi_packets_total`
- `goodbyedpi_packets_tcp`
- `goodbyedpi_packets_udp`
- `goodbyedpi_packets_tls`
- `goodbyedpi_packets_quic`
- `goodbyedpi_events_sent`
- `goodbyedpi_errors`
- `goodbyedpi_packets_ipv6`
- `goodbyedpi_packets_http`
- `goodbyedpi_packets_modified`

### CLI утилита

```bash
# Запуск через CLI
goodbyedpi -i eth0 -c "s1 -o1 -Ar" --daemon

# Проверка статуса
goodbyedpi --status

# Остановка
goodbyedpi --stop
```

## Как это работает

### 1. Загрузка eBPF (libbpf-rs)

```rust
// Dedicated BPF thread
std::thread::spawn(|| {
    let mut obj = ObjectBuilder::default()
        .open_file("goodbyedpi.bpf.o")?
        .load()?;
    
    // Attach TC programs
    TcHook::new(prog_fd)
        .attach_point(TC_EGRESS)
        .attach()?;
    
    // Start ring buffer polling
    RingBufferBuilder::new()
        .add(events_map, callback)
        .build()?
        .poll()?;
});
```

### 2. Обработка событий (Ring Buffer)

eBPF программы отправляют события через ring buffer:
- **FAKE_TRIGGERED** - Требуется инжекция пакета
- **RST_DETECTED** - Получен RST (auto-logic)
- **REDIRECT_DETECTED** - HTTP 301/302 (auto-logic)
- **SSL_ERROR_DETECTED** - SSL alert (auto-logic)
- **DISORDER_TRIGGERED** - Packet disorder

Userspace получает события через `tokio::sync::mpsc` канал и обрабатывает в async контексте.

### 3. Инжекция пакетов (Raw Socket)

```rust
// Создание raw socket
let injector = RawInjector::new()?; // Requires CAP_NET_RAW

// Инжекция fake RST
injector.inject_fake_packet(
    src_ip, dst_ip, src_port, dst_port,
    seq, ack, 0x04, // RST flag
    None,
)?;
```

## Структура проекта

```
.
├── ebpf/                    # eBPF программы (C + libbpf)
│   └── src/
│       ├── goodbyedpi.bpf.c   # Основной eBPF код (TC egress/ingress)
│       └── Makefile
├── daemon/                  # Rust daemon (userspace)
│   └── src/
│       ├── main.rs          # Точка входа, async tokio runtime
│       ├── bpf.rs           # BPF lifecycle (libbpf-rs) + ring buffer
│       ├── config.rs        # Парсер конфигурации DPI
│       ├── injector.rs      # Raw socket инжектор пакетов
│       ├── ringbuf.rs       # Обработчик событий ring buffer
│       ├── state.rs         # Управление состоянием соединений
│       └── tc.rs            # TC cleanup функции
├── cli/                     # CLI утилита
│   └── src/main.rs
├── proto/                   # Общие структуры
│   └── src/lib.rs           # Config, Event, ConnKey, ConnState
├── docs/
│   ├── DEVELOPMENT.md       # Runbook для разработки и эксплуатации
│   └── STATE_MACHINE.md     # Формальная спецификация state machine
└── systemd/                 # Файлы systemd
    └── goodbyedpi.service
```

## Документация разработчика

- `docs/DEVELOPMENT.md` — практический runbook: сборка, запуск, диагностика, откат, планы.
- `docs/STATE_MACHINE.md` — спецификация state machine: переходы `STAGE_*`, `EVENT_*`, таймауты, success/fail semantics.

## Диагностика и устранение неполадок

### Почему YouTube может не работать

1. **YouTube использует QUIC (HTTP/3)** — UDP 443 вместо TCP
   - Решение: используйте флаг `-g8` для IP-фрагментации QUIC
   - Или отключите QUIC в браузере: `chrome://flags/#enable-quic`

2. **TLS 1.3 + ECH (Encrypted Client Hello)** — SNI полностью зашифрован
   - DPI может блокировать по IP-адресу Google/YouTube
   - Попробуйте использовать комбинацию техник: `s1 -o1 -g8 -Ar`

3. **Проверьте, видит ли BPF трафик:**
   ```bash
   # Запустите с флагом --debug и проверьте логи
   sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8" --debug
   
   # Должны появляться сообщения:
   # [GoodByeDPI] TLS detected
   # [GoodByeDPI] QUIC detected
   # [QUIC FRAG] ...
   ```

4. **Проверьте статистику BPF:**
   ```bash
   sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/stats_map
   ```

### Отладка

```bash
# Проверить загружены ли BPF программы
sudo bpftool prog list | grep dpi

# Проверить TC фильтры
sudo tc filter show dev eth0 egress
sudo tc filter show dev eth0 ingress

# Мониторинг событий BPF
sudo cat /sys/kernel/debug/tracing/trace_pipe
или
sudo cat /sys/kernel/tracing/trace_pipe

# Проверить pinned maps
ls -la /sys/fs/bpf/goodbyedpi/
```

## Требования к окружению

- **ОС:** Linux kernel 5.8+
- **Привилегии:** root или capabilities (CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW)
- **BTF:** Ядро должно быть скомпилировано с CONFIG_DEBUG_INFO_BTF
- **BPF fs:** Должен быть смонтирован /sys/fs/bpf

## Безопасность

- Код требует **root** привилегий для загрузки eBPF программ
- Используются capabilities: CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW
- В systemd service включены hardening опции
- eBPF программы используют свой verifier для безопасности

## Проблемы
- Бывает не запускается демон на WSL2 (Ubuntu) из-за особенностей WSL-вского ядра

## Лицензия

GPL-2.0
