# GoodByeDPI eBPF - AI Agent Guide

Этот документ содержит важную информацию для AI агентов, работающих с проектом GoodByeDPI eBPF.

## Обзор проекта

GoodByeDPI eBPF — это реализация обхода DPI (Deep Packet Inspection) через eBPF с управлением на Rust. Проект предназначен для Linux и использует современные eBPF возможности ядра.

**Основное назначение:** Обход систем глубокого анализа пакетов (DPI), используемых для блокировки интернет-ресурсов.

**Язык проекта:** Документация и комментарии в коде преимущественно на русском языке.

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    USERSPACE (Rust)                     │
│  ┌──────────────┐  ┌──────────────────────────────┐  │
│  │ Auto-Logic   │  │ Raw Socket Injector          │  │
│  │ -Ar -At -As  │  │  - TCP fake/split/OOB        │  │
│  │ State machine│  │  - UDP fragment (IP_HDRINCL) │  │
│  └──────┬───────┘  └──────────┬───────────────────┘  │
│         │                     │                       │
│  ┌──────▼───────┐  ┌───────────▼──────────┐         │
│  │ Config       │  │ Event Processor      │         │
│  │ Parser       │  │ - FAKE/SPLIT/TLSREC  │         │
│  │ "s1 -o1..."  │  │ - QUIC_FRAGMENT      │         │
│  └──────────────┘  └───────────┬──────────┘         │
└────────────────────────────────┼──────────────────────┘
                                 │ ring buffer
┌────────────────────────────────▼──────────────────────┐
│                    eBPF KERNEL                          │
│  ┌─────────────┐    ┌───────────────┐    ┌──────────┐  │
│  │  TC Egress  │    │   TC (mod)    │    │  TC      │  │
│  │  Detection  │───▶│  - split      │    │  Ingress │  │
│  │  - fake trig│    │  - tlsrec     │    │  (auto)  │  │
│  │  - QUIC frag│    │  - disorder   │    └──────────┘  │
│  │  - events   │    │  - OOB mark   │                  │
│  └─────────────┘    └───────────────┘                  │
│  ┌─────────────────────────────────────────────────┐  │
│  │ BPF Maps: conn_map, sni_cache, auto_state        │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Структура проекта

```
.
├── ebpf/                    # eBPF программы (C + libbpf)
│   └── src/
│       ├── goodbyedpi.bpf.c # Основной eBPF код (TC egress/ingress)
│       ├── vmlinux.h        # Генерируется из BTF ядра
│       └── Makefile         # Сборка eBPF объектов
├── daemon/                  # Rust демон (userspace)
│   ├── src/
│   │   ├── main.rs          # Точка входа, async tokio runtime
│   │   ├── bpf.rs           # Загрузка и управление BPF программами
│   │   ├── config.rs        # Парсер конфигурации DPI
│   │   ├── injector.rs      # Raw socket инжектор пакетов
│   │   ├── state.rs         # Управление состоянием соединений
│   │   └── tc.rs            # TC (Traffic Control) helper функции
│   └── build.rs             # Build script для компиляции eBPF
├── cli/                     # CLI утилита
│   └── src/main.rs
├── proto/                   # Общие структуры (Rust/C interop)
│   └── src/lib.rs           # Config, Event, ConnKey, ConnState
├── systemd/                 # Файлы systemd
│   └── goodbyedpi.service
├── scripts/                 # Вспомогательные скрипты
│   ├── check-status.sh      # Проверка статуса
│   ├── run-goodbyedpi.sh    # Запуск с диагностикой
│   └── trace-logs.sh        # Просмотр логов BPF
├── docs/
│   └── DEVELOPMENT.md       # Документация для разработчиков
└── .github/workflows/ci.yml # CI/CD конфигурация
```

## Технологический стек

### Ядро (eBPF)
- **Язык:** C (с ограничениями eBPF)
- **Фреймворк:** libbpf
- **Тип программ:** TC (Traffic Control) clsact
- **Требования:**
  - Linux kernel 5.8+ (для BPF CO-RE)
  - CONFIG_DEBUG_INFO_BTF=y
  - clang 12+ с поддержкой BPF target
  - bpftool
  - libbpf-dev

### Userspace (Rust)
- **Версия:** Rust 1.75+
- **Async runtime:** Tokio
- **Основные crates:**
  - `libbpf-rs` / `libbpf-sys` — взаимодействие с eBPF
  - `nix` — низкоуровневые системные вызовы
  - `clap` — CLI аргументы
  - `anyhow` / `thiserror` — обработка ошибок
  - `serde` — сериализация

## Методы обхода DPI

| Аргумент | Значение          | Что делает                                            |
| -------- | ----------------- | ----------------------------------------------------- |
| `s1`     | `--split 1`       | Разбить TCP запрос на позиции 1                       |
| `-o1`    | `--oob 1`         | OOB (out-of-band) данные на позиции 1                 |
| `-Ar`    | `--auto rst`      | Автоматика при таймауте/RST                           |
| `-At`    | `--auto redirect` | Автоматика при HTTP redirect                          |
| `-f-1`   | `--fake -1`       | Фейк-пакет, offset = -1 (от конца пакета)             |
| `-r1+s`  | `--tlsrec 1+s`    | TLS record split на позиции 1+SNI offset              |
| `-As`    | `--auto ssl`      | Автоматика при SSL ошибке                             |
| `-g8`    | `--frag 8`        | IP фрагментация QUIC/UDP пакетов (8 байт фрагменты)   |
| `-g16`   | `--frag 16`       | IP фрагментация QUIC/UDP пакетов (16 байт фрагменты)  |
| `-d`     | `--disorder`      | Отправка пакетов в неправильном порядке (disorder)    |

### IP Fragmentation для QUIC/UDP (Phase 3)

Реализована фрагментация UDP/QUIC пакетов на уровне IP для обхода DPI:

**Как работает:**
1. eBPF детектирует QUIC Initial пакеты (UDP порт 443)
2. Отправляет событие `QUIC_FRAGMENT_TRIGGERED` в userspace
3. Userspace разбивает UDP payload на фрагменты по 8 байт (или указанный размер)
4. Каждый фрагмент отправляется как отдельный IP-пакет с:
   - IP MF (More Fragments) флагом на всех фрагментах кроме последнего
   - IP Fragment Offset в 8-байтных единицах
   - Собственным IP заголовком (IP_HDRINCL)

**Детекция QUIC Initial:**
- Проверяется Long Header (первый бит = 1)
- Проверяется packet type = 0 (Initial)
- Проверяется версия: QUIC v1 (0x00000001), v2 (0x6b3343cf), draft 29-32
- Это снижает ложные срабатывания по сравнению с простой проверкой первого бита

**Зачем:**
- DPI системы часто не могут корректно реассемблировать фрагментированные пакеты
- YouTube и другие сервисы используют QUIC (HTTP/3) поверх UDP
- Фрагментация на уровне IP прозрачна для приложений

**Поведение без фрагментации:**
- Если QUIC пакет детектирован, но фрагментация выключена, пакет пропускается
- Мы НЕ дропаем QUIC пакеты принудительно, чтобы не ломать HTTP/3 для нормальных сайтов
- Для форсированного fallback на TCP используйте настройки браузера (chrome://flags/#enable-quic)

**Использование:**
```bash
# Базовый режим (8-байтные фрагменты)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8"

# YouTube/QUIC режим с авто-логикой
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 -Ar -At -As"

# Кастомный размер фрагментов (например, 16 байт)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -g16"
```

### Packet Disorder (нарушение порядка пакетов)

Техника отправки TCP пакетов в неправильном порядке для обхода DPI:

**Как работает:**
1. eBPF детектирует HTTP/HTTPS пакеты
2. При включённом disorder (`-d`), eBPF отправляет событие в userspace
3. Userspace разбивает payload на две части
4. Сначала отправляется вторая часть (с более высоким sequence number)
5. Затем отправляется первая часть (с базовым sequence number)
6. DPI система видит out-of-order пакеты и может не обработать их корректно
7. TCP стек получателя корректно переупорядочивает пакеты

**Зачем:**
- DPI системы часто не умеют корректно обрабатывать out-of-order пакеты
- Нарушение порядка запутывает эвристические анализаторы
- Работает на уровне TCP, прозрачно для приложений

**Использование:**
```bash
# Базовый режим disorder
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -d"

# Комбинированный режим с split и disorder
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -d -Ar"

# Расширенный режим со всеми техниками
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -d -f-1 -Ar -At -As"
```

## Сборка

### Зависимости (Debian/Ubuntu)

```bash
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool \
    libelf-dev \
    zlib1g-dev \
    make
```

### Команды сборки

```bash
# Полная сборка (включая eBPF)
cargo build --release

# Сборка отдельных компонентов
cargo build -p goodbyedpi-daemon --release
cargo build -p goodbyedpi --release
cargo build -p goodbyedpi-proto --release

# Ручная сборка eBPF
cd ebpf/src && make clean && make all
```

### Процесс сборки

1. `daemon/build.rs` запускает `make` в `ebpf/src/`
2. Makefile компилирует `goodbyedpi.bpf.c` в BPF объект
3. bpftool генерирует skeleton (или используется stub)
4. Cargo собирает Rust код

## Тестирование

```bash
# Запуск всех тестов
cargo test --workspace

# Тесты с выводом
cargo test -- --nocapture

# Тесты отдельного пакета
cargo test -p goodbyedpi-daemon
cargo test -p goodbyedpi-proto

# Тесты конфигурации
cargo test -p goodbyedpi-daemon config::tests
```

## Стиль кода

### Rust
- Использовать `cargo fmt` для форматирования
- Использовать `cargo clippy` для линтинга (`-D warnings` в CI)
- Обработка ошибок через `anyhow::Context` для контекста
- Предпочитать `?` оператор вместо `match` для ошибок

### C/eBPF
- Отступы: 4 пробела
- Функции: `static __always_inline` для хелперов
- Префиксы для приватных функций
- Комментарии на русском для сложной логики

### Формат коммитов (Conventional Commits)
```
type(scope): description

Types: feat, fix, docs, style, refactor, test, chore

Пример:
feat(config): add support for multiple OOB positions
```

## Запуск и использование

### Демон

```bash
# Базовый режим
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1"

# Расширенный режим с авто-логикой
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -Ar -f-1 -r1+s -At -As"

# Режим отладки
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --debug

# YouTube/QUIC режим
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 -Ar -At -As"

# Режим с packet disorder
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -d -Ar -At -As"
```

### CLI

```bash
# Запуск через CLI
goodbyedpi -i eth0 -c "s1 -o1 -Ar" --daemon

# Проверка статуса
goodbyedpi --status

# Остановка
goodbyedpi --stop
```

## Отладка

### Проверка загруженных программ
```bash
sudo bpftool prog list | grep dpi
```

### Проверка TC фильтров
```bash
sudo tc filter show dev eth0 egress
sudo tc filter show dev eth0 ingress
```

### Мониторинг событий BPF
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# или
./scripts/trace-logs.sh
```

### Проверка pinned maps
```bash
ls -la /sys/fs/bpf/goodbyedpi/
sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/config_map
sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/stats_map
```

### Скрипты
```bash
./scripts/check-status.sh    # Проверка статуса
./scripts/run-goodbyedpi.sh  # Запуск с диагностикой
./scripts/trace-logs.sh      # Просмотр логов
```

## Особенности реализации

### BPF Maps

| Map | Type | Назначение |
|-----|------|------------|
| `config_map` | hash | Конфигурация DPI (split_pos, oob_pos, и т.д.) |
| `conn_map` | hash | Состояние соединений (stage, last_seq, flags) |
| `events` | ringbuf | События в userspace (fake, RST, redirect, SSL error) |
| `sni_cache` | lru_hash | Кэш SNI для быстрого поиска |
| `stats_map` | array | Статистика пакетов |

### Протокол userspace <-> kernel

**Event types:**
- `1` = FAKE_TRIGGERED
- `2` = RST_DETECTED
- `3` = REDIRECT_DETECTED
- `4` = SSL_ERROR_DETECTED
- `5` = DISORDER_TRIGGERED
- `6` = SPLIT_TRIGGERED
- `7` = TLSREC_TRIGGERED
- `8` = QUIC_FRAGMENT_TRIGGERED

**Stages:**
- `0` = INIT
- `1` = SPLIT
- `2` = OOB
- `3` = FAKE_SENT
- `4` = TLSREC
- `5` = DISORDER

### Важные константы

```c
#define USERSPACE_MARK 0xD0F  // Маркер для пакетов из userspace
#define FLAG_DISORDER  0xFE   // Специальный флаг для DISORDER
#define FLAG_QUIC_FRAG 0xFD   // Специальный флаг для QUIC fragmentation
#define FLAG_TLS_SPLIT 0xFF   // Специальный флаг для TLS split
```

## Требования к окружению

- **ОС:** Linux kernel 5.8+
- **Привилегии:** root или capabilities (CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW)
- **BTF:** Ядро должно быть скомпилировано с CONFIG_DEBUG_INFO_BTF
- **BPF fs:** Должен быть смонтирован /sys/fs/bpf

## Безопасность

- Код требует root-привилегий для загрузки eBPF программ
- Используются capabilities: CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW
- В systemd service включены hardening опции
- eBPF программы используют verifier для безопасности

## Известные ограничения

- Требуется ядро с BTF поддержкой (5.8+)
- IPv6 поддержка реализована, но требует тестирования
- Некоторые техники могут не работать со всеми DPI системами
- YouTube/QUIC требует специальной конфигурации (`-g8`)

## Полезные ссылки

- `README.md` — основная документация
- `docs/DEVELOPMENT.md` — руководство разработчика
- `CONTRIBUTING.md` — руководство по внесению изменений
- `.github/workflows/ci.yml` — конфигурация CI
