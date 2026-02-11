# GoodByeDPI eBPF

Реализация DPI (Deep Packet Inspection) обхода через eBPF с управлением на Rust.

## Архитектура

```
┌─────────────────────────────────────────────────────────┐
│                    USERSPACE (Rust)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Auto-Logic   │  │ Raw Socket   │  │ Config       │ │
│  │ -Ar -At -As  │  │ Injector     │  │ Parser       │ │
│  │ State machine│  │ (fake, OOB)  │  │ "s1 -o1..."  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘ │
└─────────┼─────────────────┼───────────────────────────┘
          │ ring buffer     │ bpf() load
┌─────────▼─────────────────▼───────────────────────────┐
│                    eBPF KERNEL                          │
│  ┌─────────────┐    ┌───────────────┐    ┌──────────┐ │
│  │  TC Egress  │    │   TC (mod)    │    │  TC      │ │
│  │  Detection  │───▶│  - split      │    │  Ingress │ │
│  │  - fake trig│    │  - tlsrec     │    │  (auto)  │ │
│  │  - events   │    │  - disorder   │    │          │ │
│  └─────────────┘    │  - OOB mark   │    └──────────┘ │
│                     └───────────────┘                  │
│  ┌─────────────────────────────────────────────────┐  │
│  │ BPF Maps: conn_map, sni_cache, auto_state        │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

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

# Сборка проекта
cargo build --release
```

## Использование

### Запуск демона

```bash
# Базовый режим с разбиением и OOB
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1"

# Расширенный режим с авто-логикой
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -Ar -f-1 -r1+s -At -As"

# Режим отладки
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --debug

# YouTube/QUIC режим (с IP фрагментацией)
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 -Ar -At -As"
```

### CLI утилита

```bash
# Запуск через CLI
goodbyedpi -i eth0 -c "s1 -o1 -Ar" --daemon

# Проверка статуса
goodbyedpi --status

# Остановка
goodbyedpi --stop
```

## Структура проекта

```
.
├── ebpf/               # eBPF программы (C + libbpf)
│   └── src/
│       ├── goodbyedpi.bpf.c   # Основной eBPF код
│       └── Makefile
├── daemon/             # Rust daemon (userspace)
│   └── src/
│       ├── main.rs     # Точка входа
│       ├── bpf.rs      # BPF загрузка и управление
│       ├── config.rs   # Парсер конфига
│       ├── injector.rs # Raw socket injector
│       ├── state.rs    # Управление состоянием
│       └── tc.rs       # TC helper функции
├── cli/                # CLI утилита
│   └── src/main.rs
└── proto/              # Общие структуры
    └── src/lib.rs
```

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

# Проверить pinned maps
ls -la /sys/fs/bpf/goodbyedpi/
```

## Как это работает

### 1. Обнаружение (TC Egress)

eBPF программа прикрепляется к egress трафику. Она анализирует пакеты:
- HTTP запросы (GET, POST, и т.д.)
- TLS Client Hello
- QUIC Initial packets (UDP 443)
- Определяет SNI (Server Name Indication)

### 2. Модификация

При обнаружении подходящего пакета применяются техники:
- **Split**: Разбиение пакета на части с разными TCP-сегментами
- **OOB**: Установка URG флага и urgent pointer
- **Fake**: Отправка фейкового пакета перед реальным
- **TLSrec**: Разбиение TLS-записи внутри TCP-сегмента
- **IP Frag**: Фрагментация QUIC/UDP пакетов для обхода DPI

### 3. Авто-логика (TC Ingress)

При получении ответов:
- **RST**: Переподключение с другой стратегией
- **HTTP 302/301**: Повтор запроса с изменениями
- **SSL ошибки**: Смена TLS-фингерпринта

