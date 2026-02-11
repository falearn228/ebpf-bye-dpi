# Разработка GoodByeDPI eBPF

## Архитектура

### Компоненты

1. **eBPF Kernel Code** (`ebpf/src/goodbyedpi.bpf.c`)
   - TC Egress: Обнаружение и модификация исходящих пакетов
   - TC Ingress: Анализ ответов для авто-логики
   - Maps: Хранение состояния соединений и конфигурации

2. **Rust Daemon** (`daemon/src/`)
   - Загрузка и управление eBPF программами
   - Обработка событий через ring buffer
   - Raw socket инжектор для фейк-пакетов
   - Состояние соединений в userspace

3. **CLI** (`cli/src/`)
   - Удобный интерфейс для запуска и управления

## Протокол eBPF <-> Userspace

### Maps

#### `config_map` (hash)
```c
key: u32 (always 0)
value: struct config {
    s32 split_pos;
    s32 oob_pos;
    s32 fake_offset;
    s32 tlsrec_pos;
    u8 auto_rst;
    u8 auto_redirect;
    u8 auto_ssl;
};
```

#### `conn_map` (hash)
```c
key: struct conn_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

value: struct conn_state {
    u8 stage;
    u32 last_seq;
    u32 last_ack;
    u8 flags;
    u64 timestamp;
};
```

#### `events` (ringbuf)
```c
struct event {
    u32 type;      // 1=fake, 2=rst, 3=redirect, 4=ssl_error
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 seq;
    u32 ack;
    u8 flags;
    u8 payload_len;
};
```

## Методы обхода DPI

### 1. TCP Segment Split (`s1`)

Разбивает TCP-сегмент на два сегмента:
- Первый: байты [0:split_pos]
- Второй: байты [split_pos:]

Это обманывает DPI который видит только первый (неполный) сегмент.

### 2. OOB (Out of Band) (`-o1`)

Устанавливает URG флаг в TCP заголовке с указанным offset.

Некоторые DPI не обрабатывают OOB данные корректно.

### 3. Fake Packet (`-f-1`)

Отправляет фейковый пакет (с неправильными данными) перед реальным.

Задержка между фейком и реальным пакетом не даёт DPI правильно проанализировать поток.

### 4. TLS Record Split (`-r1+s`)

Разбивает TLS Client Hello запись на две части внутри одного TCP-сегмента.

Позиция может быть абсолютной или относительно SNI (Server Name Indication).

## Сборка

```bash
# Установка зависимостей
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool

# Сборка
export LIBBPF_SYS_LIBRARIES=/usr/lib/x86_64-linux-gnu
cargo build --release
```

## Отладка

### Проверка загруженных программ
```bash
sudo bpftool prog list
```

### Проверка maps
```bash
sudo bpftool map list
sudo bpftool map dump name conn_map
```

### Трассировка eBPF
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Проверка TC фильтров
```bash
sudo tc filter show dev eth0 egress
sudo tc filter show dev eth0 ingress
```

## Тестирование

```bash
# Запуск тестов
cargo test --workspace

# Тест парсера конфига
cargo test -p goodbyedpi-daemon config::tests
```

## TODO

- [ ] Реализовать полный TLS Client Hello парсер для точного определения SNI
- [ ] Добавить поддержку IPv6
- [ ] Реализовать HTTP/2 fingerprinting
- [ ] Добавить маскировку под популярные User-Agent
- [ ] Оптимизировать обработку ring buffer (batch processing)
