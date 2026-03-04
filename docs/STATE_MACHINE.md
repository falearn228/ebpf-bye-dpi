# GoodByeDPI eBPF: State Machine Spec

Этот документ фиксирует текущее поведение state machine в проекте на уровне:
- `conn_map` в eBPF (`STAGE_*` + `EVENT_*`)
- auto-logic в userspace (`AutoLogicState` / `Strategy`)

Источник истины: `ebpf/src/goodbyedpi.bpf.c`, `proto/src/lib.rs`, `daemon/src/auto_logic.rs`, `daemon/src/ringbuf.rs`.

## 1. Сущности и состояния

### 1.1 eBPF state (`conn_map`)

Для TCP flow хранится `conn_state`:
- `stage`:
  - `STAGE_INIT` (0)
  - `STAGE_SPLIT` (1)
  - `STAGE_OOB` (2)
  - `STAGE_FAKE_SENT` (3)
  - `STAGE_TLSREC` (4)
  - `STAGE_DISORDER` (5)
- `timestamp` для TTL
- `flags` (в т.ч. отметка примененного OOB)

### 1.2 eBPF events (`ringbuf`)

- `FAKE_TRIGGERED` (1)
- `RST_DETECTED` (2)
- `REDIRECT_DETECTED` (3)
- `SSL_ERROR_DETECTED` (4)
- `DISORDER_TRIGGERED` (5)
- `SPLIT_TRIGGERED` (6)
- `TLSREC_TRIGGERED` (7)
- `QUIC_FRAGMENT_TRIGGERED` (8)
- `OOB_TRIGGERED` (9)

### 1.3 Userspace auto-logic state

На flow (IPv4) в `AutoLogic` хранится:
- текущая стратегия: `TCP_SPLIT` / `TLS_RECORD_SPLIT` / `DISORDER` / `FAKE_WITH_SPLIT`
- `param` (индекс позиции split)
- `attempts`
- счетчики `rst/redirect/ssl`
- флаг `success` (см. раздел 6)

## 2. eBPF TCP state machine (egress)

Обработка начинается только для пакетов, распознанных как HTTP request или TLS ClientHello.

### 2.1 Инициализация/TTL

- Если `conn_state` отсутствует: создается `STAGE_INIT`.
- Если найден, но старше `CONN_STATE_TTL_NS` (120s): удаляется и создается заново при следующем пакете.
- На каждом подходящем пакете `timestamp` обновляется.

### 2.2 Переходы

Порядок проверок фиксированный, сверху вниз:

1. `SPLIT`:
- Условие: `split_pos > 0 && stage == INIT && split_pos < payload_len`
- Действие: `stage = SPLIT`, `EVENT_SPLIT_TRIGGERED`, оригинал `DROP` (`TC_ACT_SHOT`)

2. `OOB`:
- Условие: `oob_pos > 0 && stage <= SPLIT`
- Если `oob_pos < payload_len`: `stage = OOB`, `flags |= OOB_APPLIED`, `EVENT_OOB_TRIGGERED`, оригинал `DROP`
- Иначе: только `stage = OOB`, без события, без `DROP`

3. `FAKE`:
- Условие: `fake_offset != 0 && stage <= OOB`
- Действие: `stage = FAKE_SENT`, `EVENT_FAKE_TRIGGERED`, пакет проходит (`TC_ACT_OK`)

4. `DISORDER`:
- Условие: `disorder == true && (stage == OOB || stage == SPLIT)`
- Если `payload_len == 0`: защита от цикла, `stage = INIT`, пакет проходит
- Иначе: `stage = DISORDER`, `EVENT_DISORDER_TRIGGERED`, оригинал `DROP`

5. `TLSREC`:
- Условие: `tlsrec_pos != -1 && is_tls && stage == INIT`
- Доп. условия: успешно найден SNI и валидная точка split (`0 < split_at < payload_len`)
- Действие: `stage = TLSREC`, `EVENT_TLSREC_TRIGGERED`, пакет проходит

Примечание: один и тот же пакет может пройти через несколько блоков, если не было раннего `return` после `DROP`.

## 3. QUIC/UDP ветка (без `STAGE_*`)

Для UDP QUIC Initial:
- Если `ip_fragment` включен и `payload_len > 20`: `EVENT_QUIC_FRAGMENT_TRIGGERED`, оригинал `DROP`
- Иначе QUIC пропускается без модификации

UDP flow не использует `conn_map stage`, это отдельная логика по событию.

## 4. Ingress feedback (RST/Redirect/SSL)

Ingress ищет reverse-key в `conn_map` (тот же TCP flow в обратном направлении).

Правила:
- Если state отсутствует: ничего не делается
- Если state протух по TTL (120s): удаляется
- Если пришел `RST`:
  - при `auto_rst`: отправляется `EVENT_RST_DETECTED`
  - state удаляется всегда (RST считается закрытием flow)
- Если `auto_redirect` и payload похож на `HTTP ... 301/302`: `EVENT_REDIRECT_DETECTED`
- Если `auto_ssl` и payload похож на TLS fatal alert: `EVENT_SSL_ERROR_DETECTED`

## 5. Userspace auto-logic transitions

Auto-logic реагирует на ingress events и обновляет runtime-конфиг.

### 5.1 Базовый цикл по RST

Старт: `TCP_SPLIT(param=0)`; позиции split по `param`: `1, 2, 5, 10`.

Переходы:
- `TCP_SPLIT`: после 3 RST -> `TLS_RECORD_SPLIT`
- `TLS_RECORD_SPLIT`: после 1 RST -> `DISORDER`
- `DISORDER`: после 1 RST -> `TCP_SPLIT(param = (param+1)%4)`
- `FAKE_WITH_SPLIT`: каждые 3 RST сдвиг `param`

### 5.2 Redirect

На `REDIRECT_DETECTED`:
- если fake еще не включен: переход в `FAKE_WITH_SPLIT`, `attempts=0`
- если fake уже включен: поднимается флаг `disorder` в `AutoLogicState`

### 5.3 SSL error

На `SSL_ERROR_DETECTED`:
- принудительный переход в `TLS_RECORD_SPLIT` (если еще не там)
- `attempts` сбрасывается

### 5.4 Применение стратегии к runtime config

Через `EventProcessor::apply_strategy` изменяются:
- `split_pos`
- `fake_offset`
- `tlsrec_pos`
- `use_disorder`

И затем конфиг синхронизируется в BPF map через канал обновления.

## 6. Таймауты и cleanup

- `conn_map` TTL в eBPF: `120s` (`CONN_STATE_TTL_NS`)
- `sni_cache` TTL в eBPF: `300s` (`SNI_CACHE_TTL_NS`)
- `AutoLogic` TTL в userspace: `60s`
- cleanup loop в `daemon/main.rs`: каждые `5s`

## 7. Что считается успехом/фейлом (текущее состояние)

### 7.1 Явные сигналы фейла

Для auto-logic фейл-сигналы это входящие события:
- `RST_DETECTED`
- `REDIRECT_DETECTED`
- `SSL_ERROR_DETECTED`

Они триггерят переходы стратегии.

### 7.2 Успех

Явного детектора успеха в текущем runtime нет:
- поле `success` в `AutoConnectionState` существует
- метод `mark_success()` реализован
- но в текущем event pipeline не вызывается

Практически это означает, что "успех" сейчас не фиксируется как отдельный event/state transition; состояние живет до TTL или удаления по `RST`.

## 8. Границы и неочевидные моменты

- Auto-logic в `ringbuf` сейчас применяется только для IPv4 flow (IPv6 логируется и пропускается без авто-переходов).
- `STAGE_OOB` может выставиться даже когда OOB реально не отправлен (если `oob_pos >= payload_len`).
- `DISORDER` зависит от текущего `stage` (`OOB`/`SPLIT`), поэтому порядок техник важен.
- `BpfManager::cleanup_connections()` в userspace не чистит `conn_map` напрямую; фактический TTL cleanup делается в eBPF при обработке пакетов.
