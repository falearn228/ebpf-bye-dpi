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

## 7. Текущий статус zapret-like функциональности

Цель остаётся прежней: приблизить конфиг к профилям zapret/winws без слома текущего `-c` синтаксиса. Ниже не wish-list, а фактический статус репозитория на текущий момент.

### Уже реализовано

- Rule engine v1 через секции `--new`
- Поля правил: `--proto`, `--ports`, `--action`, `--repeats`
- Глобальные L4-фильтры: `--filter-tcp`, `--filter-udp`
- Алиасы глобальных L4-фильтров: `--wf-tcp`, `--wf-udp`
- Targeting по спискам:
- `--hostlist`
- `--hostlist-exclude`
- `--ipset`
- `--ipset-exclude`
- Алиас доменного списка: `--hostlist-domains`
- Повторяемые list-флаги добавляются, а не перезаписываются
- Fake profiles из файлов:
- `--fake-quic`
- `--fake-discord`
- `--fake-stun`
- Алиасы fake profiles:
- `--dpi-desync-fake-quic`
- `--dpi-desync-fake-discord`
- `--dpi-desync-fake-stun`
- `--dpi-desync-fake-unknown-udp`
- `--dpi-desync-hostfakesplit-mod=host=<domain>`
- L7-фильтр:
- `--filter-l7=discord,stun`
- DPI desync DSL:
- `--dpi-desync=*`
- `--dpi-desync-repeats=*`
- `--dpi-desync-fooling=*`
- Поддержанные значения `--dpi-desync`:
- `fake`
- `disorder`
- `split`
- `hostfakesplit`
- Поддержанные значения `--dpi-desync-fooling`:
- `ts`
- `md5sig`
- Regression/unit tests для парсинга и совместимости старых/новых ключей

### Реализовано частично

- Совместимость с zapret/winws уже есть на уровне базовых action/filter/list/repeats сценариев, но не на уровне полного набора профилей
- `hostfakesplit` сейчас маппится в текущие internal actions (`split + fake`), но дополнительные zapret-модификаторы для host-specific fake payload ещё не реализованы
- Fake profile selection уже умеет выбирать payload по L7 (`stun`, `discord`) и по QUIC/port 443, но набор флагов для этого пока не полностью zapret-совместим по именам
- `--dpi-desync-hostfakesplit-mod=host=<domain>` реализован в минимальном userspace-only варианте: генерируется fake HTTP payload с указанным `Host`
- `--dpi-desync-fake-unknown-udp=*` реализован как fallback profile для unknown L7 в текущем userspace fake path
- `--ip-id=zero` реализован на userspace IPv4 injection path
- `--dpi-desync-autottl=*` реализован как userspace TTL/hop-limit tuning для инжектируемых пакетов
- `--dpi-desync-cutoff=*` реализован как per-connection/per-action cutoff в userspace event processor
- `--dpi-desync-any-protocol=*` реализован как расширение userspace fallback profile selection для unknown L7

### Пока не реализовано

- Полный coverage всех winws/zapret action/modifier имён и semantics без оговорок
- Runtime-совместимость Windows path значений вида `C:\...` на Linux по-прежнему требует замены пути

## 8. Целевой профиль совместимости с zapret

Ниже зафиксирован practical target: пользователь должен иметь возможность запускать daemon профилем, близким к следующему классу аргументов:

```text
--wf-tcp ...
--wf-udp ...
--filter-udp ...
--hostlist ...
--hostlist-exclude ...
--ipset ...
--ipset-exclude ...
--dpi-desync fake|hostfakesplit
--dpi-desync-repeats N
--dpi-desync-fake-quic ...
--dpi-desync-fake-discord ...
--dpi-desync-fake-stun ...
--dpi-desync-hostfakesplit-mod host=...
--dpi-desync-fooling ts,md5sig
--ip-id zero
--dpi-desync-autottl 2
--dpi-desync-any-protocol 1
--dpi-desync-fake-unknown-udp ...
--dpi-desync-cutoff n2
--new
```

### Что уже покрывается текущим кодом

- Разбиение профиля на секции через `--new`
- Правила с разными `filter-tcp/filter-udp` по секциям
- Алиасы `wf-tcp/wf-udp` для глобальных port filters
- `hostlist`, `hostlist-exclude`, `ipset`, `ipset-exclude`
- `hostlist-domains`
- `filter-l7 discord,stun`
- `--dpi-desync fake`
- `--dpi-desync hostfakesplit`
- `--dpi-desync-repeats`
- `--dpi-desync-fooling ts[,md5sig]`
- Загрузка fake payload через существующие флаги `--fake-quic`, `--fake-discord`, `--fake-stun`
- Алиасы `--dpi-desync-fake-{quic,discord,stun}`
- `--dpi-desync-hostfakesplit-mod=host=<domain>`
- `--dpi-desync-fake-unknown-udp`
- `--ip-id=zero`, `--dpi-desync-autottl`, `--dpi-desync-cutoff`, `--dpi-desync-any-protocol`

### Что нужно добавить для целевого zapret-профиля

#### Приоритет B: профильно-специфичные desync modifiers

- `--dpi-desync-hostfakesplit-mod=*`
- Минимальная реализация: userspace-only mod selector для `hostfakesplit`
- Первый practical target: `host=<domain>`

- `--dpi-desync-fake-unknown-udp=*`
- Семантика: payload profile для UDP трафика, не распознанного как `stun`/`discord`/`quic`

#### Приоритет C: low-level knobs

- `--ip-id=zero`
- `--dpi-desync-autottl=*`
- `--dpi-desync-cutoff=*`
- `--dpi-desync-any-protocol=*`
- Текущая реализация уже есть в userspace-only варианте
- При необходимости полной zapret-совместимости semantics можно усиливать через proto/eBPF

## 9. Совместимость и ограничения

- Текущий daemon запускается на Linux. Пути вида `C:\...` из zapret/winws-профилей не являются runtime-совместимыми как есть и должны быть заменены на Linux paths.
- Для list/profile files допустимы как CSV-значения, так и пути к локальным файлам.
- Для полной zapret-совместимости важна не только поддержка action flags, но и сохранение семантики секций `--new` и порядка применения правил.
- Для импорта profile strings теперь можно использовать `--config-file <path>`; parser понимает multiline profile text, quoted values, line continuation через `^`/`\` и игнорирует строковые комментарии (`#`, `;`, `//`, `::`, `rem`).

## 10. План реализации для zapret-like запуска

1. Добавить алиасы `--wf-tcp/--wf-udp` и `--dpi-desync-fake-*` без изменения внутренней модели. [done]
2. Добавить `--dpi-desync-hostfakesplit-mod` с минимальной поддержкой `host=<domain>`. [done]
3. Добавить `--dpi-desync-fake-unknown-udp`. [done]
4. Добавить regression-тест с большим composite profile, приближённым к реальному zapret config. [done]
5. Уточнить и при необходимости усилить semantics `ip-id/autottl/cutoff/any-protocol` до полного zapret parity. [done]
6. После этого документировать прямое соответствие `zapret args -> internal config`. [done in this document]

## 11. Соответствие zapret args -> internal config

Таблица ниже фиксирует текущее canonical mapping в userspace parser/runtime.

| Zapret-like arg | Internal field / behavior | Notes |
| --- | --- | --- |
| `--wf-tcp=<ports>` | `DpiConfig.filter_tcp` | Алиас `--filter-tcp` |
| `--wf-udp=<ports>` | `DpiConfig.filter_udp` | Алиас `--filter-udp` |
| `--filter-l7=discord,stun` | `DpiConfig.filter_l7` | Фильтр до инъекции |
| `--hostlist=*` | `DpiConfig.hostlist` | Повторяемые флаги append |
| `--hostlist-domains=*` | `DpiConfig.hostlist` | Алиас domain-only list |
| `--hostlist-exclude=*` | `DpiConfig.hostlist_exclude` | Exclude list |
| `--ipset=*` | `DpiConfig.ipset` | IPv4/IPv6 CIDR или single IP |
| `--ipset-exclude=*` | `DpiConfig.ipset_exclude` | Exclude IP list |
| `--dpi-desync=fake` | `dpi_desync_actions += Fake`, `fake_offset = -1` if unset | Legacy `-f` имеет приоритет |
| `--dpi-desync=split` | `dpi_desync_actions += Split`, `split_pos = 1` if unset | Legacy `-s` имеет приоритет |
| `--dpi-desync=disorder` | `dpi_desync_actions += Disorder`, `use_disorder = true` | Legacy `-d` имеет приоритет |
| `--dpi-desync=hostfakesplit` | `dpi_desync_actions += Split + Fake`, `split_pos = 1`, `fake_offset = -1` if unset | userspace mapping |
| `--dpi-desync-repeats=N` | `DpiConfig.dpi_desync_repeats = N` | Используется как fallback repeats |
| `--dpi-desync-fooling=ts,md5sig` | `DpiConfig.dpi_desync_fooling` | Сейчас parser/runtime metadata |
| `--fake-quic=<file>` | `fake_profiles.quic` | File payload |
| `--fake-discord=<file>` | `fake_profiles.discord` | File payload |
| `--fake-stun=<file>` | `fake_profiles.stun` | File payload |
| `--dpi-desync-fake-quic=<file>` | `fake_profiles.quic` | Алиас `--fake-quic` |
| `--dpi-desync-fake-discord=<file>` | `fake_profiles.discord` | Алиас `--fake-discord` |
| `--dpi-desync-fake-stun=<file>` | `fake_profiles.stun` | Алиас `--fake-stun` |
| `--dpi-desync-hostfakesplit-mod=host=<domain>` | `fake_profiles.hostfakesplit` | Генерируется fake HTTP payload с `Host` |
| `--dpi-desync-fake-unknown-udp=<file>` | `fake_profiles.unknown_udp` | Fallback profile для unknown UDP/L7 |
| `--ip-id=zero` | `DpiConfig.ip_id_zero` -> injector sets IPv4 ID to `0` | Userspace injection path |
| `--dpi-desync-autottl=N` | `DpiConfig.dpi_desync_autottl` -> injector TTL/Hop Limit = `64 - N`, min `1` | `None` keeps default |
| `--dpi-desync-cutoff=nN` | `DpiConfig.dpi_desync_cutoff = N` | Runtime limit per connection and per action |
| `--dpi-desync-any-protocol=1` | `DpiConfig.dpi_desync_any_protocol = true` | Expands unknown UDP fallback beyond port `443` |
| `--new --proto=tcp --ports=... --action=... --repeats=...` | `DpiConfig.rules.push(Rule)` | Rule engine section |

Практические примечания:

- Без `--dpi-desync-any-protocol=1` `fake-unknown-udp` fallback не расширяется на весь unknown UDP; по умолчанию он остаётся ограниченным QUIC-like path на `dst_port=443`.
- `cutoff` считается отдельно для каждой `(connection, action)` пары.
- `autottl` и `ip-id=zero` сейчас применяются на userspace injection path; это не eBPF-side knob.
