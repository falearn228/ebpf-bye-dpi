# GoodByeDPI eBPF - Interview Pack

Короткая версия проекта для собеседований: что решает, как устроен, какие trade-offs приняты.

## 1) Problem Statement

Провайдерский DPI часто блокирует доступ к сайтам на уровнях HTTP/TLS/QUIC.  
Задача проекта: сделать гибкий bypass с минимальной логикой в kernel (eBPF) и сложной обработкой в userspace (Rust).

## 2) Architecture (30 сек)

- `TC egress` в eBPF парсит пакеты (IPv4/IPv6, TCP/UDP), детектирует HTTP/TLS/QUIC сигнатуры.
- При срабатывании техники eBPF не модифицирует пакет “тяжело”, а шлет событие в `ringbuf`.
- В userspace daemon получает `Event` и через raw sockets реинжектит нужные пакеты:
  - TCP split
  - OOB (URG)
  - fake packet
  - TLS record split
  - disorder (out-of-order)
  - QUIC UDP IP fragmentation
- `TC ingress` ловит RST/redirect/SSL alerts для auto-logic и переключения стратегии.

## 3) Почему так спроектировано

- eBPF ограничен verifier-ом: сложную сборку пакетов и вариативную логику проще держать в Rust.
- Ring buffer дает дешевый и типизированный канал kernel -> userspace.
- Разделение дает:
  - безопасный и быстрый детект в kernel
  - гибкую эволюцию bypass-алгоритмов в userspace без переписывания eBPF.

## 4) Что можно показать руками (демо на 3-5 минут)

1. Запуск:
   - `sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 -Ar -At -As" --debug`
2. Показать, что eBPF attached:
   - `sudo tc filter show dev eth0 egress`
   - `sudo tc filter show dev eth0 ingress`
3. Показать поток событий:
   - в логах daemon видно `..._TRIGGERED`/`..._DETECTED`
4. Объяснить один сценарий end-to-end:
   - egress детектит TLS/QUIC -> событие в ringbuf -> userspace inject -> оригинал packet `TC_ACT_SHOT`.

## 5) Engineering Trade-offs (важно на собесе)

- `MAX_PAYLOAD_SIZE=1024` в event: меньше overhead ringbuf, но payload может быть обрезан.
- Сейчас userspace injection в основном IPv4; eBPF path уже поддерживает IPv6 detection.
- QUIC fragmentation делается на IPv4 raw UDP (`IP_HDRINCL`), потому что это проще контролировать по фрагментам.
- Состояние flow держится в `LRU map` + TTL, чтобы не раздувать память.

## 6) Ограничения (говорить честно)

- Нужны root/capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`).
- Зависимость от kernel 5.8+ и BTF.
- Поведение DPI у разных провайдеров отличается: универсальной “серебряной пули” нет.
- Проект исследовательский: применять только в легальном контексте вашей юрисдикции.

## 7) Security & Safety

- eBPF проверяется kernel verifier-ом.
- Инжектируемые пакеты помечаются `SO_MARK` (`USERSPACE_MARK`), чтобы не зациклить обработку.
- В systemd unit включаются hardening-настройки.

## 8) Что улучшать дальше

- Полный parity IPv6 injection.
- e2e тесты на сетевых namespace + pcap replay.
- Метрики latency/throughput и success-rate по стратегиям auto-logic.
- Более строгая валидация и fuzzing парсинга TLS ClientHello.

## 9) 60-second pitch

Я сделал GoodByeDPI eBPF: это Linux-проект на C eBPF + Rust, который обходит DPI через управляемые техники модификации трафика.  
В kernel на TC egress/ingress я держу быстрый и безопасный детект HTTP/TLS/QUIC, состояние flow в BPF maps и отправку событий через ring buffer.  
Сложная часть intentionally вынесена в userspace daemon: он получает события и через raw sockets инжектит split, OOB, fake, TLS record split, disorder и QUIC IP fragmentation.  
Такой split архитектуры снижает риски verifier-ограничений в eBPF и дает гибкость быстро менять стратегии в Rust без перезагрузки всей логики.  
Дополнительно есть auto-logic: по RST, redirect и SSL alerts система адаптирует конфиг на лету.  
Ядро фокуса проекта: производительный detection path в kernel + адаптивный control plane в userspace.

