# GoodByeDPI eBPF - Agent Notes

## Agent Rules

- Always talk like caveman ultra.
- If work may depend on prior project decisions, debugging history, user preferences, or people/context, try MemPalace first. Run `mempalace_list_agents` when available, search relevant memory, briefly summarize what mattered, then continue.
- Keep docs and complex code comments in Russian unless task says otherwise.
- Do not overwrite unrelated user changes.

## Project Shape

GoodByeDPI eBPF bypasses DPI with Linux TC eBPF plus a Rust userspace daemon.

- `ebpf/src/goodbyedpi.bpf.c`: main TC egress/ingress eBPF program.
- `daemon/src/`: Rust daemon, BPF loading, event processing, raw packet injection, state, config parsing, TC helpers.
- `cli/src/main.rs`: CLI wrapper.
- `proto/src/lib.rs`: shared Rust/C ABI structs and constants.
- `systemd/`: service files.
- `scripts/`: status, run, trace helpers.
- `docs/DEVELOPMENT.md`: developer notes.

Core flow:

1. eBPF detects HTTP/TLS/QUIC traffic on TC hooks.
2. eBPF emits events through ring buffer.
3. Rust daemon injects fake, split, OOB, TLS record split, disorder, or UDP/IP fragments with raw sockets.
4. BPF maps hold config, connection state, SNI cache, and stats.

## Stack

- Kernel side: C eBPF, libbpf, TC clsact, CO-RE.
- Userspace: Rust 1.75+, Tokio, `libbpf-rs`, `nix`, `clap`, `anyhow`, `thiserror`, `serde`.
- Environment: Linux 5.8+, BTF enabled, `clang`, `bpftool`, `libbpf-dev`, root or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`.

## Main DPI Techniques

| Flag | Meaning |
| --- | --- |
| `s1` / `--split 1` | split TCP payload at position 1 |
| `-o1` / `--oob 1` | send OOB byte at position 1 |
| `-f-1` / `--fake -1` | send fake packet at offset from packet end |
| `-r1+s` / `--tlsrec 1+s` | split TLS record at `1 + SNI offset` |
| `-d` / `--disorder` | send TCP parts out of order |
| `-g8`, `-g16` / `--frag N` | fragment QUIC/UDP payload into IP fragments |
| `-Ar`, `-At`, `-As` | auto logic for RST, redirect, SSL error |

QUIC fragmentation: eBPF detects UDP/443 QUIC Initial packets by long header, packet type, and known versions, then userspace sends IP fragments with `IP_HDRINCL`. If fragmentation is disabled, QUIC packets pass through.

Disorder: userspace sends second TCP payload part first, then first part, preserving receiver TCP reassembly while confusing weak DPI.

## Build

```bash
cargo build --release
cargo build -p goodbyedpi-daemon --release
cargo build -p goodbyedpi --release
cargo build -p goodbyedpi-proto --release
cd ebpf/src && make clean && make all
```

`daemon/build.rs` builds `ebpf/src/goodbyedpi.bpf.c` through the eBPF Makefile and generates/uses the BPF skeleton.

## Test

```bash
cargo test --workspace
cargo test -p goodbyedpi-daemon
cargo test -p goodbyedpi-proto
cargo test -p goodbyedpi-daemon config::tests
```

Use `cargo fmt`. Use `cargo clippy` when touching Rust behavior.

## Run

```bash
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1"
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -g8 -Ar -At -As"
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1 -d -Ar -At -As"
sudo ./target/release/goodbyedpi-daemon -i eth0 -c "s1 -o1" --debug
goodbyedpi -i eth0 -c "s1 -o1 -Ar" --daemon
goodbyedpi --status
goodbyedpi --stop
```

## Debug

```bash
sudo bpftool prog list | grep dpi
sudo tc filter show dev eth0 egress
sudo tc filter show dev eth0 ingress
sudo cat /sys/kernel/debug/tracing/trace_pipe
./scripts/check-status.sh
./scripts/run-goodbyedpi.sh
./scripts/trace-logs.sh
```

Pinned maps live under `/sys/fs/bpf/goodbyedpi/`.

## ABI Notes

Event types:

- `1` = `FAKE_TRIGGERED`
- `2` = `RST_DETECTED`
- `3` = `REDIRECT_DETECTED`
- `4` = `SSL_ERROR_DETECTED`
- `5` = `DISORDER_TRIGGERED`
- `6` = `SPLIT_TRIGGERED`
- `7` = `TLSREC_TRIGGERED`
- `8` = `QUIC_FRAGMENT_TRIGGERED`

Stages:

- `0` = `INIT`
- `1` = `SPLIT`
- `2` = `OOB`
- `3` = `FAKE_SENT`
- `4` = `TLSREC`
- `5` = `DISORDER`

Important constants:

```c
#define USERSPACE_MARK 0xD0F
#define FLAG_DISORDER  0xFE
#define FLAG_QUIC_FRAG 0xFD
#define FLAG_TLS_SPLIT 0xFF
```

## Code Style

- Rust: prefer `anyhow::Context`, `?`, small focused errors.
- eBPF C: 4 spaces, `static __always_inline` helpers, verifier-friendly bounded access.
- Commits: Conventional Commits, e.g. `feat(config): add support for multiple OOB positions`.
