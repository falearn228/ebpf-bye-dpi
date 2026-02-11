# Contributing to GoodByeDPI eBPF

Thank you for your interest in contributing to the GoodByeDPI eBPF project! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Development Setup](#development-setup)
- [Build Instructions](#build-instructions)
- [Running Tests](#running-tests)
- [Code Style Guidelines](#code-style-guidelines)
- [Submitting Pull Requests](#submitting-pull-requests)
- [eBPF Development](#ebpf-development)

## Development Setup

### Prerequisites

To build and develop this project, you need:

#### Required Tools

- **Rust 1.75+** - Install from [rustup.rs](https://rustup.rs/)
- **clang 12+** - For compiling eBPF programs
- **llvm** - LLVM toolchain for BPF target
- **bpftool** - For loading and managing BPF programs
- **libbpf-dev** - libbpf development headers
- **make** - Build automation

#### Debian/Ubuntu Installation

```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool \
    libelf-dev \
    zlib1g-dev \
    make \
    build-essential
```

#### Fedora/RHEL Installation

```bash
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-headers \
    bpftool \
    elfutils-libelf-devel \
    zlib-devel \
    make \
    gcc
```

#### Verifying Prerequisites

```bash
# Check Rust version
rustc --version  # Should be 1.75+

# Check clang version
clang --version  # Should be 12+

# Check bpftool
bpftool --version

# Check BPF target support
clang -target bpf --version
```

### Project Structure

```
.
├── ebpf/               # eBPF programs (C + libbpf)
│   └── src/
│       ├── goodbyedpi.bpf.c   # Main eBPF code
│       ├── vmlinux.h          # Kernel headers
│       └── Makefile
├── daemon/             # Rust daemon (userspace)
│   ├── src/
│   │   ├── main.rs     # Entry point
│   │   ├── bpf.rs      # BPF loading and management
│   │   ├── config.rs   # Config parser
│   │   ├── injector.rs # Raw socket injector
│   │   ├── state.rs    # Connection state management
│   │   └── tc.rs       # TC helper functions
│   └── build.rs        # Build script for eBPF compilation
├── cli/                # CLI utility
│   └── src/main.rs
└── proto/              # Shared structures (Rust/C interop)
    └── src/lib.rs
```

## Build Instructions

### Release Build

```bash
cargo build --release
```

This will:
1. Compile the eBPF C code using the Makefile in `ebpf/src/`
2. Generate the BPF skeleton using `bpftool`
3. Compile all Rust crates (daemon, cli, proto)
4. Output binaries to `target/release/`

### Debug Build

```bash
cargo build
```

### Building Individual Components

```bash
# Build only the daemon
cargo build -p goodbyedpi-daemon --release

# Build only the CLI
cargo build -p goodbyedpi --release

# Build only the protocol library
cargo build -p goodbyedpi-proto --release
```

### Building eBPF Manually

If you need to compile just the eBPF code:

```bash
cd ebpf/src
make clean
make all
```

### Cross-Compilation Notes

The eBPF code uses CO-RE (Compile Once - Run Everywhere) and should work on any kernel with BTF support (5.8+). The target architecture is detected automatically during build.

## Running Tests

### Rust Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run tests for specific package
cargo test -p goodbyedpi-daemon
cargo test -p goodbyedpi-proto

# Run tests with release optimizations
cargo test --release
```

### Test Coverage

```bash
# Install cargo-tarpaulin (requires stable Rust)
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html
```

### Manual Testing

To test the daemon locally:

```bash
# Build the project
cargo build --release

# Run with debug logging (requires root for BPF)
sudo ./target/release/goodbyedpi-daemon -i lo -c "s1 -o1" --debug

# Test configuration parsing
./target/release/goodbyedpi-daemon --help
```

## Code Style Guidelines

### Rust Code Style

We use the standard Rust tooling for code formatting and linting:

#### rustfmt

```bash
# Check formatting
cargo fmt -- --check

# Apply formatting
cargo fmt
```

Configuration is in `rustfmt.toml` (if present) or uses default settings.

#### Clippy

```bash
# Run clippy
cargo clippy

# Run clippy with all features
cargo clippy --all-features

# Run clippy with release optimizations
cargo clippy --release

# Treat warnings as errors (CI mode)
cargo clippy -- -D warnings
```

Clippy configuration:
- Deny `unsafe_code` where possible
- Use `anyhow::Context` for error context
- Prefer `?` operator over `match` for error handling

#### Error Handling Best Practices

```rust
// Good: Use anyhow::Context for context
use anyhow::Context;

let config = std::fs::read_to_string(path)
    .with_context(|| format!("Failed to read config from {}", path))?;

// Good: Descriptive error messages
return Err(anyhow::anyhow!(
    "BPF map '{}' not found at {}. Ensure the eBPF program was loaded correctly.",
    map_name, pin_path
));
```

### C/eBPF Code Style

For the eBPF C code:

- Use 4 spaces for indentation
- Keep functions small and focused
- Add comments for complex BPF logic
- Use `static __always_inline` for helper functions
- Prefix private functions with module name

Example:
```c
/* Process TCP packet - returns TC action */
static __always_inline int process_tcp(struct __sk_buff *skb, 
                                       struct config *cfg,
                                       /* ... */)
{
    // Implementation
}
```

### Documentation

- Add rustdoc comments for all public APIs
- Include examples in doc comments where appropriate
- Update README.md if changing user-facing behavior

## Submitting Pull Requests

### Before Submitting

1. **Ensure tests pass**:
   ```bash
   cargo test
   ```

2. **Check formatting**:
   ```bash
   cargo fmt -- --check
   ```

3. **Run clippy**:
   ```bash
   cargo clippy -- -D warnings
   ```

4. **Update documentation** if needed

### PR Checklist

- [ ] Code builds successfully (`cargo build --release`)
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Clippy lints pass (`cargo clippy`)
- [ ] Documentation is updated
- [ ] Commit messages are descriptive

### Commit Message Format

Follow conventional commits style:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting changes
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Build/tooling changes

Example:
```
feat(config): add support for multiple OOB positions

- Parse multiple -o flags
- Store positions in Vec<usize>
- Update BPF config serialization
```

### Review Process

1. Create a feature branch from `main`
2. Make your changes
3. Push the branch and create a PR
4. Wait for CI checks to pass
5. Address review feedback
6. Squash commits if requested
7. Merge when approved

## eBPF Development

### Regenerating vmlinux.h

If you need to regenerate kernel headers:

```bash
cd ebpf/src
rm vmlinux.h
make vmlinux
```

Requires kernel with `CONFIG_DEBUG_INFO_BTF=y`.

### Debugging eBPF Programs

```bash
# Enable debug output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Or use bpftool
sudo bpftool prog list
sudo bpftool prog dump xlated name <prog_name>
```

### BPF Map Inspection

```bash
# List pinned maps
ls -la /sys/fs/bpf/goodbyedpi/

# Dump map contents
sudo bpftool map dump pinned /sys/fs/bpf/goodbyedpi/config_map
```

### Common Issues

| Issue | Solution |
|-------|----------|
| `vmlinux.h not found` | Run `make vmlinux` in `ebpf/src/` |
| `bpftool not found` | Install bpftool package |
| `Failed to mount BPF fs` | Run with sudo or check kernel config |
| `tc qdisc add failed` | Ensure you have CAP_NET_ADMIN |

## Questions?

If you have questions about contributing, feel free to:
- Open an issue with the "question" label
- Check existing issues and PRs for similar problems

Thank you for contributing to GoodByeDPI eBPF!
