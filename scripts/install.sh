#!/usr/bin/env bash
# Простой установщик GoodByeDPI eBPF для пользователей.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PREFIX="/usr/local/bin"
INSTALL_DEPS=1
RUN_DAEMON=0
RUN_IFACE="eth0"
RUN_CONFIG="s1 -o1"
RUN_DEBUG=0

usage() {
    cat <<'EOF'
Usage: ./scripts/install.sh [options]

Options:
  --no-deps           Не устанавливать системные зависимости
  --prefix <path>     Каталог установки бинарников (default: /usr/local/bin)
  --run               Запустить daemon после установки (через sudo)
  --iface <name>      Интерфейс для запуска daemon (default: eth0)
  --config <string>   Конфиг daemon для --run (default: "s1 -o1")
  --debug             Добавить --debug при запуске daemon с --run
  -h, --help          Показать помощь
EOF
}

run_as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-deps)
            INSTALL_DEPS=0
            shift
            ;;
        --prefix)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --prefix requires a value"
                exit 1
            fi
            PREFIX="$2"
            shift 2
            ;;
        --run)
            RUN_DAEMON=1
            shift
            ;;
        --iface)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --iface requires a value"
                exit 1
            fi
            RUN_IFACE="$2"
            shift 2
            ;;
        --config)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --config requires a value"
                exit 1
            fi
            RUN_CONFIG="$2"
            shift 2
            ;;
        --debug)
            RUN_DEBUG=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option '$1'"
            usage
            exit 1
            ;;
    esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: this installer supports Linux only."
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found. Install Rust toolchain first: https://rustup.rs"
    exit 1
fi

if [[ "${INSTALL_DEPS}" -eq 1 ]]; then
    if command -v apt-get >/dev/null 2>&1; then
        echo "==> Installing system dependencies (Debian/Ubuntu)"
        run_as_root apt-get update
        run_as_root apt-get install -y \
            clang \
            llvm \
            libbpf-dev \
            "linux-headers-$(uname -r)" \
            bpftool \
            libelf-dev \
            zlib1g-dev \
            make
    elif command -v pacman >/dev/null 2>&1; then
        echo "==> Installing system dependencies (Arch Linux)"
        run_as_root pacman -Syu --needed --noconfirm \
            clang \
            llvm \
            libbpf \
            linux-headers \
            bpftool \
            libelf \
            zlib \
            make
    else
        echo "ERROR: unsupported package manager. Use --no-deps and install dependencies manually."
        exit 1
    fi
fi

echo "==> Building project (release)"
(cd "${ROOT_DIR}" && cargo build --release)

DAEMON_BIN="${ROOT_DIR}/target/release/goodbyedpi-daemon"
CLI_BIN="${ROOT_DIR}/target/release/goodbyedpi-cli"

if [[ ! -x "${DAEMON_BIN}" ]]; then
    echo "ERROR: daemon binary not found: ${DAEMON_BIN}"
    exit 1
fi

if [[ ! -x "${CLI_BIN}" ]]; then
    echo "ERROR: cli binary not found: ${CLI_BIN}"
    exit 1
fi

echo "==> Installing binaries to ${PREFIX}"
run_as_root install -d "${PREFIX}"
run_as_root install -m 0755 "${DAEMON_BIN}" "${PREFIX}/goodbyedpi-daemon"
run_as_root install -m 0755 "${CLI_BIN}" "${PREFIX}/goodbyedpi"

echo ""
echo "Installation completed."
echo "Run examples:"
echo "  sudo ${PREFIX}/goodbyedpi-daemon -i eth0 -c \"s1 -o1\""
echo "  ${PREFIX}/goodbyedpi --status"

if [[ "${RUN_DAEMON}" -eq 1 ]]; then
    DAEMON_CMD=("${PREFIX}/goodbyedpi-daemon" "-i" "${RUN_IFACE}" "-c" "${RUN_CONFIG}")
    if [[ "${RUN_DEBUG}" -eq 1 ]]; then
        DAEMON_CMD+=("--debug")
    fi

    echo ""
    echo "==> Starting daemon:"
    echo "    sudo ${DAEMON_CMD[*]}"
    run_as_root "${DAEMON_CMD[@]}"
fi
