#!/usr/bin/env bash
# Linux runner, порт логики test.ps1 для goodbyedpi-daemon:
# - запускает daemon на выбранном интерфейсе с набором config strings;
# - проверяет HTTP/TLS/ping targets или DPI checker suite;
# - сохраняет отчёт и восстанавливает lists/ipset-all.txt после DPI режима.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTS_DIR="${ROOT_DIR}/lists"
UTILS_DIR="${ROOT_DIR}/utils"
RESULTS_DIR="${UTILS_DIR}/test-results"
IPSET_FLAG_FILE="${ROOT_DIR}/ipset_switched.flag"
IPSET_FILE="${LISTS_DIR}/ipset-all.txt"
IPSET_BACKUP_FILE="${LISTS_DIR}/ipset-all.test-backup.txt"

DPI_TIMEOUT_SECONDS="${MONITOR_TIMEOUT:-5}"
DPI_RANGE_BYTES="${MONITOR_RANGE:-262144}"
DPI_WARN_MIN_KB="${MONITOR_WARN_MINKB:-14}"
DPI_WARN_MAX_KB="${MONITOR_WARN_MAXKB:-22}"
DPI_CUSTOM_URL="${MONITOR_URL:-}"

IFACE="${TEST_IFACE:-}"
DAEMON_BIN="${GBD_DAEMON_BIN:-}"
TEST_TYPE=""
SELECT_MODE=""
NON_INTERACTIVE=0
IN_CLEANUP=0
declare -a CONFIG_SPECS=()
declare -a GLOBAL_ROWS=()
declare -a STARTED_PIDS=()
DAEMON_PID=""

DEFAULT_CONFIGS=(
    "s1 -o1"
    "s1 -o1 -f-1"
    "s1 -o1 -g8 -Ar -At -As"
    "s1 -o1 -d -Ar -At -As"
    "s1 -r-2 -Ar"
)

DEFAULT_TARGETS=(
    "Discord Main=https://discord.com"
    "Discord Gateway=https://gateway.discord.gg"
    "Discord CDN=https://cdn.discordapp.com"
    "Discord Updates=https://updates.discord.com"
    "YouTube Web=https://www.youtube.com"
    "YouTube Short=https://youtu.be"
    "YouTube Image=https://i.ytimg.com"
    "YouTube Video Redirect=https://redirector.googlevideo.com"
    "Google Main=https://www.google.com"
    "Google Gstatic=https://www.gstatic.com"
    "Cloudflare Web=https://www.cloudflare.com"
    "Cloudflare CDN=https://cdnjs.cloudflare.com"
    "Cloudflare DNS 1.1.1.1=PING:1.1.1.1"
    "Cloudflare DNS 1.0.0.1=PING:1.0.0.1"
    "Google DNS 8.8.8.8=PING:8.8.8.8"
    "Google DNS 8.8.4.4=PING:8.8.4.4"
    "Quad9 DNS 9.9.9.9=PING:9.9.9.9"
)

usage() {
    cat <<'USAGE'
Usage:
  sudo ./test-linux.sh [--iface IFACE] [--standard|--dpi] [--all|--select LIST]
                       [--config "s1 -o1"]... [--config-file PATH] [--yes]

Env:
  TEST_IFACE=eth0
  GBD_DAEMON_BIN=./target/release/goodbyedpi-daemon
  MONITOR_URL=https://example.org/file.bin
  MONITOR_TIMEOUT=5 MONITOR_RANGE=262144 MONITOR_WARN_MINKB=14 MONITOR_WARN_MAXKB=22

Examples:
  sudo ./test-linux.sh --iface eth0 --standard --config "s1 -o1 -Ar" --yes
  sudo ./test-linux.sh --iface eth0 --dpi --all
USAGE
}

log() { printf '%s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERROR] %s\n' "$*" >&2; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "required command not found: $1"
        exit 1
    fi
}

ipset_status() {
    if [[ ! -f "${IPSET_FILE}" ]]; then
        printf 'none'
        return
    fi

    if [[ ! -s "${IPSET_FILE}" ]]; then
        printf 'any'
        return
    fi

    if grep -qE '203\.0\.113\.113/32' "${IPSET_FILE}"; then
        printf 'none'
    else
        printf 'loaded'
    fi
}

set_ipset_mode() {
    local mode="$1"
    mkdir -p "${LISTS_DIR}"

    case "${mode}" in
        any)
            if [[ -f "${IPSET_FILE}" ]]; then
                cp -f "${IPSET_FILE}" "${IPSET_BACKUP_FILE}"
            else
                : >"${IPSET_BACKUP_FILE}"
            fi
            : >"${IPSET_FILE}"
            ;;
        restore)
            if [[ -f "${IPSET_BACKUP_FILE}" ]]; then
                mv -f "${IPSET_BACKUP_FILE}" "${IPSET_FILE}"
            fi
            ;;
        *)
            err "unknown ipset mode: ${mode}"
            exit 1
            ;;
    esac
}

terminate_pid() {
    local pid="$1"
    local i

    if ! kill -0 "${pid}" 2>/dev/null; then
        return
    fi

    kill "${pid}" 2>/dev/null || true
    for i in {1..20}; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            wait "${pid}" 2>/dev/null || true
            return
        fi
        sleep 0.1
    done

    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
}

cleanup() {
    [[ "${IN_CLEANUP}" -eq 1 ]] && return
    IN_CLEANUP=1
    set +e
    for pid in "${STARTED_PIDS[@]:-}"; do
        terminate_pid "${pid}"
    done

    if [[ "${ORIGINAL_IPSET_STATUS:-any}" != "any" ]]; then
        set_ipset_mode restore
    fi
    rm -f "${IPSET_FLAG_FILE}"
}

handle_interrupt() {
    local code="$1"
    trap - EXIT INT TERM
    printf '\n[WARN] interrupted, stopping daemon and restoring ipset\n' >&2
    cleanup
    exit "${code}"
}

trap cleanup EXIT
trap 'handle_interrupt 130' INT
trap 'handle_interrupt 143' TERM

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iface|-i)
                IFACE="${2:-}"
                shift 2
                ;;
            --standard)
                TEST_TYPE="standard"
                shift
                ;;
            --dpi)
                TEST_TYPE="dpi"
                shift
                ;;
            --all)
                SELECT_MODE="all"
                shift
                ;;
            --select)
                SELECT_MODE="${2:-}"
                shift 2
                ;;
            --config|-c)
                CONFIG_SPECS+=("config:${2:-}")
                shift 2
                ;;
            --config-file)
                CONFIG_SPECS+=("file:${2:-}")
                shift 2
                ;;
            --yes|-y)
                NON_INTERACTIVE=1
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                err "unknown argument: $1"
                usage
                exit 1
                ;;
        esac
    done
}

detect_iface() {
    if [[ -n "${IFACE}" ]]; then
        return
    fi

    IFACE="$(ip route show default 2>/dev/null | awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
    if [[ -z "${IFACE}" ]]; then
        err "interface not set. Use --iface eth0 or TEST_IFACE=eth0"
        exit 1
    fi
}

find_daemon() {
    if [[ -n "${DAEMON_BIN}" ]]; then
        return
    fi

    if [[ -x "${ROOT_DIR}/target/release/goodbyedpi-daemon" ]]; then
        DAEMON_BIN="${ROOT_DIR}/target/release/goodbyedpi-daemon"
    elif [[ -x "${ROOT_DIR}/target/debug/goodbyedpi-daemon" ]]; then
        DAEMON_BIN="${ROOT_DIR}/target/debug/goodbyedpi-daemon"
    else
        err "daemon binary not found. Build: cargo build --release -p goodbyedpi-daemon"
        exit 1
    fi
}

ensure_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        return
    fi

    exec sudo --preserve-env=TEST_IFACE,GBD_DAEMON_BIN,MONITOR_URL,MONITOR_TIMEOUT,MONITOR_RANGE,MONITOR_WARN_MINKB,MONITOR_WARN_MAXKB "$0" "$@"
}

read_choice() {
    local prompt="$1"
    local default="$2"
    local value

    if [[ "${NON_INTERACTIVE}" -eq 1 ]]; then
        printf '%s' "${default}"
        return
    fi

    read -r -p "${prompt}" value
    printf '%s' "${value:-${default}}"
}

select_test_type() {
    if [[ -n "${TEST_TYPE}" ]]; then
        return
    fi

    while true; do
        log ""
        log "Select test type:"
        log "  [1] Standard tests (HTTP/ping)"
        log "  [2] DPI checkers (TCP 16-20 freeze)"
        case "$(read_choice "Enter 1 or 2 [1]: " "1")" in
            1) TEST_TYPE="standard"; return ;;
            2) TEST_TYPE="dpi"; return ;;
            *) warn "incorrect input" ;;
        esac
    done
}

load_configs() {
    if [[ "${#CONFIG_SPECS[@]}" -eq 0 ]]; then
        for cfg in "${DEFAULT_CONFIGS[@]}"; do
            CONFIG_SPECS+=("config:${cfg}")
        done
    fi

    if [[ -z "${SELECT_MODE}" && "${NON_INTERACTIVE}" -eq 0 && "${#CONFIG_SPECS[@]}" -gt 1 ]]; then
        log ""
        log "Select test run mode:"
        log "  [1] All configs"
        log "  [2] Selected configs"
        case "$(read_choice "Enter 1 or 2 [1]: " "1")" in
            2) SELECT_MODE="prompt" ;;
            *) SELECT_MODE="all" ;;
        esac
    fi

    if [[ "${SELECT_MODE}" == "prompt" ]]; then
        log ""
        log "Available configs:"
        local i
        for i in "${!CONFIG_SPECS[@]}"; do
            printf '  [%d] %s\n' "$((i + 1))" "${CONFIG_SPECS[$i]}"
        done
        SELECT_MODE="$(read_choice "Enter numbers/ranges, 0 for all: " "0")"
    fi

    if [[ -n "${SELECT_MODE}" && "${SELECT_MODE}" != "all" && "${SELECT_MODE}" != "0" ]]; then
        local -a selected=()
        local token start end idx
        IFS=', ' read -r -a parts <<<"${SELECT_MODE}"
        for token in "${parts[@]}"; do
            [[ -z "${token}" ]] && continue
            if [[ "${token}" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                start="${BASH_REMATCH[1]}"
                end="${BASH_REMATCH[2]}"
                for ((idx = start; idx <= end; idx++)); do
                    if ((idx >= 1 && idx <= ${#CONFIG_SPECS[@]})); then
                        selected+=("${CONFIG_SPECS[$((idx - 1))]}")
                    fi
                done
            elif [[ "${token}" =~ ^[0-9]+$ ]]; then
                idx="${token}"
                if ((idx >= 1 && idx <= ${#CONFIG_SPECS[@]})); then
                    selected+=("${CONFIG_SPECS[$((idx - 1))]}")
                fi
            fi
        done
        if [[ "${#selected[@]}" -eq 0 ]]; then
            err "no configs selected"
            exit 1
        fi
        CONFIG_SPECS=("${selected[@]}")
    fi
}

load_targets() {
    local target_file="${UTILS_DIR}/targets.txt"
    if [[ -f "${target_file}" ]]; then
        TARGETS=()
        local line key value
        while IFS= read -r line; do
            [[ "${line}" =~ ^[[:space:]]*# ]] && continue
            [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
            [[ "${line}" != *"="* ]] && continue
            key="${line%%=*}"
            value="${line#*=}"
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            value="${value%\"}"
            value="${value#\"}"
            TARGETS+=("${key}=${value}")
        done <"${target_file}"
    else
        TARGETS=("${DEFAULT_TARGETS[@]}")
    fi
}

config_label() {
    local spec="$1"
    case "${spec}" in
        config:*) printf '%s' "${spec#config:}" ;;
        file:*) printf '%s' "$(basename "${spec#file:}")" ;;
    esac
}

start_daemon() {
    local spec="$1"
    local label="$2"
    local log_file="$3"
    local -a args=("${DAEMON_BIN}" -i "${IFACE}" --debug --no-metrics)

    case "${spec}" in
        config:*) args+=(-c "${spec#config:}") ;;
        file:*) args+=(--config-file "${spec#file:}") ;;
    esac

    log "  > Starting daemon: ${label}"
    "${args[@]}" >"${log_file}" 2>&1 &
    local pid=$!
    STARTED_PIDS+=("${pid}")
    DAEMON_PID="${pid}"

    local i
    for i in {1..40}; do
        if grep -qE 'Ring buffer polling started|eBPF programs loaded and attached successfully' "${log_file}" 2>/dev/null; then
            return
        fi
        if ! kill -0 "${pid}" 2>/dev/null; then
            err "daemon exited early"
            tail -n 80 "${log_file}" >&2 || true
            exit 1
        fi
        sleep 0.25
    done

    err "daemon did not start"
    tail -n 120 "${log_file}" >&2 || true
    exit 1
}

stop_daemon() {
    local pid="$1"
    terminate_pid "${pid}"
}

curl_status() {
    local url="$1"
    local label="$2"
    shift 2
    local output exit_code code

    set +e
    output="$(curl -I -s -m 5 -o /dev/null -w '%{http_code}' --show-error "$@" "${url}" 2>&1)"
    exit_code=$?
    set -e

    code="$(printf '%s' "${output}" | tail -c 3)"
    if [[ "${exit_code}" -eq 0 ]]; then
        printf '%s:OK' "${label}"
    elif [[ "${exit_code}" -eq 35 || "${output}" =~ not\ supported|unsupported|Unknown\ option|Unrecognized\ option ]]; then
        printf '%s:UNSUP' "${label}"
    elif [[ "${output}" =~ certificate|Could\ not\ resolve\ host|SSL ]]; then
        printf '%s:SSL' "${label}"
    else
        printf '%s:ERROR(%s)' "${label}" "${code:-NA}"
    fi
}

ping_status() {
    local host="$1"
    local output avg

    set +e
    output="$(ping -c 3 -W 2 "${host}" 2>/dev/null)"
    local exit_code=$?
    set -e

    if [[ "${exit_code}" -ne 0 ]]; then
        printf 'Timeout'
        return
    fi

    avg="$(awk -F'/' '/rtt|round-trip/ { print $5 }' <<<"${output}")"
    if [[ -n "${avg}" ]]; then
        LC_NUMERIC=C printf '%.0f ms' "${avg}"
    else
        printf 'OK'
    fi
}

run_standard_tests() {
    local config_name="$1"
    local max_len=10
    local item name value url ping_target http1 tls12 tls13 ping result_line

    load_targets
    for item in "${TARGETS[@]}"; do
        name="${item%%=*}"
        (( ${#name} > max_len )) && max_len="${#name}"
    done

    for item in "${TARGETS[@]}"; do
        name="${item%%=*}"
        value="${item#*=}"
        url=""
        ping_target=""

        if [[ "${value}" == PING:* ]]; then
            ping_target="${value#PING:}"
        else
            url="${value}"
            ping_target="${url#http://}"
            ping_target="${ping_target#https://}"
            ping_target="${ping_target%%/*}"
        fi

        if [[ -n "${url}" ]]; then
            http1="$(curl_status "${url}" HTTP --http1.1)"
            tls12="$(curl_status "${url}" TLS1.2 --tlsv1.2 --tls-max 1.2)"
            tls13="$(curl_status "${url}" TLS1.3 --tlsv1.3 --tls-max 1.3)"
            ping="$(ping_status "${ping_target}")"
            printf '  %-*s  %-14s %-14s %-14s | Ping: %s\n' "${max_len}" "${name}" "${http1}" "${tls12}" "${tls13}" "${ping}"
            result_line="${config_name}|standard|${name}|${http1} ${tls12} ${tls13}|${ping}"
        else
            ping="$(ping_status "${ping_target}")"
            printf '  %-*s  Ping: %s\n' "${max_len}" "${name}" "${ping}"
            result_line="${config_name}|standard|${name}||${ping}"
        fi

        GLOBAL_ROWS+=("${result_line}")
    done
}

build_dpi_targets() {
    if [[ -n "${DPI_CUSTOM_URL}" ]]; then
        printf 'CUSTOM\tCustom\t%s\n' "${DPI_CUSTOM_URL}"
        return
    fi

    python3 - <<'PY'
import json
import sys
import urllib.request

url = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.json"
try:
    with urllib.request.urlopen(url, timeout=10) as response:
        suite = json.load(response)
except Exception as exc:
    print(f"[WARN] Fetch dpi suite failed: {exc}", file=sys.stderr)
    sys.exit(0)

for entry in suite:
    repeat = int(entry.get("times") or 1)
    for idx in range(repeat):
        suffix = f"@{idx}" if repeat > 1 else ""
        print(f"{entry.get('id', 'UNKNOWN')}{suffix}\t{entry.get('provider', 'UNKNOWN')}\t{entry.get('url', '')}")
PY
}

dpi_curl_one() {
    local url="$1"
    local label="$2"
    shift 2
    local range_end=$((DPI_RANGE_BYTES - 1))
    local output exit_code code size size_kb status

    set +e
    output="$(curl -L --range "0-${range_end}" -m "${DPI_TIMEOUT_SECONDS}" -w '%{http_code} %{size_download}' -o /dev/null -s "$@" "${url}" 2>&1)"
    exit_code=$?
    set -e

    code="NA"
    size="0"
    if [[ "${output}" =~ ^([0-9]{3})[[:space:]]+([0-9]+)$ ]]; then
        code="${BASH_REMATCH[1]}"
        size="${BASH_REMATCH[2]}"
    elif [[ "${exit_code}" -eq 35 || "${output}" =~ not\ supported|unsupported|Unknown\ option|Unrecognized\ option|SSL ]]; then
        code="UNSUP"
    elif [[ -n "${output}" ]]; then
        code="ERR"
    fi

    size_kb="$(awk -v bytes="${size}" 'BEGIN { printf "%.1f", bytes / 1024 }')"
    status="OK"
    if [[ "${code}" == "UNSUP" ]]; then
        status="UNSUPPORTED"
    elif [[ "${exit_code}" -ne 0 || "${code}" == "ERR" || "${code}" == "NA" ]]; then
        status="FAIL"
    fi

    if awk -v kb="${size_kb}" -v min="${DPI_WARN_MIN_KB}" -v max="${DPI_WARN_MAX_KB}" -v curl_exit="${exit_code}" 'BEGIN { exit !((kb >= min) && (kb <= max) && (curl_exit != 0)) }'; then
        status="LIKELY_BLOCKED"
    fi

    printf '%s|%s|%s|%s|%s\n' "${label}" "${code}" "${size}" "${size_kb}" "${status}"
}

run_dpi_tests() {
    local config_name="$1"
    local targets=()
    local line id provider url test_result test label code size size_kb status warned=0

    mapfile -t targets < <(build_dpi_targets)
    if [[ "${#targets[@]}" -eq 0 ]]; then
        warn "DPI suite empty; set MONITOR_URL to test one URL"
        return
    fi

    log "[INFO] Targets: ${#targets[@]}; Range: 0-$((DPI_RANGE_BYTES - 1)); Timeout: ${DPI_TIMEOUT_SECONDS}s; Warn: ${DPI_WARN_MIN_KB}-${DPI_WARN_MAX_KB} KB"

    for line in "${targets[@]}"; do
        IFS=$'\t' read -r id provider url <<<"${line}"
        [[ -z "${url}" ]] && continue
        printf '\n=== %s [%s] ===\n' "${id}" "${provider}"

        for test in "HTTP --http1.1" "TLS1.2 --tlsv1.2 --tls-max 1.2" "TLS1.3 --tlsv1.3 --tls-max 1.3"; do
            read -r label arg1 arg2 arg3 <<<"${test}"
            if [[ -n "${arg3:-}" ]]; then
                test_result="$(dpi_curl_one "${url}" "${label}" "${arg1}" "${arg2}" "${arg3}")"
            else
                test_result="$(dpi_curl_one "${url}" "${label}" "${arg1}")"
            fi
            IFS='|' read -r label code size size_kb status <<<"${test_result}"
            printf '  [%s] code=%s size=%s bytes (%s KB) status=%s\n' "${label}" "${code}" "${size}" "${size_kb}" "${status}"
            [[ "${status}" == "LIKELY_BLOCKED" ]] && warned=1
            GLOBAL_ROWS+=("${config_name}|dpi|${id}|${provider}|${label}|${code}|${size_kb}|${status}")
        done
    done

    if [[ "${warned}" -eq 1 ]]; then
        warn "possible DPI TCP 16-20 blocking detected"
    else
        log "[OK] No 16-20KB freeze pattern detected"
    fi
}

write_results() {
    local result_file="$1"
    local row
    : >"${result_file}"

    for row in "${GLOBAL_ROWS[@]}"; do
        IFS='|' read -r config type rest <<<"${row}"
        printf 'Config: %s Type: %s Data: %s\n' "${config}" "${type}" "${rest}" >>"${result_file}"
    done
}

run_suite() {
    local spec label safe_label daemon_log pid index=0

    log ""
    log "============================================================"
    log "                 GOODBYEDPI LINUX TESTS"
    log "                 Mode: ${TEST_TYPE}"
    log "                 Interface: ${IFACE}"
    log "                 Total configs: ${#CONFIG_SPECS[@]}"
    log "============================================================"

    if [[ "${ORIGINAL_IPSET_STATUS}" != "any" && "${TEST_TYPE}" == "dpi" ]]; then
        warn "ipset is '${ORIGINAL_IPSET_STATUS}'. Switching lists/ipset-all.txt to any for DPI tests"
        set_ipset_mode any
        : >"${IPSET_FLAG_FILE}"
    fi

    for spec in "${CONFIG_SPECS[@]}"; do
        index=$((index + 1))
        label="$(config_label "${spec}")"
        safe_label="$(tr -c 'A-Za-z0-9_.-' '_' <<<"${label}" | cut -c1-80)"
        daemon_log="${RESULTS_DIR}/daemon_${index}_${safe_label}.log"

        log ""
        log "------------------------------------------------------------"
        log "  [${index}/${#CONFIG_SPECS[@]}] ${label}"
        log "------------------------------------------------------------"

        start_daemon "${spec}" "${label}" "${daemon_log}"
        pid="${DAEMON_PID}"
        sleep 2

        if [[ "${TEST_TYPE}" == "standard" ]]; then
            run_standard_tests "${label}"
        else
            run_dpi_tests "${label}"
        fi

        stop_daemon "${pid}"
    done
}

main() {
    parse_args "$@"
    ensure_root "$@"

    require_cmd ip
    require_cmd awk
    require_cmd curl
    require_cmd ping
    require_cmd python3

    if [[ ! -f "${ROOT_DIR}/ebpf/src/vmlinux.h" ]]; then
        err "run from repository root"
        exit 1
    fi

    mkdir -p "${RESULTS_DIR}"
    detect_iface
    find_daemon

    if [[ -f "${IPSET_FLAG_FILE}" ]]; then
        warn "leftover ipset switch flag detected; restoring ipset"
        set_ipset_mode restore
        rm -f "${IPSET_FLAG_FILE}"
    fi

    ORIGINAL_IPSET_STATUS="$(ipset_status)"
    if [[ "${ORIGINAL_IPSET_STATUS}" != "any" ]]; then
        warn "current ipset status: ${ORIGINAL_IPSET_STATUS}"
    fi

    select_test_type
    load_configs

    run_suite

    local date_str result_file
    date_str="$(date '+%Y-%m-%d_%H-%M-%S')"
    result_file="${RESULTS_DIR}/test_results_${date_str}.txt"
    write_results "${result_file}"

    log ""
    log "All tests finished."
    log "Results saved to ${result_file}"
}

main "$@"
