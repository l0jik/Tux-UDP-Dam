#!/usr/bin/env bash
set -u
set -o pipefail

APP_NAME="TuxUdpDam"
STATE_DIR="/var/lib/tuxudpdam"
LOG_FILE="${STATE_DIR}/tux_udp_dam.log"
STATE_FILE="${STATE_DIR}/state.json"
WATCHER_PID_FILE="${STATE_DIR}/watcher.pid"
ALLOW_LIST_FILE="${STATE_DIR}/allow_programs.txt"

NFT_FAMILY="inet"
NFT_TABLE="tuxudpdam"
NFT_CHAIN="output"
CGROUP_ROOT="/sys/fs/cgroup"
CGROUP_PREFIX="tuxudpdam-"

BLOCK_MODE_ALLOW_DNS=0
COMMAND=""
ALLOW_PROGRAMS=()

mkdir -p "${STATE_DIR}"

# ✅ Banner cyber minimale
print_banner() {
echo -e "\033[1;32m:: Tux-UDP-Dam ::\033[0m"
}

log() {
    local level="$1"; shift
    printf '%s | %s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${level}" "$*" >> "${LOG_FILE}"
}

log_and_print() {
    local level="$1"; shift
    echo "$*"
    log "${level}" "$*"
}

die() {
    log_and_print "ERROR" "Error: $*"
    exit 1
}

ensure_root() {
    [ "$(id -u)" -eq 0 ] || die "run this script as root."
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

ensure_env() {
    require_cmd nft
    require_cmd ss
    require_cmd sha256sum
    [ -f "${CGROUP_ROOT}/cgroup.controllers" ] || die "cgroup v2 not detected"
}

normalize_path() {
    readlink -f "$1" 2>/dev/null | grep -q . || return 1
    local rp
    rp="$(readlink -f "$1")"
    [ -f "$rp" ] || return 1
    echo "$rp"
}

hash_program() {
    echo -n "$1" | sha256sum | cut -c1-12
}

cgroup_name_for_program() {
    echo "${CGROUP_PREFIX}$(hash_program "$1")"
}

cgroup_path_for_program() {
    echo "${CGROUP_ROOT}/$(cgroup_name_for_program "$1")"
}

remove_nft_table_if_exists() {
    nft list table ${NFT_FAMILY} ${NFT_TABLE} >/dev/null 2>&1 && \
    nft delete table ${NFT_FAMILY} ${NFT_TABLE}
}

create_cgroups() {
    for p in "${ALLOW_PROGRAMS[@]}"; do
        mkdir -p "$(cgroup_path_for_program "$p")"
    done
}

build_rules() {
cat <<EOF
table ${NFT_FAMILY} ${NFT_TABLE} {
 chain ${NFT_CHAIN} {
  type filter hook output priority 0; policy accept;
EOF

    for p in "${ALLOW_PROGRAMS[@]}"; do
        cg="$(cgroup_name_for_program "$p")"
        echo "  socket cgroupv2 level 1 \"$cg\" udp accept"
    done

    [ "$BLOCK_MODE_ALLOW_DNS" -eq 1 ] && echo "  udp dport 53 accept"
    echo "  meta l4proto udp drop"

cat <<EOF
 }
}
EOF
}

apply_rules() {
    build_rules | nft -f -
}

move_matching_pids_once() {
    for p in "${ALLOW_PROGRAMS[@]}"; do
        cg="$(cgroup_path_for_program "$p")"
        for pid in /proc/[0-9]*; do
            exe="$(readlink -f "$pid/exe" 2>/dev/null || true)"
            [ "$exe" = "$p" ] && echo "${pid##*/}" > "$cg/cgroup.procs" 2>/dev/null || true
        done
    done
}

watcher() {
    while true; do
        move_matching_pids_once
        sleep 2
    done
}

start_watcher() {
    watcher &
    echo $! > "$WATCHER_PID_FILE"
}

stop_watcher() {
    [ -f "$WATCHER_PID_FILE" ] && kill "$(cat "$WATCHER_PID_FILE")" 2>/dev/null || true
    rm -f "$WATCHER_PID_FILE"
}

enable_cmd() {
    ensure_root; ensure_env
    create_cgroups
    remove_nft_table_if_exists
    apply_rules
    start_watcher
    log_and_print INFO "UDP blocking enabled"
}

disable_cmd() {
    ensure_root
    stop_watcher
    remove_nft_table_if_exists
    log_and_print INFO "Rules removed"
}

status_cmd() {
    echo "=== STATUS ==="
    nft list table ${NFT_FAMILY} ${NFT_TABLE} 2>/dev/null || echo "No rules"
    echo
    ss -u -a -n -p || true
}

parse_args() {
    COMMAND="$1"; shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --allow-dns) BLOCK_MODE_ALLOW_DNS=1 ;;
            --allow-program)
                shift
                p=$(normalize_path "$1") || die "invalid path"
                ALLOW_PROGRAMS+=("$p")
                ;;
        esac
        shift
    done
}

main() {
    touch "$LOG_FILE"
    print_banner   # 🔥 sempre mostrato
    log "INFO" "Command: $*"

    parse_args "$@"

    case "$COMMAND" in
        enable) enable_cmd ;;
        disable) disable_cmd ;;
        status) status_cmd ;;
        *) die "invalid command" ;;
    esac
}

main "$@"
