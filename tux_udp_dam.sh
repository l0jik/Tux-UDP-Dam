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

RULE_COMMENT_DROP="TuxUdpDam drop outbound UDP"
RULE_COMMENT_DNS="TuxUdpDam allow DNS UDP/53"
RULE_COMMENT_ALLOW_PREFIX="TuxUdpDam allow cgroup "

BLOCK_MODE_ALLOW_DNS=0
COMMAND=""
ALLOW_PROGRAMS=()

mkdir -p "${STATE_DIR}"

log() {
    local level="$1"
    shift
    local msg="$*"
    printf '%s | %s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${level}" "${msg}" >> "${LOG_FILE}"
}

log_and_print() {
    local level="$1"
    shift
    local msg="$*"
    printf '%s\n' "${msg}"
    log "${level}" "${msg}"
}

die() {
    log_and_print "ERROR" "Error: $*"
    exit 1
}

ensure_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "run this script as root."
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found in PATH: $1"
}

ensure_env() {
    require_cmd nft
    require_cmd ss
    require_cmd sha256sum
    [ -f "${CGROUP_ROOT}/cgroup.controllers" ] || die "cgroup v2 not detected at ${CGROUP_ROOT}"
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "${s}"
}

normalize_path() {
    local p="$1"
    local rp
    rp="$(readlink -f -- "$p" 2>/dev/null)" || return 1
    [ -f "${rp}" ] || return 1
    printf '%s\n' "${rp}"
}

dedupe_allow_programs() {
    local tmp=()
    local seen=""
    local p
    for p in "${ALLOW_PROGRAMS[@]}"; do
        if [[ ":${seen}:" != *":${p}:"* ]]; then
            tmp+=("${p}")
            seen="${seen}:${p}"
        fi
    done
    ALLOW_PROGRAMS=("${tmp[@]}")
}

hash_program() {
    local p="$1"
    printf '%s' "${p}" | sha256sum | awk '{print substr($1,1,12)}'
}

cgroup_name_for_program() {
    local p="$1"
    printf '%s%s\n' "${CGROUP_PREFIX}" "$(hash_program "$p")"
}

cgroup_path_for_program() {
    local p="$1"
    printf '%s/%s\n' "${CGROUP_ROOT}" "$(cgroup_name_for_program "$p")"
}

nft_table_exists() {
    nft list table "${NFT_FAMILY}" "${NFT_TABLE}" >/dev/null 2>&1
}

remove_nft_table_if_exists() {
    if nft_table_exists; then
        nft delete table "${NFT_FAMILY}" "${NFT_TABLE}" || die "unable to delete nft table"
    fi
}

create_cgroups() {
    local p cg
    for p in "${ALLOW_PROGRAMS[@]}"; do
        cg="$(cgroup_path_for_program "$p")"
        mkdir -p "${cg}" || die "unable to create cgroup ${cg}"
    done
}

write_allow_list() {
    : > "${ALLOW_LIST_FILE}" || die "unable to write ${ALLOW_LIST_FILE}"
    local p
    for p in "${ALLOW_PROGRAMS[@]}"; do
        printf '%s\n' "${p}" >> "${ALLOW_LIST_FILE}"
    done
}

build_nft_ruleset() {
    local p cg_name
    cat <<EOF
table ${NFT_FAMILY} ${NFT_TABLE} {
  chain ${NFT_CHAIN} {
    type filter hook output priority 0; policy accept;
EOF

    for p in "${ALLOW_PROGRAMS[@]}"; do
        cg_name="$(cgroup_name_for_program "$p")"
        printf '    socket cgroupv2 level 1 "%s" udp counter accept comment "%s%s";\n' \
            "${cg_name}" "${RULE_COMMENT_ALLOW_PREFIX}" "${cg_name}"
    done

    if [ "${BLOCK_MODE_ALLOW_DNS}" -eq 1 ]; then
        printf '    udp dport 53 counter accept comment "%s";\n' "${RULE_COMMENT_DNS}"
    fi

    printf '    meta l4proto udp counter drop comment "%s";\n' "${RULE_COMMENT_DROP}"

    cat <<EOF
  }
}
EOF
}

apply_nft_ruleset() {
    local tmp
    tmp="$(mktemp)"
    build_nft_ruleset > "${tmp}"
    log "INFO" "Applying nft ruleset from ${tmp}"
    nft -f "${tmp}" || {
        rm -f "${tmp}"
        die "nft failed to apply ruleset"
    }
    rm -f "${tmp}"
}

collect_udp_snapshot_json() {
    local first=1
    printf '['
    ss -u -a -n -p -H 2>/dev/null | while IFS= read -r line; do
        local esc
        esc="$(json_escape "$line")"
        if [ "${first}" -eq 1 ]; then
            first=0
            printf '{"raw":"%s"}' "${esc}"
        else
            printf ',{"raw":"%s"}' "${esc}"
        fi
    done
    printf ']'
}

save_state() {
    local enabled_at snapshot
    enabled_at="$(date '+%Y-%m-%dT%H:%M:%S')"
    snapshot="$(collect_udp_snapshot_json)"

    {
        printf '{\n'
        printf '  "enabled_at": "%s",\n' "$(json_escape "${enabled_at}")"
        if [ "${BLOCK_MODE_ALLOW_DNS}" -eq 1 ]; then
            printf '  "allow_dns": true,\n'
        else
            printf '  "allow_dns": false,\n'
        fi

        printf '  "exempt_programs": ['
        local i
        for i in "${!ALLOW_PROGRAMS[@]}"; do
            [ "$i" -gt 0 ] && printf ', '
            printf '"%s"' "$(json_escape "${ALLOW_PROGRAMS[$i]}")"
        done
        printf '],\n'

        printf '  "cgroups": {\n'
        local count=0
        local p
        for p in "${ALLOW_PROGRAMS[@]}"; do
            [ "${count}" -gt 0 ] && printf ',\n'
            printf '    "%s": "%s"' \
                "$(json_escape "${p}")" \
                "$(json_escape "$(cgroup_path_for_program "$p")")"
            count=$((count + 1))
        done
        printf '\n  },\n'

        printf '  "udp_snapshot_before_enable": %s\n' "${snapshot}"
        printf '}\n'
    } > "${STATE_FILE}" || die "unable to write state file"
}

move_matching_pids_once() {
    [ -f "${ALLOW_LIST_FILE}" ] || return 0

    local p cg pid exe
    while IFS= read -r p; do
        [ -n "${p}" ] || continue
        cg="$(cgroup_path_for_program "$p")"
        [ -d "${cg}" ] || mkdir -p "${cg}" || continue

        for pid_dir in /proc/[0-9]*; do
            [ -d "${pid_dir}" ] || continue
            pid="${pid_dir##*/}"

            exe="$(readlink -f "${pid_dir}/exe" 2>/dev/null || true)"
            [ -n "${exe}" ] || continue

            if [ "${exe}" = "${p}" ]; then
                printf '%s\n' "${pid}" > "${cg}/cgroup.procs" 2>/dev/null || true
            fi
        done
    done < "${ALLOW_LIST_FILE}"
}

watcher_loop() {
    while true; do
        move_matching_pids_once
        sleep 2
    done
}

start_watcher() {
    stop_watcher_silent
    watcher_loop >/dev/null 2>&1 &
    echo "$!" > "${WATCHER_PID_FILE}"
    log "INFO" "Watcher started with PID $(cat "${WATCHER_PID_FILE}")"
}

stop_watcher_silent() {
    if [ -f "${WATCHER_PID_FILE}" ]; then
        local pid
        pid="$(cat "${WATCHER_PID_FILE}" 2>/dev/null || true)"
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            sleep 1
            kill -9 "${pid}" 2>/dev/null || true
        fi
        rm -f "${WATCHER_PID_FILE}"
    fi
}

cleanup_cgroups() {
    if [ -f "${ALLOW_LIST_FILE}" ]; then
        local p cg
        while IFS= read -r p; do
            [ -n "${p}" ] || continue
            cg="$(cgroup_path_for_program "$p")"
            [ -d "${cg}" ] || continue

            if [ ! -s "${cg}/cgroup.procs" ] 2>/dev/null; then
                rmdir "${cg}" 2>/dev/null || true
            fi
        done < "${ALLOW_LIST_FILE}"
    fi
}

status_cmd() {
    echo "TuxUdpDam nftables rules:"
    if nft_table_exists; then
        nft list table "${NFT_FAMILY}" "${NFT_TABLE}" 2>/dev/null || true
    else
        echo "  none"
    fi

    if [ -f "${STATE_FILE}" ]; then
        echo
        echo "Saved state:"
        cat "${STATE_FILE}"
    fi

    echo
    echo "Watcher:"
    if [ -f "${WATCHER_PID_FILE}" ]; then
        local pid
        pid="$(cat "${WATCHER_PID_FILE}" 2>/dev/null || true)"
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            echo "  running (pid=${pid})"
        else
            echo "  stale pid file"
        fi
    else
        echo "  not running"
    fi

    echo
    echo "UDP endpoints:"
    if ! ss -u -a -n -p -H 2>/dev/null; then
        echo "  Error: unable to enumerate UDP endpoints."
    fi

    echo
    echo "Log file:   ${LOG_FILE}"
    echo "State file: ${STATE_FILE}"
}

enable_cmd() {
    ensure_root
    ensure_env

    create_cgroups
    write_allow_list
    move_matching_pids_once

    remove_nft_table_if_exists
    apply_nft_ruleset
    start_watcher
    save_state

    log_and_print "INFO" "Outbound UDP blocking enabled."

    if [ "${BLOCK_MODE_ALLOW_DNS}" -eq 1 ]; then
        log_and_print "INFO" "UDP DNS on destination port 53 is NOT blocked."
        log_and_print "INFO" "Note: DNS over TCP/53, DoH and DoT are not covered by this exception."
    fi

    if [ "${#ALLOW_PROGRAMS[@]}" -gt 0 ]; then
        log_and_print "INFO" "Allowed UDP for these programs:"
        local p
        for p in "${ALLOW_PROGRAMS[@]}"; do
            log_and_print "INFO" "  - ${p}"
        done
        log_and_print "INFO" "Note: Linux exemption is best-effort via cgroup v2 + watcher."
    fi
}

disable_cmd() {
    ensure_root
    ensure_env

    stop_watcher_silent
    remove_nft_table_if_exists
    cleanup_cgroups

    log_and_print "INFO" "TuxUdpDam rules removed."
}

parse_args() {
    [ "$#" -ge 1 ] || die "usage: $0 {enable|disable|status} [--allow-dns] [--allow-program PATH]"

    COMMAND="$1"
    shift

    case "${COMMAND}" in
        enable|disable|status) ;;
        *)
            die "invalid command: ${COMMAND}"
            ;;
    esac

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --allow-dns)
                BLOCK_MODE_ALLOW_DNS=1
                shift
                ;;
            --allow-program)
                [ "$#" -ge 2 ] || die "--allow-program requires PATH"
                local norm
                norm="$(normalize_path "$2")" || die "invalid executable path: $2"
                ALLOW_PROGRAMS+=("${norm}")
                shift 2
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
    done

    dedupe_allow_programs
}

main() {
    touch "${LOG_FILE}" 2>/dev/null || true
    log_and_print "INFO" "Requested command: $*"

    parse_args "$@"

    case "${COMMAND}" in
        enable)
            enable_cmd
            ;;
        disable)
            disable_cmd
            ;;
        status)
            status_cmd
            ;;
    esac
}

main "$@"
