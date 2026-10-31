#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY=https://github.com/spark108/pnt.git
INSTALL_DIR=/opt/pnt
BIN=$INSTALL_DIR/pnt
LINK=/usr/local/bin/pnt
UNIT=/etc/systemd/system/pnt.service
SOURCE_FILE=/etc/pnt/source-dir
INVOKER_FILE=/etc/pnt/invoker
OPERATIONS=/var/lib/pnt/operations

usage() {
    cat <<'EOF'
Usage: sudo ./pnt.sh <command>

  install                 Install PNT on this Debian server
  install -r root@ip      Install on another server and join it to this cluster
  update                  Update this server and announce it to the cluster
  update --check          Check GitHub without installing or stopping the service
  start                   Start pnt.service
  stop                    Stop pnt.service
  restart                 Restart pnt.service
  status                  Show service and recent operation status

Install and update run in a background systemd unit. Completed stages are
shown here; closing the terminal does not stop the operation.
Repository: https://github.com/spark108/pnt.git
EOF
}

die() { printf 'pnt.sh: %s\n' "$*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || die 'Run with sudo or as root.'; [ "$(uname -s)" = Linux ] || die 'Debian Linux is required.'; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }
require_access() { [ "$(id -u)" -eq 0 ] || id -Gn | tr ' ' '\n' | grep -qx pnt || die 'Only root or members of pnt may use PNT.'; }
invoker() { printf '%s\n' "${PNT_INVOKER:-${SUDO_USER:-root}}"; }
as_invoker() { if [ "$(invoker)" = root ]; then "$@"; else runuser -u "$(invoker)" -- "$@"; fi; }

runtime_id() {
    case "$(uname -m)" in
        x86_64) printf '%s\n' linux-x64 ;;
        aarch64) printf '%s\n' linux-arm64 ;;
        *) die 'Only x64 and ARM64 are supported.' ;;
    esac
}

step() {
    CURRENT_STAGE=$1
    shift
    "$@"
    printf '✓ %s\n' "$CURRENT_STAGE" >> "$PROGRESS"
}

install_dependencies() {
    require_command apt-get
    [ -r /etc/os-release ] || die 'Cannot read /etc/os-release.'
    . /etc/os-release
    [ "$ID" = debian ] || die 'Automatic installation supports Debian only.'
    case "$VERSION_ID" in
        12) icu_package=libicu72; ssl_package=libssl3 ;;
        13) icu_package=libicu76; ssl_package=libssl3t64 ;;
        *) die 'Debian 12 or 13 is required.' ;;
    esac
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl git openssh-client systemd nftables iptables util-linux python3 \
        libc6 libgcc-s1 libgssapi-krb5-2 libstdc++6 tzdata zlib1g "$icu_package" "$ssl_package"
    if ! dpkg-query -W -f='${Status}' packages-microsoft-prod 2>/dev/null | grep -q 'install ok installed'; then
        curl -fsSL "https://packages.microsoft.com/config/debian/$VERSION_ID/packages-microsoft-prod.deb" \
            -o "$TEMP_DIR/packages-microsoft-prod.deb"
        dpkg -i "$TEMP_DIR/packages-microsoft-prod.deb"
        apt-get update
    fi
    apt-get install -y libmsquic
    if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks 2>/dev/null | grep -q '^10\.'; then
        apt-get install -y dotnet-sdk-10.0
    fi
    dotnet --list-sdks | grep -q '^10\.' || die '.NET 10 SDK installation failed.'
}

publish_source() {
    [ -f "$SCRIPT_DIR/pnt.csproj" ] || die 'pnt.csproj is missing.'
    as_invoker dotnet publish "$SCRIPT_DIR/pnt.csproj" -c Release -r "$(runtime_id)" --self-contained true \
        -p:PublishSingleFile=true -o "$TEMP_DIR/build"
    [ -s "$TEMP_DIR/build/pnt" ] || die 'Build did not produce pnt.'
}

save_source_dir() {
    install -d -m 700 /etc/pnt
    printf '%s\n' "$SCRIPT_DIR" > "$SOURCE_FILE"
    printf '%s\n' "$(invoker)" > "$INVOKER_FILE"
    chmod 600 "$SOURCE_FILE" "$INVOKER_FILE"
}

configure_access() {
    "$BIN" _prepare-access
    chown root:pnt "$BIN"
    chmod 750 "$BIN"
}

install_local() {
    [ ! -e "$BIN" ] || die 'PNT is already installed; use update.'
    step 'Зависимости Debian и .NET установлены' install_dependencies
    if [ "$(invoker)" != root ]; then chown "$(invoker)" "$TEMP_DIR"; fi
    step 'Бинарник собран' publish_source
    install -d -m 755 "$INSTALL_DIR"
    install -d -m 700 /var/lib/pnt
    INSTALLED=1
    install -m 755 "$TEMP_DIR/build/pnt" "$BIN"
    ln -sfn "$BIN" "$LINK"
    install -m 644 "$SCRIPT_DIR/deploy/pnt.service" "$UNIT"
    save_source_dir
    step 'Группа pnt и права доступа настроены' configure_access
    systemctl daemon-reload
    systemctl enable --now pnt.service
    sleep 2
    systemctl is-active --quiet pnt.service || die 'Service did not start.'
    printf '✓ Служба установлена и запущена\n' >> "$PROGRESS"
}

refresh_update_sources() {
    require_command git
    [ -f "$BIN" ] || die 'PNT is not installed.'
    [ -f "$UNIT" ] || die 'pnt.service is missing.'
    checkout=$(as_invoker git -C "$SCRIPT_DIR" rev-parse --show-toplevel) || die 'Git checkout is required.'
    [ "$checkout" = "$SCRIPT_DIR" ] || die 'Run pnt.sh from the checkout root.'
    branch=$(as_invoker git -C "$SCRIPT_DIR" symbolic-ref --quiet --short HEAD) || die 'A Git branch is required.'
    as_invoker git -C "$SCRIPT_DIR" remote set-url origin "$REPOSITORY"
    as_invoker git -C "$SCRIPT_DIR" pull --ff-only origin "$branch"
}

update_local() {
    BACKUP_BIN=$(mktemp "$INSTALL_DIR/.pnt-old.XXXXXX")
    cp -p "$BIN" "$BACKUP_BIN"
    cp -p "$UNIT" "$TEMP_DIR/pnt.service.old"
    OLD_ACTIVE=0
    if systemctl is-active --quiet pnt.service; then OLD_ACTIVE=1; fi
    if "$BIN" node status --require-cluster >/dev/null 2>&1; then
        if "$BIN" node maintenance start; then
            MAINT_STARTED=1
            printf '✓ Статус update разослан узлам кластера\n' >> "$PROGRESS"
            sleep 8
        else
            printf '%s\n' 'Текущий бинарник ещё не поддерживает статус update; он появится после этого обновления.'
        fi
    fi
    systemctl stop pnt.service
    STOPPED=1
    printf '✓ Служба остановлена\n' >> "$PROGRESS"
    step 'Зависимости Debian и QUIC установлены' install_dependencies
    if [ "$(invoker)" != root ]; then chown "$(invoker)" "$TEMP_DIR"; fi
    step 'Бинарник собран' as_invoker dotnet publish "$SCRIPT_DIR/pnt.csproj" -c Release \
        -r "$(runtime_id)" --self-contained true -p:PublishSingleFile=true -o "$TEMP_DIR/build"
    [ -s "$TEMP_DIR/build/pnt" ] || die 'Build did not produce pnt.'
    STAGED_BIN=$(mktemp "$INSTALL_DIR/.pnt-new.XXXXXX")
    install -m 755 "$TEMP_DIR/build/pnt" "$STAGED_BIN"
    mv -f "$STAGED_BIN" "$BIN"
    STAGED_BIN=''
    SWAPPED=1
    install -m 644 "$SCRIPT_DIR/deploy/pnt.service" "$UNIT"
    save_source_dir
    step 'Группа pnt и права доступа настроены' configure_access
    systemctl daemon-reload
    systemctl start pnt.service
    sleep 2
    systemctl is-active --quiet pnt.service || die 'Updated service did not start.'
    printf '✓ Служба запущена с новой версией\n' >> "$PROGRESS"
    if [ "$MAINT_STARTED" -eq 1 ]; then
        step 'Статус update снят' "$BIN" node maintenance done
        MAINT_STARTED=0
    fi
    if [ -n "$EVENT_ID" ]; then
        step 'Обновление узла подтверждено' "$BIN" node update applied "$EVENT_ID"
    elif "$BIN" node status --require-cluster >/dev/null 2>&1; then
        commit=$(as_invoker git -C "$SCRIPT_DIR" rev-parse HEAD)
        step 'Обновление объявлено кластеру' "$BIN" node update announce "$commit"
    fi
    UPDATE_OK=1
}

remote_ssh() { ssh -S "$SSH_SOCKET" -o BatchMode=yes "$REMOTE_HOST" "$@"; }

install_remote() {
    REMOTE_HOST=$1
    SSH_SOCKET=$2
    remote_ip=${REMOTE_HOST#root@}
    step 'Связь с удалённым сервером установлена' remote_ssh true
    if remote_ssh 'test -x /usr/local/bin/pnt && pnt node status --require-cluster >/dev/null 2>&1'; then
        die 'The remote server already belongs to a cluster.'
    fi
    CURRENT_STAGE='PNT установлен на удалённом сервере'
    remote_ssh "set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y git ca-certificates; touch /etc/default/pnt; sed -i '/^PNT_ADVERTISE_IP=/d' /etc/default/pnt; printf 'PNT_ADVERTISE_IP=%s\\n' '$remote_ip' >> /etc/default/pnt; if [ -d /root/pnt/.git ]; then git -C /root/pnt remote set-url origin $REPOSITORY; git -C /root/pnt pull --ff-only origin master; else git clone $REPOSITORY /root/pnt; fi; if [ -x /usr/local/bin/pnt ]; then /root/pnt/pnt.sh update; else /root/pnt/pnt.sh install; fi"
    printf '✓ %s\n' "$CURRENT_STAGE" >> "$PROGRESS"
    CURRENT_STAGE='Заявка нового узла отправлена'
    entry_ip=$("$BIN" node status --require-cluster | sed -n 's/^IP: //p')
    remote_id=$(remote_ssh 'pnt node identity')
    printf '%s\n' "$remote_id" | grep -Eq '^[0-9a-f]{16}$' || die 'The remote node returned an invalid identity.'
    remote_ssh "pnt node join '$entry_ip'"
    printf '✓ %s\n' "$CURRENT_STAGE" >> "$PROGRESS"
    CURRENT_STAGE='Подключение нового узла подтверждено'
    attempts=0
    until "$BIN" node requests | grep -q "^$remote_id "; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 30 ] || die 'The new node did not send its enrollment request.'
        sleep 1
    done
    "$BIN" node accept "$remote_id"
    attempts=0
    until remote_ssh 'pnt node status --require-cluster >/dev/null 2>&1'; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 30 ] || die 'The new node did not receive approval.'
        sleep 1
    done
    printf '✓ %s\n' "$CURRENT_STAGE" >> "$PROGRESS"
}

finish_worker() {
    code=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$code" -ne 0 ]; then
        if [ "$ACTION" = install ] && [ "$INSTALLED" -eq 1 ]; then
            systemctl disable --now pnt.service >/dev/null 2>&1
            rm -f "$LINK" "$BIN" "$UNIT"
            systemctl daemon-reload
        fi
        if [ "$ACTION" = update ] && [ "$UPDATE_OK" -eq 0 ]; then
            if [ "$SWAPPED" -eq 1 ]; then
                mv -f "$BACKUP_BIN" "$BIN"
                BACKUP_BIN=''
                install -m 644 "$TEMP_DIR/pnt.service.old" "$UNIT"
                systemctl daemon-reload
            fi
            if [ "$STOPPED" -eq 1 ] && [ "$OLD_ACTIVE" -eq 1 ]; then systemctl start pnt.service; fi
            if [ "$MAINT_STARTED" -eq 1 ]; then "$BIN" node maintenance done; fi
        fi
        printf '✗ %s\n' "${CURRENT_STAGE:-Операция завершилась ошибкой}" >> "$PROGRESS"
    fi
    if [ -n "$SSH_SOCKET" ] && [ -n "$REMOTE_HOST" ]; then
        ssh -S "$SSH_SOCKET" -O exit "$REMOTE_HOST" >/dev/null 2>&1
    fi
    [ -z "$STAGED_BIN" ] || rm -f "$STAGED_BIN"
    [ -z "$BACKUP_BIN" ] || rm -f "$BACKUP_BIN"
    [ -z "$TEMP_DIR" ] || rm -rf "$TEMP_DIR"
    printf '%s\n' "$code" > "$RESULT"
    exit "$code"
}

worker() {
    require_root
    ACTION=$1
    OP_ID=$2
    EVENT_ID=${3:-}
    CURRENT_WORKER=${4:-}
    SSH_SOCKET=''
    REMOTE_HOST=''
    if [ "$ACTION" = remote ]; then REMOTE_HOST=$3; SSH_SOCKET=$4; EVENT_ID=''; fi
    case "$OP_ID" in *[!a-zA-Z0-9-]*|'') die 'Invalid operation ID.' ;; esac
    install -d -m 700 "$OPERATIONS"
    PROGRESS=$OPERATIONS/$OP_ID.progress
    RESULT=$OPERATIONS/$OP_ID.result
    LOG=$OPERATIONS/$OP_ID.log
    if [ "$CURRENT_WORKER" != current ]; then rm -f "$RESULT"; : > "$PROGRESS"; fi
    exec >> "$LOG" 2>&1
    TEMP_DIR=''
    STAGED_BIN=''
    BACKUP_BIN=''
    SWAPPED=0
    STOPPED=0
    OLD_ACTIVE=0
    UPDATE_OK=0
    MAINT_STARTED=0
    INSTALLED=0
    CURRENT_STAGE='Подготовка'
    trap finish_worker EXIT
    trap 'exit 1' HUP INT TERM
    require_command flock
    if [ "$CURRENT_WORKER" = current ]; then
        [ "$ACTION" = update ] && [ "${PNT_UPDATE_HANDOFF:-}" = "$OP_ID" ] || die 'Invalid update handoff.'
        unset PNT_UPDATE_HANDOFF
    else
        exec 9>/run/pnt-maintenance.lock
    fi
    flock -n 9 || die 'Another PNT installation or update is already running.'
    if [ "$ACTION" = update ] && [ "$CURRENT_WORKER" != current ]; then
        step 'Исходники обновлены из GitHub' refresh_update_sources
        export PNT_UPDATE_HANDOFF="$OP_ID"
        exec /bin/sh "$SCRIPT_DIR/pnt.sh" _worker-current "$OP_ID" "$EVENT_ID"
    fi
    TEMP_DIR=$(mktemp -d)
    case "$ACTION" in
        install) install_local ;;
        update) update_local ;;
        remote) install_remote "$REMOTE_HOST" "$SSH_SOCKET" ;;
        *) die 'Unknown worker action.' ;;
    esac
}

watch_operation() {
    op_id=$1
    progress_file=$OPERATIONS/$op_id.progress
    result_file=$OPERATIONS/$op_id.result
    log_file=$OPERATIONS/$op_id.log
    shown=0
    while :; do
        if [ -f "$progress_file" ]; then
            lines=$(wc -l < "$progress_file")
            if [ "$lines" -gt "$shown" ]; then
                sed -n "$((shown + 1)),${lines}p" "$progress_file"
                shown=$lines
            fi
        fi
        if [ -f "$result_file" ]; then
            result=$(cat "$result_file")
            if [ "$result" -ne 0 ]; then tail -n 15 "$log_file" >&2; fi
            return "$result"
        fi
        if ! systemctl is-active --quiet "pnt-operation-$op_id"; then
            printf '✗ Фоновый процесс завершился без результата\n' >&2
            tail -n 15 "$log_file" >&2
            return 1
        fi
        sleep 1
    done
}

launch_operation() {
    require_root
    require_command systemd-run
    action=$1
    shift
    install -d -m 700 "$OPERATIONS"
    op_id=$(date +%s)-$$
    printf 'Запущена фоновая операция: %s\n' "$action"
    if ! systemd-run --unit="pnt-operation-$op_id" --collect --property=Type=exec --setenv="PNT_INVOKER=$(invoker)" \
        /bin/sh "$SCRIPT_DIR/pnt.sh" _worker "$action" "$op_id" "$@" >/dev/null; then
        if [ "$action" = remote ]; then ssh -S "$2" -O exit "$1" >/dev/null 2>&1 || true; fi
        die 'Could not launch background worker.'
    fi
    watch_operation "$op_id"
}

start_remote_install() {
    require_root
    require_command ssh
    host=$1
    printf '%s\n' "$host" | grep -Eq '^root@([0-9]{1,3}\.){3}[0-9]{1,3}$' || die 'Use root@IPv4.'
    ip=${host#root@}
    old_ifs=$IFS
    IFS=.
    set -- $ip
    IFS=$old_ifs
    for octet do [ "$octet" -le 255 ] || die 'Invalid IPv4 address.'; done
    "$BIN" node status --require-cluster >/dev/null || die 'Create or join a cluster on this server first.'
    install -d -m 700 /run/pnt
    socket=/run/pnt/ssh-$(date +%s)-$$.sock
    ssh -M -S "$socket" -o ControlPersist=3600 -fN "$host"
    launch_operation remote "$host" "$socket"
}

command_name=${1:-}
require_access
if [ "$#" -gt 0 ]; then shift; fi
case "$command_name" in
    install)
        case "$#" in
            0) launch_operation install ;;
            2) [ "$1" = -r ] || die 'Use install -r root@ip.'; start_remote_install "$2" ;;
            *) die 'Use install or install -r root@ip.' ;;
        esac ;;
    update)
        if [ "$#" -eq 1 ] && [ "$1" = --check ]; then exec "$BIN" update --check; fi
        [ "$#" -eq 0 ] || die 'Use update or update --check.'
        launch_operation update ;;
    _worker) worker "$@" ;;
    _worker-current) worker update "$1" "${2:-}" current ;;
    start) require_root; systemctl start pnt.service ;;
    stop) require_root; systemctl stop pnt.service ;;
    restart) require_root; systemctl restart pnt.service ;;
    status)
        systemctl status --no-pager --full pnt.service || true
        if [ -d "$OPERATIONS" ]; then
            latest=$(ls -t "$OPERATIONS"/*.progress 2>/dev/null | head -n 1 || true)
            if [ -n "$latest" ]; then printf '\nПоследняя операция:\n'; cat "$latest"; fi
        fi ;;
    help|--help|-h|'') usage ;;
    *) usage >&2; exit 2 ;;
esac
