#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR=/opt/pnt
BIN=$INSTALL_DIR/pnt
LINK=/usr/local/bin/pnt
UNIT=/etc/systemd/system/pnt.service
REPO_CONFIG=/etc/pnt/update.conf
DEFAULT_REPOSITORY=ssh://git@162.55.1.114:4022/spark108/pnt.git

usage() {
    cat <<'EOF'
Usage: sudo ./pnt.sh <command>

  install                 Build the current source and install the systemd service
  update [repository_url] Clone, build, and install an update from the private repository
  start                   Start pnt.service
  stop                    Stop pnt.service
  restart                 Restart pnt.service

Default repository: ssh://git@162.55.1.114:4022/spark108/pnt.git
SSH may ask for a key passphrase, password, or host-key confirmation.
An optional URL is saved for later updates.
EOF
}

die() { printf 'pnt.sh: %s\n' "$*" >&2; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die 'Run this command as root (sudo ./pnt.sh ...).'
    [ "$(uname -s)" = Linux ] || die 'This script supports Linux only.'
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

runtime_id() {
    if [ -n "${PNT_RUNTIME_ID:-}" ]; then printf '%s\n' "$PNT_RUNTIME_ID"; return; fi
    case "$(uname -m)" in
        x86_64) printf '%s\n' linux-x64 ;;
        aarch64) printf '%s\n' linux-arm64 ;;
        *) die 'Unsupported architecture. Set PNT_RUNTIME_ID explicitly.' ;;
    esac
}

publish_source() {
    source_dir=$1
    output_dir=$2
    [ -f "$source_dir/pnt.csproj" ] || die 'The repository has no pnt.csproj.'
    [ -f "$source_dir/deploy/pnt.service" ] || die 'The repository has no deploy/pnt.service.'
    dotnet publish "$source_dir/pnt.csproj" -c Release -r "$(runtime_id)" --self-contained true \
        -p:PublishSingleFile=true -o "$output_dir"
    [ -s "$output_dir/pnt" ] || die 'Build did not produce the pnt executable.'
}

repository_url() {
    if [ "$#" -gt 0 ]; then
        printf '%s\n' "$1"
    elif [ -n "${PNT_REPOSITORY:-}" ]; then
        printf '%s\n' "$PNT_REPOSITORY"
    elif [ -f "$REPO_CONFIG" ]; then
        cat "$REPO_CONFIG"
    else
        printf '%s\n' "$DEFAULT_REPOSITORY"
    fi
}

check_repository_url() {
    case "$1" in
        ssh://git@162.55.1.114:4022/spark108/pnt.git) return ;;
    esac
    printf '%s\n' "$1" | grep -Eq '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$' ||
        die 'The repository must be the configured private SSH URL or a GitHub HTTPS URL.'
}

install_current() {
    require_root
    require_command dotnet
    require_command systemctl
    [ ! -e "$BIN" ] || die 'PNT is already installed. Use update to install a new version.'
    temp_dir=$(mktemp -d)
    trap 'rm -rf -- "$temp_dir"' EXIT HUP INT TERM
    publish_source "$SCRIPT_DIR" "$temp_dir/build"
    install -d -m 755 "$INSTALL_DIR"
    install -d -m 700 /var/lib/pnt
    install -m 755 "$temp_dir/build/pnt" "$BIN"
    ln -sfn "$BIN" "$LINK"
    install -m 644 "$SCRIPT_DIR/deploy/pnt.service" "$UNIT"
    systemctl daemon-reload
    systemctl enable --now pnt.service
    printf 'PNT installed and started.\n'
}

update_from_repository() {
    require_root
    require_command git
    require_command dotnet
    require_command systemctl
    [ -f "$BIN" ] || die 'PNT is not installed. Run: sudo ./pnt.sh install'
    [ -f "$UNIT" ] || die 'The pnt.service unit is missing.'
    [ "$#" -le 1 ] || die 'update accepts one repository URL at most.'
    repo=$(repository_url "$@")
    check_repository_url "$repo"

    temp_dir=$(mktemp -d)
    staged_bin=''
    backup_bin=''
    swapped=0
    update_ok=0
    cleanup_update() {
        result=$?
        trap - EXIT HUP INT TERM
        if [ "$swapped" -eq 1 ] && [ "$update_ok" -eq 0 ]; then
            mv -f "$backup_bin" "$BIN" || true
            install -m 644 "$temp_dir/pnt.service.old" "$UNIT" || true
            systemctl daemon-reload || true
            if [ "$was_active" -eq 1 ]; then systemctl restart pnt.service || true; fi
            printf 'pnt.sh: previous version restored after failed update.\n' >&2
        fi
        rm -rf -- "$temp_dir"
        [ -z "$staged_bin" ] || rm -f -- "$staged_bin"
        [ -z "$backup_bin" ] || rm -f -- "$backup_bin"
        exit "$result"
    }
    trap cleanup_update EXIT
    trap 'exit 1' HUP INT TERM

    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        require_command runuser
        chown "$SUDO_USER" "$temp_dir"
        runuser -u "$SUDO_USER" -- git clone --depth 1 -- "$repo" "$temp_dir/source"
        runuser -u "$SUDO_USER" -- dotnet publish "$temp_dir/source/pnt.csproj" -c Release -r "$(runtime_id)" \
            --self-contained true -p:PublishSingleFile=true -o "$temp_dir/build"
        [ -s "$temp_dir/build/pnt" ] || die 'Build did not produce the pnt executable.'
        [ -f "$temp_dir/source/deploy/pnt.service" ] || die 'The repository has no deploy/pnt.service.'
    else
        git clone --depth 1 -- "$repo" "$temp_dir/source"
        publish_source "$temp_dir/source" "$temp_dir/build"
    fi

    # Keep both executable files on one filesystem so each replacement is atomic.
    staged_bin=$(mktemp "$INSTALL_DIR/.pnt-new.XXXXXX")
    backup_bin=$(mktemp "$INSTALL_DIR/.pnt-old.XXXXXX")
    install -m 755 "$temp_dir/build/pnt" "$staged_bin"
    cp -p "$BIN" "$backup_bin"
    cp -p "$UNIT" "$temp_dir/pnt.service.old"
    was_active=0
    if systemctl is-active --quiet pnt.service; then was_active=1; fi

    mv -f "$staged_bin" "$BIN"
    staged_bin=''
    swapped=1
    install -m 644 "$temp_dir/source/deploy/pnt.service" "$UNIT"
    systemctl daemon-reload
    if [ "$was_active" -eq 1 ]; then
        systemctl restart pnt.service || die 'The updated service failed to start.'
    fi

    if [ "$#" -eq 1 ]; then
        install -d -m 700 /etc/pnt
        printf '%s\n' "$repo" > "$REPO_CONFIG"
        chmod 600 "$REPO_CONFIG"
    fi
    update_ok=1
    if [ "$was_active" -eq 1 ]; then
        printf 'PNT updated and restarted.\n'
    else
        printf 'PNT updated. The service remains stopped.\n'
    fi
}

command_name=${1:-}
if [ "$#" -gt 0 ]; then shift; fi
case "$command_name" in
    install) [ "$#" -eq 0 ] || die 'install takes no arguments.'; install_current ;;
    update) update_from_repository "$@" ;;
    start) [ "$#" -eq 0 ] || die 'start takes no arguments.'; require_root; systemctl start pnt.service ;;
    stop) [ "$#" -eq 0 ] || die 'stop takes no arguments.'; require_root; systemctl stop pnt.service ;;
    restart) [ "$#" -eq 0 ] || die 'restart takes no arguments.'; require_root; systemctl restart pnt.service ;;
    help|--help|-h|'') usage ;;
    *) usage >&2; exit 2 ;;
esac
