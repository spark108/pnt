#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR=/opt/pnt
BIN=$INSTALL_DIR/pnt
LINK=/usr/local/bin/pnt
UNIT=/etc/systemd/system/pnt.service
REPO_CONFIG=/etc/pnt/update.conf
DEFAULT_REPOSITORY=https://gitea.alathea.ru/spark108/pnt.git

usage() {
    cat <<'EOF'
Usage: sudo ./pnt.sh <command>

  install                 Install Debian dependencies, build, and start the service
  update [repository_url] Clone, build, and install an update from the private repository
  start                   Start pnt.service
  stop                    Stop pnt.service
  restart                 Restart pnt.service
  status                  Show pnt.service status

Default repository: https://gitea.alathea.ru/spark108/pnt.git
Git may ask for a username and password or access token.
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

install_dependencies() {
    temporary_dir=$1
    require_command apt-get
    [ -r /etc/os-release ] || die 'Cannot read /etc/os-release.'
    . /etc/os-release
    [ "$ID" = debian ] || die 'Automatic dependency installation supports Debian only.'
    case "$VERSION_ID" in
        12) icu_package=libicu72; ssl_package=libssl3 ;;
        13) icu_package=libicu76; ssl_package=libssl3t64 ;;
        *) die 'Automatic .NET 10 installation supports Debian 12 and 13 only.' ;;
    esac
    runtime_id >/dev/null

    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl git openssh-client systemd nftables iptables \
        libc6 libgcc-s1 libgssapi-krb5-2 libstdc++6 tzdata zlib1g \
        "$icu_package" "$ssl_package"

    if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks 2>/dev/null | grep -q '^10\.'; then
        require_command dpkg
        curl -fsSL "https://packages.microsoft.com/config/debian/$VERSION_ID/packages-microsoft-prod.deb" \
            -o "$temporary_dir/packages-microsoft-prod.deb"
        dpkg -i "$temporary_dir/packages-microsoft-prod.deb"
        apt-get update
        apt-get install -y dotnet-sdk-10.0
    fi
    dotnet --list-sdks | grep -q '^10\.' || die '.NET 10 SDK installation failed.'
}

repository_url() {
    if [ "$#" -gt 0 ]; then
        printf '%s\n' "$1"
    elif [ -n "${PNT_REPOSITORY:-}" ]; then
        printf '%s\n' "$PNT_REPOSITORY"
    elif [ -f "$REPO_CONFIG" ]; then
        saved_repo=$(cat "$REPO_CONFIG")
        case "$saved_repo" in
            ssh://git@162.55.1.114:4022/spark108/pnt.git) printf '%s\n' "$DEFAULT_REPOSITORY" ;;
            *) printf '%s\n' "$saved_repo" ;;
        esac
    else
        printf '%s\n' "$DEFAULT_REPOSITORY"
    fi
}

check_repository_url() {
    case "$1" in
        https://gitea.alathea.ru/spark108/pnt.git) return ;;
    esac
    printf '%s\n' "$1" | grep -Eq '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$' ||
        die 'The repository must be the configured Gitea URL or a GitHub HTTPS URL.'
}

install_current() {
    require_root
    [ ! -e "$BIN" ] || die 'PNT is already installed. Use update to install a new version.'
    temp_dir=$(mktemp -d)
    trap 'rm -rf -- "$temp_dir"' EXIT HUP INT TERM
    install_dependencies "$temp_dir"
    require_command systemctl
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
    status) [ "$#" -eq 0 ] || die 'status takes no arguments.'; require_command systemctl; systemctl status --no-pager --full pnt.service ;;
    help|--help|-h|'') usage ;;
    *) usage >&2; exit 2 ;;
esac
