# Sourced by the foreground watcher; workers never depend on terminal state.
pnt_ui_start() {
    PNT_TUI=0
    if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ]; then
        PNT_TUI=1
        printf '\033[?1049h\033[?25l\033[2J\033[H'
        trap 'pnt_ui_stop' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM HUP
        pnt_ui_size
    fi
}
pnt_ui_size() {
    size=$(stty size </dev/tty 2>/dev/null || printf '24 80')
    ui_rows=${size% *};ui_cols=${size#* }
    [ "$ui_rows" -ge 5 ] || ui_rows=5
    ui_bottom=$((ui_rows - 2))
    printf '\033[1;%sr' "$ui_bottom"
}
pnt_ui_footer() {
    [ "$PNT_TUI" -eq 1 ] || return 0
    printf '\0337'
    pnt_ui_size
    percent=$1;label=$2;bar_width=$((ui_cols - 10));[ "$bar_width" -le 20 ] || bar_width=20;[ "$bar_width" -ge 1 ] || bar_width=1
    filled=$((percent * bar_width / 100));bar=''
    i=0;while [ "$i" -lt "$bar_width" ]; do
        if [ "$i" -lt "$filled" ]; then bar="$bar#";else bar="$bar-";fi
        i=$((i + 1))
    done
    label=$(printf '%s' "$label" | tr '\r\n\033' '   ' | LC_ALL=C.UTF-8 sed -E "s/^(.{0,$((ui_cols - 1))}).*/\\1/")
    printf '\033[%s;1H\033[2K[%s] %s%%\033[%s;1H\033[2K%s\0338' "$((ui_rows - 1))" "$bar" "$percent" "$ui_rows" "$label"
}
pnt_ui_stop() {
    if [ "${PNT_TUI:-0}" -eq 1 ]; then
        printf '\033[r\033[?25h\033[?1049l'
        PNT_TUI=0
    fi
}
