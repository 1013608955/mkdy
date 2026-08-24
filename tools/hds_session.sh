#!/usr/bin/env bash
# hds_session.sh — 在带 GUI 自动应答的 D-Bus 会话中执行 hdspace 命令。
# 用法: HDS_AK=.. HDS_SK=.. tools/hds_session.sh devenv list
# 前置: Xvfb :99 已启动；keyring 文件已由 config 步骤创建（密码 ci-unlock）。
set -u
export DISPLAY="${DISPLAY:-:99}"
export HDS_SESSION_ARGS
HDS_SESSION_ARGS=$(printf '%q ' "$@")

timeout 100 dbus-run-session -- bash -exc '
  DISPLAY=:99 openbox >/dev/null 2>&1 &
  sleep 1
  # 用创建时的密码解锁已存在的 login keyring
  echo -n "ci-unlock" | gnome-keyring-daemon --unlock >/dev/null 2>&1 || true
  eval "$(printf "\n" | gnome-keyring-daemon --start)" || true
  # 防意外弹窗的自动应答器
  (
    for i in $(seq 1 90); do
      WINS=$( { xdotool search --onlyvisible --name gcr 2>/dev/null;
                xdotool search --onlyvisible --class Gcr 2>/dev/null; } | sort -u)
      [ -z "$WINS" ] && { sleep 1; continue; }
      echo "[autoresponder] 命中gcr窗口: $WINS" >&2
      for W in $WINS; do
        eval "$(xdotool getwindowgeometry --shell "$W" 2>/dev/null)"
        xdotool mousemove --window "$W" $((WIDTH/2)) $((HEIGHT/2)) click 1 2>/dev/null
        xdotool windowfocus "$W" 2>/dev/null
        sleep 0.5
        if [ $((i % 2)) -eq 0 ]; then PW=''; else PW='ci-unlock'; fi
        echo "[autoresponder] 尝试密码: \${PW:+<ci-unlock>}" >&2
        xdotool type --delay 80 "$PW"
        xdotool key Tab
        xdotool type --delay 80 "$PW"
        xdotool key Return
        sleep 3
      done
    done
  ) &
  AR=$!
  eval "set -- $HDS_SESSION_ARGS"
  ./tools/bin/hdspace-linux "$@"
  RC=$?
  kill $AR 2>/dev/null
  exit $RC
'
