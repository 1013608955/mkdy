#!/usr/bin/env python3
"""config_hds.py — 用 pty 精确驱动 hdspace config 的交互式提示。
从环境变量读 HDS_AK / HDS_SK，检测到对应提示词时逐个喂入。
在 dbus-run-session + gnome-keyring 解锁会话内运行。"""
import os
import pty
import sys
import time

ak = os.environ.get("HDS_AK", "")
sk = os.environ.get("HDS_SK", "")
if not ak or not sk:
    print("[err] HDS_AK/HDS_SK 未设置")
    sys.exit(2)

pid, fd = pty.fork()
if pid == 0:
    os.execvp("./tools/bin/hdspace-linux",
              ["./tools/bin/hdspace-linux", "config"])
    os._exit(1)

sent_ak = sent_sk = False
buf = b""
text_all = ""
deadline = time.time() + 30
while time.time() < deadline:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
    text_all += chunk.decode("utf-8", "replace")
    low = text_all.lower()
    if not sent_ak and "access key" in low and "id" in low:
        time.sleep(0.3)
        os.write(fd, (ak + "\n").encode())
        sent_ak = True
        text_all = ""
    elif sent_ak and not sent_sk and "secret" in low:
        time.sleep(0.3)
        os.write(fd, (sk + "\n").encode())
        sent_sk = True
        text_all = ""
    if sent_ak and sent_sk and len(text_all) > 200:
        break

# 排干剩余输出直到子进程退出（上限 10s）
deadline = time.time() + 10
while time.time() < deadline:
    try:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        text_all += chunk.decode("utf-8", "replace")
    except OSError:
        break
try:
    os.close(fd)
except OSError:
    pass
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass

print(text_all[-800:])
print(f"[info] sent_ak={sent_ak} sent_sk={sent_sk}")
