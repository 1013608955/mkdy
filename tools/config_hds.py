#!/usr/bin/env python3
"""config_hds.py — 用 pty 精确驱动 hdspace config 交互。
select 带超时读写，发完 SK 即收尾强杀，绝不挂死。"""
import os
import pty
import select
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
sk_sends = 0
text = ""
deadline = time.time() + 25
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1.0)
    if not r:
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    text += chunk.decode("utf-8", "replace")
    low = text.lower()
    if not sent_ak and "access key" in low and "id" in low:
        time.sleep(0.3)
        os.write(fd, (ak + "\n").encode())
        sent_ak = True
        text = ""
        print("[info] 已喂入 AK")
    elif "secret" in low:
        time.sleep(0.3)
        os.write(fd, (sk + "\n").encode())
        sent_sk = True
        sk_sends += 1
        text = ""
        print(f"[info] 已喂入 SK 第{sk_sends}次")
    if sent_sk and sk_sends >= 2 and len(text) > 120:
        break

# 等子进程自然退出（keyring 写入可能发生在末尾），上限 30s
deadline = time.time() + 30
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1.0)
    if not r:
        # 无新数据时探测子进程是否已退出
        try:
            pid_done, _ = os.waitpid(pid, os.WNOHANG)
            if pid_done:
                break
        except ChildProcessError:
            break
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    text += chunk.decode("utf-8", "replace")

try:
    os.kill(pid, 9)
except OSError:
    pass
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass

print(text[-600:])
print(f"[result] sent_ak={sent_ak} sent_sk={sent_sk}")
sys.exit(0 if (sent_ak and sent_sk) else 1)
