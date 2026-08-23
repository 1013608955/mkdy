#!/usr/bin/env python3
"""config_hds.py — 用 pty 精确驱动 hdspace config 交互。
v14：加长等待窗（弹窗交互可能很慢），完整回显，不提前截断。"""
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

sent_ak = False
sk_sends = 0
text = ""
deadline = time.time() + 150          # 给弹窗交互留足时间
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1.0)
    if not r:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                print("[info] 子进程已退出")
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
        sk_sends += 1
        text = ""
        print(f"[info] 已喂入 SK 第{sk_sends}次")

# 收尾：等自然退出最多 10s，再强杀
end = time.time() + 10
while time.time() < end:
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            break
    except ChildProcessError:
        break
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            chunk = os.read(fd, 4096)
            if chunk:
                text += chunk.decode("utf-8", "replace")
        except OSError:
            break
try:
    os.kill(pid, 9)
except OSError:
    pass
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass

print("===== pty 完整输出尾 =====")
print(text[-2000:])
print(f"[result] sent_ak={sent_ak} sk_sends={sk_sends}")
sys.exit(0 if (sent_ak and sk_sends >= 2) else 1)
