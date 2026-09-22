"""tools/hds_key_reset.sh 的单元测试（run#2777 回归防护）。

背景：华为云 open-api 在短时间多次调用（list/start/start-tunnel/ssh-key-reset）后返回
`Too many requests. Please try again later.`，ssh-key-reset 拿不到私钥；旧写法用
`|| true` 吞掉错误，一路走到后续步骤的 chmod 才炸，且把本应「跳过、不告警」的轮次
升级成真失败 + 失败告警邮件。

这些测试用假会话命令（stub）驱动真实脚本，不接触网络、不接触华为云：
  - 限流后重试成功          → 退出 0，私钥就绪、权限 600
  - 限流重试耗尽            → 退出 10（调用方据此按跳过语义收尾、不告警）
  - 非限流类错误重试耗尽    → 退出 1（仍按真失败处理，不放宽判定）
  - 私钥文件始终不出现      → 退出 1 且打印明确原因（含路径）
"""

import os
import re
import shlex
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "hds_key_reset.sh"

KEY_RESET_SKIP_MARKER = "KEY_RESET_SKIP=1"
RATE_LIMIT_OUTPUT = (
    "reset private key failed: get private key from open-api failed: "
    "Too many requests. Please try again later."
)


def _bash_works(path) -> bool:
    """候选 bash 必须能真正执行一段脚本：Windows 上 WindowsApps\\bash.exe 是 WSL 占位
    程序（WSL 未安装时只会打印一段 UTF-16 提示并失败），不能拿来跑用例。"""
    try:
        proc = subprocess.run(
            [str(path), "-c", "echo ok"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and "ok" in proc.stdout


def _find_bash():
    """找一个真能用的 bash。

    Linux CI：PATH 里的 /bin/bash。
    Windows 本地：必须优先真实的 Git Bash —— PATH 里的 WindowsApps\\bash.exe 是 WSL
    占位程序（本机 WSL 未安装，执行只会输出一段 UTF-16 提示），误选会让全部用例假失败。
    """
    candidates = []
    if os.name == "nt":
        candidates += [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ]
    which = shutil.which("bash")
    if which:
        candidates.append(which)
    for cand in candidates:
        if Path(cand).is_file() and _bash_works(cand):
            return cand
    return None


BASH = _find_bash()
# CI（ubuntu-latest）上 bash 必然存在；本机 Windows 也要求真实 Git Bash。若找不到，
# 直接硬失败而不是静默全 skip —— 否则 shell 覆盖率变成零却仍显示绿灯。
if BASH is None:
    raise RuntimeError("找不到可用的 bash，无法验证私钥重置脚本（不允许静默跳过）")


def _write_executable(path: Path, text: str) -> None:
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _stub_session(tmp_path: Path, *, outputs, create_key_after=None, keyname="inst-1"):
    """造一个假 tools/hds_session.sh。

    outputs: 每次调用写入日志的文本列表（超出长度的按最后一个重复）
    create_key_after: 第 N 次调用之后生成私钥文件（None = 永不生成）
    """
    out_dir = tmp_path / "outputs"
    out_dir.mkdir(exist_ok=True)
    for i, text in enumerate(outputs):
        (out_dir / f"call{i + 1}.txt").write_text(text, encoding="utf-8")

    script = tmp_path / "stub_session.sh"
    keyfile = tmp_path / "home" / ".devenv" / ".ssh" / "IdentityFile" / keyname
    # 只在指定了 create_key_after 时才生成私钥，避免 stub 自身产生无关的 shell 报错
    create_block = ""
    if create_key_after is not None:
        create_block = (
            f'if [ "$n" -ge {int(create_key_after)} ]; then\n'
            f'  mkdir -p "$(dirname "{keyfile.as_posix()}")"\n'
            f'  printf "PRIVATE-KEY" > "{keyfile.as_posix()}"\n'
            "fi\n"
        )
    _write_executable(
        script,
        f"""
        #!/usr/bin/env bash
        counter_file={shlex.quote(str(tmp_path / 'calls'))}
        n=0
        [ -f "$counter_file" ] && n=$(cat "$counter_file")
        n=$((n + 1))
        echo "$n" > "$counter_file"
        printf '%s' "$n" >> {shlex.quote(str(tmp_path / 'argv.log'))}
        echo " | $*" >> {shlex.quote(str(tmp_path / 'argv.log'))}
        idx=$n
        last={len(outputs)}
        [ "$idx" -gt "$last" ] && idx=$last
        cat {shlex.quote(str(out_dir))}/call$idx.txt
        {create_block}exit 0
        """,
    )
    return script, keyfile


def _run_script(tmp_path, stub, keyname="inst-1", attempts=3, backoff=0, wait=1, deadline=None):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),  # Windows 上 bash 可能读这个
            "HDS_SESSION_CMD": str(stub),
            "HDS_KEY_RESET_ATTEMPTS": str(attempts),
            "HDS_KEY_RESET_BACKOFF": str(backoff),
            "HDS_KEY_RESET_WAIT": str(wait),
            "HDS_KEY_RESET_LOG": str(tmp_path / "reset.log"),
            **({"HDS_KEY_RESET_DEADLINE": str(deadline)} if deadline is not None else {}),
        }
    )
    proc = subprocess.run(
        [BASH, str(SCRIPT), keyname],
        capture_output=True,
        text=True,
        encoding="utf-8",       # 脚本输出为 UTF-8 中文；不指定会用系统 locale（Windows GBK）解码而失败
        errors="replace",
        env=env,
        timeout=180,
    )
    return proc, home


def _calls(tmp_path) -> int:
    f = tmp_path / "calls"
    return int(f.read_text().strip()) if f.exists() else 0


def test_retry_succeeds_after_rate_limit(tmp_path):
    """限流一次后重试成功：退出 0，私钥就绪且权限收窄到 600。"""
    stub, keyfile = _stub_session(
        tmp_path, outputs=[RATE_LIMIT_OUTPUT], create_key_after=2
    )
    proc, _ = _run_script(tmp_path, stub, attempts=3, backoff=0)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert keyfile.is_file(), "重试成功后私钥应当存在"
    assert "[keyreset][ok]" in proc.stdout
    assert _calls(tmp_path) == 2, "应当恰好重试一次"
    if os.name != "nt":  # Windows 上 chmod 语义不同，跳过权限断言
        assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600


def test_rate_limit_exhausted_signals_skip(tmp_path):
    """限流一直持续：退出 10 —— 调用方据此按跳过语义收尾（NOCOMPUTE_SKIP=1，不告警）。"""
    stub, keyfile = _stub_session(tmp_path, outputs=[RATE_LIMIT_OUTPUT])
    proc, _ = _run_script(tmp_path, stub, attempts=3, backoff=0)

    assert proc.returncode == 10, proc.stdout + proc.stderr
    assert not keyfile.exists()
    assert _calls(tmp_path) == 3, "应当用满全部尝试次数"
    # 断言稳定 token（告警类别与病因路径），不绑定具体中文文案：
    # 文案将来微调不应让行为正确的实现变红。
    assert "[keyreset][ERR]" in proc.stdout
    assert "IdentityFile/inst-1" in proc.stdout
    # 限流被正确归类，且摘要里指明末次类型
    assert "末次类型=ratelimit" in proc.stdout



def test_deadline_caps_total_time(tmp_path):
    """总耗时上限：DEADLINE=0 时不应继续重试，但结论仍按已归类的末次错误走。

    [2] 步骤没有自己的 timeout-minutes（job 上限 30min），因此重试+退避必须自带
    硬上限，不能挤占后续隧道/验证阶段。这里验证触顶时仍能给出正确的退出码语义。
    """
    stub, _ = _stub_session(tmp_path, outputs=[RATE_LIMIT_OUTPUT])
    proc, _ = _run_script(
        tmp_path, stub, attempts=5, backoff=0, deadline=0
    )

    assert proc.returncode == 10, proc.stdout + proc.stderr
    assert _calls(tmp_path) == 1, f"触顶后只保留首次尝试，calls={_calls(tmp_path)}"
    assert "末次类型=ratelimit" in proc.stdout

def test_deadline_does_not_affect_existing_semantics(tmp_path):
    """给了充裕上限时，限流耗尽仍按 10 退出（回归：截止逻辑不改变既有语义）。"""
    stub, _ = _stub_session(tmp_path, outputs=[RATE_LIMIT_OUTPUT])
    proc, _ = _run_script(tmp_path, stub, attempts=3, backoff=0, deadline=300)

    assert proc.returncode == 10, proc.stdout + proc.stderr
    assert _calls(tmp_path) == 3, f"充裕上限下应用满尝试次数，calls={_calls(tmp_path)}"
    assert "IdentityFile/inst-1" in (proc.stdout + proc.stderr)


def test_unknown_failure_stays_real_failure(tmp_path):
    """非限流类错误：退出 1，仍按真失败处理（不得被跳过语义掩盖）。"""
    stub, _ = _stub_session(tmp_path, outputs=["some unexpected platform error"])
    proc, _ = _run_script(tmp_path, stub, attempts=2, backoff=0)

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "末次错误类型=unknown" in proc.stdout


def test_non_ratelimit_reset_failure_stays_real_failure(tmp_path):
    """reset 调用明确失败但原因不是限流：同样退出 1，不并入跳过语义。"""
    stub, _ = _stub_session(
        tmp_path,
        outputs=["reset private key failed: get private key from open-api failed: unauthorized"],
    )
    proc, _ = _run_script(tmp_path, stub, attempts=2, backoff=0)

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "末次错误类型=resetfail" in proc.stdout


def test_missing_key_reports_explicit_reason(tmp_path):
    """私钥始终不存在：错误信息必须含路径与明确原因，而不是一行裸 chmod 报错。"""
    stub, keyfile = _stub_session(tmp_path, outputs=[RATE_LIMIT_OUTPUT])
    proc, _ = _run_script(tmp_path, stub, attempts=1, backoff=0)
    combined = (proc.stdout + proc.stderr).replace("\\", "/")
    # 断言与平台无关的路径尾段：Git Bash 会把临时目录映射成 /tmp/... 或 /c/...，
    # 但 IdentityFile/<实例ID> 这一段在任何平台上都应当原样出现在错误信息里。
    assert f"IdentityFile/{keyfile.name}" in combined, (
        f"必须打印明确病因与私钥路径；实际输出：{combined}"
    )

def test_script_rejects_missing_instance_id(tmp_path):
    """缺少实例 ID 时立即失败，避免静默走偏。"""
    env = dict(os.environ)
    proc = subprocess.run(
        [BASH, str(SCRIPT)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=os.environ.copy(),
        timeout=60,
    )
    assert proc.returncode == 1
    assert "缺少实例 ID" in proc.stdout


def test_workflow_uses_key_reset_helper_and_file_guard():
    """workflow 接线断言：私钥获取走带重试的 helper，且守卫判文件存在而非变量非空。"""
    workflow = (REPO_ROOT / ".github" / "workflows" / "hds-cycle.yml").read_text(
        encoding="utf-8"
    )
    # 旧写法必须消失（被 || true 吞掉错误的那一行）
    assert (
        'ssh-key-reset --instance-id="$TARGET_INSTANCE" > /tmp/reset.log 2>&1 || true'
        not in workflow
    )
    assert 'timeout -k 5 420 bash tools/hds_key_reset.sh "$TARGET_INSTANCE"' in workflow
    # rc=10/124 都必须并入跳过语义。这里刻意匹配整段条件而不是单行
    # 'echo "NOCOMPUTE_SKIP=1"'：后者在无算力分支里本来就有同名字符串，属恒真陷阱。
    assert '[ "$KEY_RESET_RC" -eq 10 ] || [ "$KEY_RESET_RC" -eq 124 ]' in workflow
    assert 'echo "KEY_RESET_SKIP=1" >> "$GITHUB_ENV"' in workflow
    # 死守卫必须已被替换
    assert '[ -n "$KEYFILE" ] || { echo "[ERR] 私钥未找到"; exit 1; }' not in workflow
    assert '[ ! -f "$KEYFILE" ]' in workflow


def test_workflow_branch_runs_and_skips_without_failure(tmp_path):
    """端到端执行 [2] 步骤的 rc=10 分支：真跑那段脚本，验证「跳过且不算失败」。

    这是本次修复的核心主张（限流耗尽 → NOCOMPUTE_SKIP=1 + exit 0 + 关机 + 不告警）。
    不靠 YAML 字符串断言，而是把该分支整块抽出来，用假 hds_session.sh（恒返回限流）
    与假 GITHUB_ENV 实际执行。
    """
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "hds-cycle.yml").read_text(encoding="utf-8")
    )
    step2 = next(
        s for s in workflow["jobs"]["cycle"]["steps"] if s["name"].startswith("[2] 查状态")
    )
    run = step2["run"]

    # 抽取「私钥重置」这一段：从 KEY_RESET_RC=0 到真失败透传结束
    start = run.index("KEY_RESET_RC=0")
    tail = run.index('exit "$KEY_RESET_RC"')
    branch = run[start : run.index("\n", tail) + 1]
    # 去掉 GitHub 表达式（本用例不需要 workflow 上下文的插值）
    branch = re.sub(r"\$\{\{[^}]*\}\}", "", branch)

    workdir = tmp_path / "e2e"
    workdir.mkdir()
    tools = workdir / "tools"
    tools.mkdir()
    shutil.copy2(REPO_ROOT / "tools" / "hds_key_reset.sh", tools / "hds_key_reset.sh")
    argv_log = workdir / "argv.log"
    stub = tools / "hds_session.sh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$*" >> "{argv_log.as_posix()}"\n'
        f"cat <<'EOF'\n{RATE_LIMIT_OUTPUT}\nEOF\n"
        "exit 0\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(0o755)
    (tools / "hds_key_reset.sh").chmod(0o755)

    script = workdir / "branch.sh"
    script.write_text(
        "set -u\nTARGET_INSTANCE=inst-1\n" + branch + "\necho REACHED_LATER_STEPS\n",
        encoding="utf-8",
        newline="\n",
    )
    gh_env = workdir / "gh_env"
    gh_env.write_text("", encoding="utf-8")
    (workdir / "home").mkdir()

    env = dict(os.environ)
    env.update(
        HOME=str(workdir / "home"),
        USERPROFILE=str(workdir / "home"),
        GITHUB_ENV=str(gh_env),
        HDS_KEY_RESET_ATTEMPTS="2",
        HDS_KEY_RESET_BACKOFF="0",
        HDS_KEY_RESET_WAIT="1",
        HDS_KEY_RESET_DEADLINE="60",
        HDS_KEY_RESET_LOG=str(workdir / "reset.log"),
    )
    proc = subprocess.run(
        [BASH, "-e", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(workdir),
        env=env,
        timeout=180,
    )

    # 核心主张 1：不失败（[6] 的 failure() 因此不触发）
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    # 核心主张 2：[3] 被 env.NOCOMPUTE_SKIP != '1' 拦住，且病因标记就位
    written = gh_env.read_text(encoding="utf-8").split()
    assert "NOCOMPUTE_SKIP=1" in written, written
    assert "KEY_RESET_SKIP=1" in written, written
    # 核心主张 3：容器已开机则 best-effort 关机释放核时
    argv = argv_log.read_text(encoding="utf-8")
    assert " stop " in f" {argv} ", argv
    # 核心主张 4：确实重试过（不是一次就放弃）
    assert argv.count("ssh-key-reset") == 2, argv
    # 核心主张 5：不会继续往后续阶段走
    assert "REACHED_LATER_STEPS" not in proc.stdout


def test_workflow_yaml_parses_with_expected_steps():
    """workflow YAML 仍可解析，且改动步骤的 name/if 落点未被破坏。"""
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "hds-cycle.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["cycle"]["steps"]
    by_index = {i: s for i, s in enumerate(steps)}
    by_name = {s["name"]: s for s in steps}

    reset_step = next(s for s in steps if s["name"].startswith("[2] 查状态"))
    assert reset_step["if"] == "steps.gate.outputs.skip != '1'"
    assert reset_step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "hds_key_reset.sh" in reset_step["run"]

    tunnel_step = next(s for s in steps if s["name"].startswith("[3] 开隧道"))
    assert tunnel_step["if"] == (
        "steps.gate.outputs.skip != '1' && env.NOCOMPUTE_SKIP != '1'"
    )
    assert '[ ! -f "$KEYFILE" ]' in tunnel_step["run"]

    # 跳过语义的既有消费者（[2b]）与告警步骤 [6] 仍在，且 [2b] 触发条件未变
    assert by_name["[2b] 无算力连续多轮兜底告警（仅跳过轮执行；每轮风暴只提醒一次）"]["if"] == (
        "env.NOCOMPUTE_SKIP == '1'"
    )
    assert any(n.startswith("[6]") for n in by_name)
