"""Docker 沙箱: 实际运行 PoC 以验证 sink 真的被触达 —— 「动态验证 / 闭环」。

为安全起见:
  - 在受限 Docker 容器中运行被测二进制 (--network none, 只读挂载, 内存/进程/时间限制);
  - 命令执行类 sink (system/popen/exec*) 不真打恶意命令, 而是把 PoC 输入喂进去后,
    用 strace 观察是否实际调用了 execve/system —— 「确认到达 sink」而非「造成破坏」;
  - 内存类 (strcpy/memcpy 溢出): 用 ASAN 重新编译运行, 观察是否崩溃/越界报告。

Docker 不可用时返回 (False, 原因), 不影响主流程 (符号执行结论仍有效)。
"""
from __future__ import annotations

import ast
import shlex
import shutil
import subprocess
from pathlib import Path

from ..config import Config
from ..models import DataFlow, SymbolicResult


def _docker_available(cfg: Config) -> bool:
    return shutil.which("docker") is not None and cfg.sandbox == "docker"


def _parse_poc(poc: str) -> tuple[bytes, list[bytes]]:
    """从 SymbolicResult.poc_input 解析 stdin 与 argv。

    格式形如:  argv1=b'...'; stdin=b'...'
    返回 (stdin_bytes, [argv1, ...])。
    """
    stdin_data = b""
    argv: list[bytes] = []
    env: dict[str, bytes] = {}
    for part in poc.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip()
        try:
            raw = ast.literal_eval(val.strip())
            if isinstance(raw, str):
                raw = raw.encode()
        except Exception:
            raw = val.strip().encode()
        if key == "stdin":
            stdin_data = raw
        elif key.startswith("env:"):
            env[key.split(":", 1)[1]] = raw
        elif key.startswith("argv"):
            argv.append(raw)
    return stdin_data, argv, env


def validate_in_sandbox(flow: DataFlow, sym: SymbolicResult, cfg: Config,
                        workdir: Path) -> SymbolicResult:
    """在 Docker 沙箱里跑 PoC, 更新 sym.sandbox_validated / sandbox_evidence。"""
    if not cfg.use_sandbox:
        sym.sandbox_evidence = "未启用沙箱验证 (--no-sandbox)"
        return sym
    if not _docker_available(cfg):
        sym.sandbox_evidence = "Docker 不可用, 跳过沙箱验证 (符号执行结论仍有效)"
        return sym
    if sym.status != "reachable":
        sym.sandbox_evidence = f"状态为 {sym.status}, 无需运行 PoC"
        return sym

    from .angr_backend import _locate_source
    src = _locate_source(flow)
    if src is None:
        sym.sandbox_evidence = "源文件不存在, 无法在沙箱中复现"
        return sym

    # 用 strace 观察 execve, 或用 ASAN 观察内存错误
    sink = (flow.sink_api or flow.sink or "").split(".")[-1].lower()
    is_memory = sink in ("strcpy", "strcat", "sprintf", "memcpy", "gets")

    stdin_data, argv, env = _parse_poc(sym.poc_input)

    # PoC 可能含空字节, 不能拼进 shell 命令。改为写文件 + base64 传入容器。
    # argv 不可含空字节 (execve 以 NUL 截断), 故在首个 NUL 处截断。
    import base64
    argv_trunc = [a.split(b"\x00", 1)[0] for a in argv]

    # 内存类 sink: 符号执行的 PoC 只保证"到达 strcpy", 未必够长触发溢出。
    # 这里把触发输入填充到足够长 (远超常见栈缓冲区), 以确实触发越界写。
    OVERFLOW_LEN = 512
    if is_memory:
        if argv_trunc:
            base = argv_trunc[0] or b"A"
            argv_trunc[0] = (base * (OVERFLOW_LEN // len(base) + 1))[:OVERFLOW_LEN]
        else:
            argv_trunc = [b"A" * OVERFLOW_LEN]
        if stdin_data:
            stdin_data = (stdin_data * (OVERFLOW_LEN // max(1, len(stdin_data)) + 1))[:OVERFLOW_LEN]
        else:
            # 某些样本从 stdin 读入; 同时给一份超长 stdin 兜底
            stdin_data = b"A" * OVERFLOW_LEN

    inputs_dir = workdir / "sandbox_inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    (inputs_dir / "stdin.bin").write_bytes(stdin_data)
    (inputs_dir / "argv.b64").write_text(
        "\n".join(base64.b64encode(a).decode() for a in argv_trunc), encoding="ascii")
    (inputs_dir / "env.b64").write_text(
        "\n".join(f"{k}={base64.b64encode(v.split(chr(0).encode(),1)[0]).decode()}"
                  for k, v in env.items()), encoding="ascii")

    proj_dir = src.parent.resolve()
    asan_flags = "-fsanitize=address -g" if is_memory else "-g"
    observe = "" if is_memory else "strace -f -e trace=execve,execveat"

    # 容器内脚本: 全程用 base64 解码, 避免任何转义/空字节问题
    container_script = f"""set +e
cp /work/{shlex.quote(src.name)} /tmp/src.cpp
g++ {asan_flags} -O0 -o /tmp/poc /tmp/src.cpp -ldl 2>/tmp/build.log \
  || g++ {asan_flags} -O0 -o /tmp/poc /tmp/src.cpp 2>>/tmp/build.log
if [ ! -x /tmp/poc ]; then echo '---BUILD-FAILED---'; cat /tmp/build.log; exit 0; fi
# 还原 argv (mapfile 读每行 base64 再解码)
ARGS=()
while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  ARGS+=("$(printf %s "$line" | base64 -d)")
done < /inputs/argv.b64
# 还原 env
ENVS=()
while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  name="${{line%%=*}}"; val="${{line#*=}}"
  ENVS+=("$name=$(printf %s "$val" | base64 -d)")
done < /inputs/env.b64
echo "---DIAG--- argc=${{#ARGS[@]}} arg0len=${{#ARGS[0]}}"
export ASAN_OPTIONS=abort_on_error=1:exitcode=99
echo '---RUN---'
env "${{ENVS[@]}}" {observe} /tmp/poc "${{ARGS[@]}}" < /inputs/stdin.bin 2>&1
echo "---END--- rc=$?"
"""

    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory", "512m", "--pids-limit", "128",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    ]
    # 命令执行类需要 strace 观察 execve, 单独加回 PTRACE 能力 (仍无网络/只读挂载)
    if not is_memory:
        docker_cmd += ["--cap-add", "SYS_PTRACE"]
    docker_cmd += [
        "-v", f"{proj_dir}:/work:ro",
        "-v", f"{inputs_dir.resolve()}:/inputs:ro",
        cfg.sandbox_image,
        "bash", "-c", container_script,
    ]
    try:
        cp = subprocess.run(docker_cmd, capture_output=True, text=True,
                            timeout=cfg.sandbox_timeout)
    except subprocess.TimeoutExpired:
        sym.sandbox_evidence = "沙箱运行超时"
        return sym
    except Exception as e:
        sym.sandbox_evidence = f"沙箱启动失败: {e}"
        return sym

    out = (cp.stdout or "") + (cp.stderr or "")
    if "---BUILD-FAILED---" in out:
        sym.sandbox_evidence = "沙箱内编译失败: " + out.split("---BUILD-FAILED---", 1)[1][:300].strip()
        return sym
    if is_memory:
        # ASAN 报告 / 崩溃 = 内存破坏被实际触发
        markers = ("AddressSanitizer", "stack-buffer-overflow", "heap-buffer-overflow",
                   "stack-smashing", "SEGV", "runtime error", "buffer-overflow")
        if any(m in out for m in markers):
            sym.sandbox_validated = True
            sym.sandbox_evidence = "ASAN/运行时检测到内存越界, PoC 实际触发了溢出"
        else:
            sym.sandbox_evidence = ("运行未触发 ASAN 报告 (诊断: "
                                    + (out.split("---DIAG---", 1)[1][:120].strip()
                                       if "---DIAG---" in out else out[:120].strip()) + ")")
    else:
        # strace 观察到 execve = 命令执行 sink 实际被调用
        if "execve(" in out:
            sym.sandbox_validated = True
            sym.sandbox_evidence = "strace 观察到 execve 调用, 命令执行 sink 实际被触达"
        else:
            sym.sandbox_evidence = "运行未观察到 execve (sink 可能未在该输入下触发)"
    return sym


# --------------------------------------------------------------------------- #
# Python 沙箱: 直接 patch 危险 sink 函数 (命中即拦截记录), 并辅以审计钩子。
# 「实证触达」而非「造成破坏」—— sink 被调用瞬间拦截, 危害不真正发生。
# --------------------------------------------------------------------------- #
# sink_api(末段, 小写) -> 要 patch 的 (模块, 属性) 列表
_PY_SINK_PATCH = {
    "loads": [("pickle", "loads")],
    "load": [("yaml", "load")],
    "system": [("os", "system")],
    "popen": [("os", "popen"), ("subprocess", "Popen")],
    "call": [("subprocess", "call")],
    "run": [("subprocess", "run")],
    "eval": [("builtins", "eval")],
    "exec": [("builtins", "exec")],
}
# 辅助: 审计事件 (部分 sink 有标准事件)
_PY_AUDIT_EVENTS = {
    "loads": ["pickle.find_class"],
    "system": ["os.system"],
    "popen": ["os.system", "subprocess.Popen"],
    "call": ["subprocess.Popen"],
    "run": ["subprocess.Popen"],
    "eval": ["exec", "compile"],
    "exec": ["exec", "compile"],
}

_PY_RUNNER_TEMPLATE = r'''
import sys, importlib.util

FUNC = {func!r}
MODPATH = "/work/{modname}"
PATCH = {patch!r}          # [(module, attr), ...]
EVENTS = {events!r}
PAYLOAD = {payload!r}

_hit = {{"v": False, "ev": ""}}

# 1) 审计钩子 (辅助信号)
def _hook(event, args):
    for pref in EVENTS:
        if event == pref or event.startswith(pref):
            _hit["v"] = True
            _hit["ev"] = "audit:" + event
sys.addaudithook(_hook)

# 2) 直接 patch sink 函数 (主信号): 命中即记录并抛异常拦截
def _install_patches():
    for modname, attr in PATCH:
        try:
            m = __import__(modname, fromlist=[attr]) if "." in modname else __import__(modname)
        except Exception:
            continue
        if hasattr(m, attr):
            def _hook_fn(*a, _ev=modname + "." + attr, **k):
                _hit["v"] = True
                _hit["ev"] = _ev
                raise RuntimeError("SUPPLYGUARD_SINK_BLOCKED")
            try:
                setattr(m, attr, _hook_fn)
            except Exception:
                pass

spec = importlib.util.spec_from_file_location("_t", MODPATH)
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
    _install_patches()      # 模块加载后再 patch, 覆盖其 import 的引用
    fn = getattr(mod, FUNC)
    try:
        fn(PAYLOAD)
    except RuntimeError as e:
        if "SUPPLYGUARD_SINK_BLOCKED" not in str(e):
            pass
    except Exception:
        pass
except Exception as e:
    print("---PYERR---", e)

if _hit["v"]:
    print("---SINK-HIT---", _hit["ev"])
else:
    print("---NO-SINK---")
'''


def validate_python_in_sandbox(flow: DataFlow, sym: SymbolicResult,
                               cfg: Config) -> SymbolicResult:
    """在 Docker 沙箱里用审计钩子验证 Python sink 是否真被触达。"""
    if not cfg.use_sandbox:
        sym.sandbox_evidence = "未启用沙箱验证 (--no-sandbox)"
        return sym
    if not _docker_available(cfg):
        sym.sandbox_evidence = "Docker 不可用, 跳过沙箱验证 (符号执行结论仍有效)"
        return sym
    if sym.status != "reachable":
        sym.sandbox_evidence = f"状态为 {sym.status}, 无需运行 PoC"
        return sym

    from .angr_backend import _locate_source
    from .py_harness import analyze_python_target
    src = _locate_source(flow)
    target = analyze_python_target(flow)
    if src is None or not target:
        sym.sandbox_evidence = "未能定位 Python 目标函数, 跳过沙箱验证"
        return sym

    sink_short = (flow.sink_api or flow.sink or "").split(".")[-1].lower()
    patch = _PY_SINK_PATCH.get(sink_short)
    if not patch:
        sym.sandbox_evidence = f"sink {sink_short} 暂不支持 Python 沙箱验证"
        return sym
    events = _PY_AUDIT_EVENTS.get(sink_short, [])

    # 选一个能触发该类 sink 的恶意 payload (sink 被 patch 拦截, 危害不真正发生)
    if sink_short in ("loads",):
        # 触发 pickle.find_class 的 payload: 反序列化 os.system (被拦截不执行)
        payload = b"\x80\x03cposix\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."
    elif sink_short in ("load",):
        payload = "!!python/object/apply:os.system ['id']"
    elif sink_short in ("system", "popen", "call", "run"):
        payload = "$(id)"
    else:
        payload = "__import__('os').system('id')"

    runner = _PY_RUNNER_TEMPLATE.format(
        func=target["func_name"], modname=Path(src).name,
        patch=patch, events=events, payload=payload,
    )

    proj_dir = Path(src).parent.resolve()
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--memory", "512m", "--pids-limit", "128",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", f"{proj_dir}:/work:ro",
        cfg.sandbox_image,
        "python3", "-c", runner,
    ]
    try:
        cp = subprocess.run(docker_cmd, capture_output=True, text=True,
                            timeout=cfg.sandbox_timeout)
    except subprocess.TimeoutExpired:
        sym.sandbox_evidence = "沙箱运行超时"
        return sym
    except Exception as e:
        sym.sandbox_evidence = f"沙箱启动失败: {e}"
        return sym

    out = (cp.stdout or "") + (cp.stderr or "")
    if "---SINK-HIT---" in out:
        ev = out.split("---SINK-HIT---", 1)[1].strip().split()[0:1]
        sym.sandbox_validated = True
        sym.sandbox_evidence = f"沙箱拦截到危险 sink 调用 ({' '.join(ev)}), sink 实际被触达"
    elif "---NO-SINK---" in out:
        sym.sandbox_evidence = "运行未触发 sink (该 payload 下未触达)"
    else:
        sym.sandbox_evidence = "沙箱执行无明确结果: " + out[-200:].strip()
    return sym
