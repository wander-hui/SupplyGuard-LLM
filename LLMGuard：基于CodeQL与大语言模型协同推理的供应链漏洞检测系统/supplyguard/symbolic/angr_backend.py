"""C/C++ 符号执行后端 (angr)。

流程:
  1. 把目标源码编译为可分析的二进制 (若工程已编译, 直接用现成二进制);
  2. 用 LLM 生成的 harness 规格, 把 stdin/argv/env 设为符号量;
  3. angr 定向探索到达 sink 函数 (find=sink_addr), 关键节点作为剪枝提示;
  4. 命中 -> 求解出具体 PoC 输入 (SAT); 全部走完未命中 -> UNSAT(不可达); 超时 -> unknown。

angr 为可选依赖; 未安装时返回 status='unknown', 不影响主流程。
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

from ..config import Config
from ..models import DataFlow, SymbolicResult

# sink 函数 -> 该 sink 触发即视为危险 (无需额外条件)
_KNOWN_SINKS = {"system", "popen", "execl", "execlp", "execv", "execvp",
                "execve", "dlopen", "strcpy", "strcat", "sprintf", "memcpy", "gets"}


def _have_angr() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except Exception:
        return False


def _locate_source(flow: DataFlow) -> Optional[Path]:
    """定位 sink 所在源文件。

    CodeQL 的 SARIF 路径常是相对 source-root 的相对路径 (如 'vuln.cpp'),
    内置分析器则给绝对路径。这里依次尝试:
      1) 原样路径; 2) 相对当前工作目录; 3) 在 CWD 下按文件名递归搜索。
    """
    raw = Path(flow.file)
    if raw.is_absolute() and raw.exists():
        return raw
    # 相对当前工作目录
    cand = Path.cwd() / flow.file
    if cand.exists():
        return cand
    if raw.exists():
        return raw
    # 按文件名在 CWD 下搜索 (取第一个匹配)
    name = raw.name
    for p in Path.cwd().rglob(name):
        if p.is_file():
            return p
    return None


def _compile_binary(flow: DataFlow, cfg: Config, workdir: Path) -> tuple[Optional[Path], str]:
    """把 sink 所在源文件编译成带符号、便于 angr 分析的二进制。

    返回 (二进制路径 | None, 详情字符串)。失败时详情含编译器 stderr。
    """
    src = _locate_source(flow)
    if src is None:
        return None, f"源文件未找到: {flow.file} (CWD={Path.cwd()})"
    proj_dir = src.parent

    # 1) 工程里已有 Makefile -> make -B (强制重建, 保证产物存在)
    makefile = proj_dir / "Makefile"
    if makefile.exists():
        cp = subprocess.run(["make", "-B"], cwd=str(proj_dir), capture_output=True, text=True)
        if cp.returncode == 0:
            exes = [p for p in proj_dir.iterdir()
                    if p.is_file() and os.access(p, os.X_OK) and p.suffix == ""]
            if exes:
                return max(exes, key=lambda p: p.stat().st_mtime), f"make 产物: {exes[0].name}"

    # 2) 直接编译单文件 (关闭优化/栈保护/PIE, 便于符号执行与定位符号)
    out = workdir / "target.bin"
    compiler = cfg.cpp_compiler if src.suffix in (".cpp", ".cc", ".cxx") else "gcc"
    base = [compiler, "-g", "-O0", "-fno-stack-protector", "-no-pie",
            "-fno-builtin",  # 阻止 strcpy/memcpy 被内联, 保留 PLT 符号
            str(src), "-o", str(out)]
    attempts = [base + ["-ldl"], base]   # 先带 -ldl, 失败再不带
    errors = []
    for cmd in attempts:
        cp = subprocess.run(cmd, capture_output=True, text=True)
        if cp.returncode == 0 and out.exists():
            return out, f"g++ 编译成功: {' '.join(cmd[-3:])}"
        errors.append((cp.stderr or cp.stdout or "").strip()[-500:])
    return None, "g++ 编译失败:\n" + "\n----\n".join(errors)


def run_angr(flow: DataFlow, spec: dict, harness_script: str,
             cfg: Config, workdir: Path) -> SymbolicResult:
    res = SymbolicResult(engine="angr", harness=harness_script)
    if not _have_angr():
        res.status = "unknown"
        res.detail = "未安装 angr (pip install angr); 跳过符号执行"
        return res

    import angr
    import claripy
    import logging
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    logging.getLogger("pyvex").setLevel(logging.ERROR)

    binary, compile_detail = _compile_binary(flow, cfg, workdir)
    if binary is None:
        res.status = "error"
        res.detail = compile_detail
        return res
    res.detail = f"binary={binary.name}; "

    try:
        proj = angr.Project(str(binary), auto_load_libs=False)
    except Exception as e:
        res.status = "error"
        res.detail += f"angr 加载失败: {e}"
        return res

    sink_fn = spec.get("sink_function", "").split(".")[-1].lower()
    if not sink_fn:
        res.status = "unknown"
        res.detail += "未知 sink 函数"
        return res

    # 解析 sink 地址: 优先 PLT (对外部 libc 函数), 再符号表
    sink_addr = None
    try:
        if sink_fn in proj.loader.main_object.plt:
            sink_addr = proj.loader.main_object.plt[sink_fn]
        else:
            sym = proj.loader.find_symbol(sink_fn)
            if sym is not None:
                sink_addr = sym.rebased_addr
    except Exception:
        pass
    if sink_addr is None:
        res.status = "unknown"
        res.detail += f"在二进制中找不到 sink 符号 {sink_fn} (可能被内联或静态链接)"
        return res

    # 构造符号输入
    syms = spec.get("symbolic_inputs") or ["stdin", "argv"]
    argv = [binary.name.encode() if isinstance(binary.name, str) else b"target"]
    argv_syms = {}
    env_syms = {}
    state_args = {}
    if any(s == "argv" for s in syms):
        a = claripy.BVS("argv1", 8 * 48)
        argv.append(a)
        argv_syms["argv1"] = a
    if any(s == "stdin" for s in syms):
        state_args["stdin"] = angr.SimFileStream(name="stdin", has_end=False)
    # 环境变量符号化: 通过 full_init_state 的 env 参数 (angr 原生支持符号值)
    env_dict = {}
    for s in syms:
        if s.startswith("env:"):
            name = s.split(":", 1)[1]
            ev = claripy.BVS(f"env_{name}", 8 * 48)
            env_dict[name] = ev
            env_syms[name] = ev
    if env_dict:
        state_args["env"] = env_dict

    try:
        state = proj.factory.full_init_state(args=argv, **state_args)
    except Exception as e:
        res.status = "error"
        res.detail += f"构造初始状态失败: {e}"
        return res

    simgr = proj.factory.simulation_manager(state)

    # 防路径爆炸: 限制总步数, 用 DFS 降低内存占用
    try:
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
        simgr.use_technique(angr.exploration_techniques.DFS())
    except Exception:
        pass

    # 墙钟超时: 通过 step_func 周期性检查
    import time
    deadline = time.monotonic() + cfg.symbolic_timeout
    timed_out = {"v": False}

    def _budget(sm):
        if time.monotonic() > deadline:
            timed_out["v"] = True
            sm.move(from_stash="active", to_stash="_timeout")
        return sm

    try:
        simgr.explore(find=sink_addr, num_find=1, step_func=_budget)
    except Exception as e:
        res.status = "unknown"
        res.detail += f"探索异常: {e}"
        return res

    if simgr.found:
        found = simgr.found[0]
        res.status = "reachable"
        # 求解 PoC
        poc_parts = []
        for name, bv in argv_syms.items():
            try:
                val = found.solver.eval(bv, cast_to=bytes)
                poc_parts.append(f"{name}={val!r}")
            except Exception:
                pass
        if any(s == "stdin" for s in syms):
            try:
                stdin_data = found.posix.dumps(0)
                poc_parts.append(f"stdin={stdin_data!r}")
            except Exception:
                pass
        for name, bv in env_syms.items():
            try:
                val = found.solver.eval(bv, cast_to=bytes)
                poc_parts.append(f"env:{name}={val!r}")
            except Exception:
                pass
        res.poc_input = "; ".join(poc_parts) if poc_parts else "(sink 可达, 输入无约束)"
        res.path_constraint = f"reach({sink_fn}@0x{sink_addr:x})"
        res.detail += f"SAT: 符号执行求得到达 {sink_fn} 的输入"
    elif timed_out["v"] or simgr.active:
        # 超时或仍有活跃状态但达到预算上限 -> 未定
        res.status = "unknown"
        res.detail += ("符号执行超时" if timed_out["v"] else "探索预算内未命中 sink (可能路径爆炸/超界)")
    else:
        # 所有状态终结且无人到达 sink -> 在预算内判为不可达
        res.status = "unreachable"
        res.detail += f"UNSAT: 探索完所有路径未发现可达 {sink_fn} 的输入"
    return res
