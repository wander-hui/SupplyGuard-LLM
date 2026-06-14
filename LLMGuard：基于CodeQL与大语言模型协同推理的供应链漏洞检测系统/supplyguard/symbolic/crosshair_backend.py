"""Python 符号执行后端 (CrossHair, CLI 模式 + 独立持久 venv)。

为什么用 CLI + 真实源码文件 (而非动态闭包):
  CrossHair 依赖 `inspect.getsource` 读取被分析函数的源码做符号执行, 动态构造的
  闭包没有源码、无法被分析。因此这里生成一个**真实的 harness .py 文件**, 内含一个带
  契约 (post 条件) 的函数, 再用 `crosshair check` 命令行分析它。

为什么用独立 venv:
  目标工程可能依赖任意第三方库, 直接在主环境 import 会污染/冲突。这里维护一个**持久**
  的符号执行专用 venv (默认 .sym_venv), 把 crosshair 与目标工程的 requirements 装进去,
  跑完保留, 下一个 Python 程序复用已装依赖。

结果判定 (解析 crosshair 输出):
  报告反例 (error: ... when calling)  => reachable + PoC
  "No counterexamples"/无输出          => unreachable (路径不可达, 误报)
  超时/异常/未装                        => unknown
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

from ..config import Config
from ..models import DataFlow, SymbolicResult
from .py_harness import analyze_python_target, refine_with_llm

# sink_api(末段, 小写) -> 在 harness 中要 patch/监控的 (导入名, 模块, 属性)
_SINK_PATCH = {
    "loads": ("pickle", "pickle", "loads"),
    "load": ("yaml", "yaml", "load"),
    "system": ("os", "os", "system"),
    "popen": ("subprocess", "subprocess", "Popen"),
    "call": ("subprocess", "subprocess", "call"),
    "run": ("subprocess", "subprocess", "run"),
    "eval": ("builtins", "builtins", "eval"),
    "exec": ("builtins", "builtins", "exec"),
}


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _ensure_venv(cfg: Config) -> tuple[Path | None, str]:
    """确保符号执行专用 venv 存在且装好 crosshair。返回 (python 路径 | None, 详情)。"""
    venv_dir = Path(cfg.crosshair_venv)
    py = _venv_python(venv_dir)
    if not py.exists():
        try:
            venv.create(venv_dir, with_pip=True)
        except Exception as e:
            return None, f"创建符号执行 venv 失败: {e}"
    # 检查 crosshair 是否已装
    chk = subprocess.run([str(py), "-c", "import crosshair"],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        ins = subprocess.run([str(py), "-m", "pip", "install", "-q",
                              "crosshair-tool"], capture_output=True, text=True)
        if ins.returncode != 0:
            return None, f"在 venv 安装 crosshair 失败: {ins.stderr[-300:]}"
    return py, "venv ready"


def _install_target_deps(py: Path, flow: DataFlow, cfg: Config) -> None:
    """把目标工程的 requirements.txt 装进符号执行 venv (复用, 失败忽略)。"""
    if not cfg.crosshair_auto_deps:
        return
    from .angr_backend import _locate_source
    src = _locate_source(flow)
    if src is None:
        return
    req = Path(src).parent / "requirements.txt"
    if req.exists():
        subprocess.run([str(py), "-m", "pip", "install", "-q", "-r", str(req)],
                       capture_output=True, text=True)


def _render_harness(target: dict, import_name: str, mod_attr: str, attr: str) -> str:
    """生成真实可被 crosshair 分析的 harness 源码。

    harness 把目标模块所在目录加入 sys.path, import 目标函数; patch 危险 sink 为
    「命中即抛 _Hit」; 探针函数带契约 post: __return__ == True, sink 命中则返回 False。
    """
    mod_file = Path(target["module_path"]).resolve()
    mod_name = mod_file.stem
    mod_dir = str(mod_file.parent).replace("\\", "\\\\")
    func = target["func_name"]
    params = target["params"]
    sig = ", ".join(f"{p['name']}: {p['type']}" for p in params)
    call_args = ", ".join(p["name"] for p in params)

    return f'''# 自动生成的 CrossHair harness —— 验证 {func} 是否可触达 {attr}
import sys
sys.path.insert(0, "{mod_dir}")

import {mod_attr}
import {mod_name} as _target


class _Hit(Exception):
    pass


def probe({sig}) -> bool:
    """ 验证外部输入能否触达危险 sink。
    post: __return__ == True
    """
    # 仅在调用目标函数期间临时 patch sink, 调用后立刻还原,
    # 避免污染 CrossHair 自身对 {mod_attr}.{attr} 的使用 (尤其 builtins.eval/exec)。
    _orig = {mod_attr}.{attr}
    _hit = [False]

    def _sink_hook(*a, **k):
        _hit[0] = True
        raise _Hit()

    {mod_attr}.{attr} = _sink_hook
    try:
        _target.{func}({call_args})
    except _Hit:
        pass
    except Exception:
        pass
    finally:
        {mod_attr}.{attr} = _orig
    # 触达 sink -> 返回 False -> 违反 post 契约 -> CrossHair 报反例
    return not _hit[0]
'''


_COUNTEREXAMPLE_RE = re.compile(r"(probe\([^)]*\))")


def run_crosshair(flow: DataFlow, cfg: Config, llm_client=None) -> SymbolicResult:
    res = SymbolicResult(engine="crosshair")

    target = analyze_python_target(flow)
    if not target:
        res.status = "unknown"
        res.detail = "未能定位 sink 所在的可符号化函数 (sink 可能在模块级或函数无参数)"
        return res
    target = refine_with_llm(target, flow, llm_client)

    sink_short = (target["sink_api"] or "").split(".")[-1].lower()
    patch = _SINK_PATCH.get(sink_short)
    if not patch:
        res.status = "unknown"
        res.detail = f"sink {sink_short} 暂不支持 CrossHair 验证"
        return res
    import_name, mod_attr, attr = patch

    harness_src = _render_harness(target, import_name, mod_attr, attr)
    res.harness = harness_src

    # 准备专用 venv
    py, detail = _ensure_venv(cfg)
    if py is None:
        res.status = "unknown"
        res.detail = detail
        return res
    _install_target_deps(py, flow, cfg)

    # 写 harness 到临时文件, 用 crosshair check 分析
    workdir = Path(tempfile.mkdtemp(prefix="supplyguard-ch-"))
    hfile = workdir / "sg_harness.py"
    hfile.write_text(harness_src, encoding="utf-8")

    cmd = [str(py), "-m", "crosshair", "check",
           "--per_condition_timeout", str(cfg.symbolic_timeout),
           str(hfile)]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=cfg.symbolic_timeout + 30)
    except subprocess.TimeoutExpired:
        res.status = "unknown"
        res.detail = "CrossHair 超时"
        return res
    except Exception as e:
        res.status = "unknown"
        res.detail = f"运行 crosshair 失败: {e}"
        return res
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)

    out = (cp.stdout or "") + "\n" + (cp.stderr or "")

    # crosshair check: 发现反例时退出码非 0, 并打印形如
    #   sg_harness.py:NN: error: false when calling probe(payload=b'...')
    if "when calling probe(" in out or "error:" in out:
        m = _COUNTEREXAMPLE_RE.search(out)
        res.status = "reachable"
        res.poc_input = m.group(1) if m else "(reachable, 见 crosshair 输出)"
        res.path_constraint = f"reach({sink_short})"
        res.detail = f"CrossHair 求得触达 {attr} 的输入 (反例)"
    elif cp.returncode == 0:
        res.status = "unreachable"
        res.detail = f"CrossHair 确认无输入可触达 {attr} (路径不可达 / 误报)"
    else:
        res.status = "unknown"
        res.detail = f"CrossHair 结果不确定: {out.strip()[-200:]}"
    return res
