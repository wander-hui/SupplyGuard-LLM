"""动态符号执行模块 (可选增强)。

对外暴露 verify_flow(): 对一条 DataFlow 做「LLM生成harness -> 符号执行 -> 沙箱验证」,
返回 SymbolicResult。当前实现 C/C++ (angr); Python (crosshair) 预留; 其余语言 not-applicable。
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..config import Config
from ..models import DataFlow, SymbolicResult
from .harness import generate_harness_spec
from .angr_backend import run_angr
from .sandbox import validate_in_sandbox

_CPP_LANGS = {"cpp", "c", "c++"}


def verify_flow(flow: DataFlow, cfg: Config, llm_client=None) -> SymbolicResult:
    lang = (flow.language or "").lower()

    if lang not in {l.lower() for l in cfg.symbolic_languages}:
        return SymbolicResult(status="not-applicable",
                              detail=f"{lang} 不在 symbolic_languages 中")

    if lang in _CPP_LANGS:
        # 1) LLM 生成 harness 规格 (融入【前】)
        spec, script = generate_harness_spec(flow, llm_client)
        # 2) angr 符号执行
        workdir = Path(tempfile.mkdtemp(prefix="supplyguard-sym-"))
        try:
            res = run_angr(flow, spec, script, cfg, workdir)
            # 3) 沙箱实际验证 PoC
            if res.status == "reachable":
                res = validate_in_sandbox(flow, res, cfg, workdir)
        finally:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
        return res

    if lang == "python":
        from .crosshair_backend import run_crosshair
        res = run_crosshair(flow, cfg, llm_client=llm_client)
        if res.status == "reachable":
            from .sandbox import validate_python_in_sandbox
            res = validate_python_in_sandbox(flow, res, cfg)
        return res

    return SymbolicResult(status="not-applicable", detail=f"{lang} 暂不支持符号执行")


__all__ = ["verify_flow"]
