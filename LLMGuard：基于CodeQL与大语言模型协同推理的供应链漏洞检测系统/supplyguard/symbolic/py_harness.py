"""Python 符号执行入口分析 —— 「LLM 融入符号执行【前】」(Python 侧)。

用 ast 定位 sink 所在的函数, 提取函数名、参数及类型注解, 供 CrossHair 把参数作为
符号量求解。LLM(若可用)进一步判断哪个参数承载外部输入、推断更精确的参数类型。
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from ..models import DataFlow


def _annotation_to_type(node) -> str:
    """把 ast 注解节点转成简单类型名 (str/bytes/int/...)。"""
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _find_enclosing_function(tree: ast.AST, sink_line: int):
    """找到包含 sink_line 的最内层函数定义。"""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = max((getattr(n, "lineno", start) for n in ast.walk(node)), default=start)
            if start <= sink_line <= end:
                if best is None or node.lineno > best.lineno:   # 取最内层(行号最大)
                    best = node
    return best


# CrossHair 支持的、便于求解的参数类型 (按对 sink 的常见承载排序)
_PREFERRED_TYPES = ("str", "bytes")


def analyze_python_target(flow: DataFlow):
    """返回 dict: {module_path, func_name, params:[{name,type}], sink_api, sink_call}。

    找不到合适函数时返回 None (上层据此给 not-applicable/unknown)。
    """
    from .angr_backend import _locate_source
    src = _locate_source(flow)
    if src is None:
        return None
    try:
        text = Path(src).read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text)
    except Exception:
        return None

    fn = _find_enclosing_function(tree, flow.sink_line)
    if fn is None:
        return None

    params = []
    for arg in fn.args.args:
        if arg.arg in ("self", "cls"):
            continue
        t = _annotation_to_type(arg.annotation)
        params.append({"name": arg.arg, "type": t or "bytes"})

    return {
        "module_path": str(src),
        "func_name": fn.name,
        "params": params,
        "sink_api": flow.sink_api or flow.sink,
    }


# ------------------------- LLM 精修 (可选) ------------------------- #
PY_HARNESS_SYSTEM = (
    "You configure a CrossHair symbolic-execution run for a Python function. "
    "Given the function signature and the dangerous sink it contains, decide the best "
    "concrete parameter types to make the sink reachable. "
    "Reply ONLY with JSON: {\"params\":[{\"name\":..,\"type\":\"str|bytes|int\"}], \"notes\":..}."
)


def refine_with_llm(target: dict, flow: DataFlow, llm_client) -> dict:
    cfg = getattr(llm_client, "cfg", None)
    use_llm = llm_client is not None and cfg is not None and not cfg.mock_llm and cfg.api_key
    if not use_llm or not target:
        return target
    user = (
        "Function and sink:\n"
        + json.dumps({
            "func_name": target["func_name"],
            "params": target["params"],
            "sink_api": target["sink_api"],
            "code_snippet": flow.code_snippet,
        }, ensure_ascii=False, indent=2)
        + "\n\nReturn refined params JSON now."
    )
    try:
        raw = llm_client._chat(PY_HARNESS_SYSTEM, user)
        import re
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            d = json.loads(m.group(0))
            if isinstance(d.get("params"), list) and d["params"]:
                # 仅采纳已知类型
                for p in d["params"]:
                    if p.get("type") not in ("str", "bytes", "int"):
                        p["type"] = "bytes"
                target = {**target, "params": d["params"]}
    except Exception:
        pass
    return target
