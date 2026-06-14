"""LLM 生成符号执行入口 (harness) —— 「LLM 融入符号执行【前】」。

让 LLM 阅读 CodeQL 切出的 source->sink 片段, 产出一份**结构化 harness 规格**:
告诉符号执行引擎"哪个变量是外部可控的符号量、从哪开始跑、目标 sink 是什么"。

设计要点:
  - 为安全与稳健, 我们让 LLM 产出**结构化 JSON 规格**(而非可执行脚本), 由我们可信的
    angr 驱动消费; 同时让 LLM 附带一段等价的 angr 脚本文本仅供展示/复现。
  - 无密钥/mock 时退回基于 DataFlow 的启发式规格, 保证流程可跑通。
"""
from __future__ import annotations

import json
import re

from ..models import DataFlow

# 不同 sink 默认的符号输入来源 (启发式兜底用)
_SINK_INPUT_HINT = {
    "system": "stdin", "popen": "argv", "execl": "argv", "execlp": "argv",
    "execv": "argv", "execvp": "argv",
    "strcpy": "argv", "strcat": "argv", "sprintf": "argv", "memcpy": "argv",
    "dlopen": "env",
}

HARNESS_SYSTEM_PROMPT = (
    "You are a program-analysis expert configuring a symbolic execution run (angr for C/C++). "
    "Given a source->sink data flow and the surrounding source code, produce a JSON spec that "
    "tells the symbolic engine how to drive the program toward the sink. "
    "Reply ONLY with a single JSON object, no markdown, with keys: "
    "entry (string, the function to start from, usually 'main'), "
    "symbolic_inputs (array of strings, each one of: 'stdin', 'argv', or 'env:NAME'), "
    "sink_function (string, the libc/library function at the sink, e.g. 'system','strcpy','dlopen','popen'), "
    "sink_argument_index (integer, which argument carries the tainted data, 0-based), "
    "avoid_hints (array of strings, names/notes of branches irrelevant to the vuln), "
    "notes (string, brief)."
)


def _heuristic_spec(flow: DataFlow) -> dict:
    sink = (flow.sink_api or flow.sink or "").split(".")[-1].lower()
    inp = _SINK_INPUT_HINT.get(sink, "stdin")
    if inp == "env":
        symbolic_inputs = ["env:PLUGIN_PATH", "stdin", "argv"]
    elif inp == "argv":
        symbolic_inputs = ["argv", "stdin"]
    else:
        symbolic_inputs = ["stdin", "argv"]
    # strcpy/memcpy 的污点参数是第 2 个 (index 1)
    sink_arg = 1 if sink in ("strcpy", "strcat", "sprintf", "memcpy") else 0
    return {
        "entry": "main",
        "symbolic_inputs": symbolic_inputs,
        "sink_function": sink,
        "sink_argument_index": sink_arg,
        "avoid_hints": [],
        "notes": "heuristic spec (no LLM)",
    }


def _extract_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            text = brace.group(0)
    return json.loads(text)


def _normalize_spec(d: dict, flow: DataFlow) -> dict:
    base = _heuristic_spec(flow)
    out = {
        "entry": str(d.get("entry") or base["entry"]),
        "symbolic_inputs": d.get("symbolic_inputs") or base["symbolic_inputs"],
        "sink_function": str(d.get("sink_function") or base["sink_function"]).split(".")[-1].lower(),
        "sink_argument_index": int(d.get("sink_argument_index", base["sink_argument_index"])
                                   if str(d.get("sink_argument_index", "")).strip() != "" else base["sink_argument_index"]),
        "avoid_hints": d.get("avoid_hints") or [],
        "notes": str(d.get("notes") or ""),
    }
    if not isinstance(out["symbolic_inputs"], list) or not out["symbolic_inputs"]:
        out["symbolic_inputs"] = base["symbolic_inputs"]
    return out


def _render_angr_script(spec: dict, binary_hint: str = "<binary>") -> str:
    """生成等价的 angr 脚本文本 (仅用于报告展示/复现, 不实际执行)。"""
    syms = spec["symbolic_inputs"]
    lines = [
        "import angr, claripy",
        f"proj = angr.Project({binary_hint!r}, auto_load_libs=False)",
        "argv1 = claripy.BVS('argv1', 8 * 64)" if any(s == "argv" for s in syms) else "",
        "state = proj.factory.full_init_state(",
        "    args=[proj.filename, argv1]," if any(s == "argv" for s in syms) else "    args=[proj.filename],",
        "    stdin=angr.SimFileStream(name='stdin', has_end=False),"
        if any(s == "stdin" for s in syms) else "",
        ")",
        f"sink = proj.loader.find_symbol({spec['sink_function']!r}).rebased_addr",
        "mgr = proj.factory.simulation_manager(state)",
        "mgr.explore(find=sink)",
        "if mgr.found:",
        "    s = mgr.found[0]",
        "    print('PoC argv1 =', s.solver.eval(argv1, cast_to=bytes))"
        if any(s == "argv" for s in syms) else "    print('reached sink')",
    ]
    return "\n".join(l for l in lines if l != "")


def generate_harness_spec(flow: DataFlow, llm_client) -> tuple[dict, str]:
    """返回 (结构化规格, 展示用 angr 脚本)。llm_client 为 None 或 mock 时走启发式。"""
    cfg = getattr(llm_client, "cfg", None)
    use_llm = llm_client is not None and cfg is not None and not cfg.mock_llm and cfg.api_key
    if not use_llm:
        spec = _heuristic_spec(flow)
        return spec, _render_angr_script(spec)

    user = (
        "Source->sink data flow:\n"
        + json.dumps({
            "language": flow.language,
            "file": flow.file,
            "source": flow.source,
            "sink": flow.sink,
            "sink_api": flow.sink_api,
            "sink_line": flow.sink_line,
            "key_path": flow.key_path,
            "code_snippet": flow.code_snippet,
        }, ensure_ascii=False, indent=2)
        + "\n\nProduce the angr harness spec JSON now."
    )
    try:
        raw = llm_client._chat(HARNESS_SYSTEM_PROMPT, user)
        spec = _normalize_spec(_extract_json(raw), flow)
    except Exception:
        spec = _heuristic_spec(flow)
    return spec, _render_angr_script(spec)
