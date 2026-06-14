"""模块四：风险传播链切片 / 压缩。

把可能很长的调用链压缩为 source -> 关键节点 -> sink, 既保留语义又大幅降低
送入 LLM 的 token。这是方案中的创新点之一。
"""
from __future__ import annotations

import re

from ..models import DataFlow

# 压缩时优先保留的节点 (含这些关键字的路径节点视为"关键")
_KEEP_HINTS = (
    "request", "input", "param", "argv", "environ", "getenv", "recv", "read",
    "parse", "load", "exec", "system", "popen", "eval", "deserial", "readobject",
    "runtime", "process", "yaml", "pickle", "forname", "scriptengine",
)


def _is_key_node(node: str) -> bool:
    low = node.lower()
    return any(h in low for h in _KEEP_HINTS)


def compress_path(flow: DataFlow, max_nodes: int = 6) -> list[str]:
    """压缩一条数据流的 key_path。

    规则:
      - 始终保留首 (source) 与尾 (sink);
      - 中间节点优先保留命中关键字者;
      - 仍超出 max_nodes 时, 均匀采样中间节点。
    """
    path = [p for p in flow.key_path if p]
    if not path:
        path = [flow.source, flow.sink]
    if len(path) <= max_nodes:
        return path

    head, tail = path[0], path[-1]
    middle = path[1:-1]

    key_middle = [n for n in middle if _is_key_node(n)]
    budget = max_nodes - 2

    if len(key_middle) <= budget:
        chosen = key_middle
        # 不足则用均匀采样补齐
        if len(chosen) < budget:
            remaining = [n for n in middle if n not in chosen]
            step = max(1, len(remaining) // (budget - len(chosen) or 1))
            chosen = chosen + remaining[::step]
            chosen = chosen[:budget]
    else:
        step = max(1, len(key_middle) // budget)
        chosen = key_middle[::step][:budget]

    # 保持原始顺序
    ordered_middle = [n for n in middle if n in set(chosen)]
    return [head] + ordered_middle + [tail]


def slice_flows(flows: list[DataFlow], max_nodes: int = 6) -> list[DataFlow]:
    """对所有数据流就地压缩 key_path, 返回新列表。"""
    out: list[DataFlow] = []
    seen: set[tuple] = set()
    for f in flows:
        f.key_path = compress_path(f, max_nodes=max_nodes)
        # 去重: 同文件同 sink 同 sink_line 视为同一条
        sig = (f.file, f.sink, f.sink_line)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(f)
    return out
