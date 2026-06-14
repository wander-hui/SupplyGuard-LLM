"""模块三：数据流提取。

提供两种后端:
  1. builtin —— 内置轻量分析器 (Python ast + Java/C++ 正则), 零依赖, 始终可用;
  2. codeql  —— 调用真实 CodeQL CLI 建库 + 跑 taint 查询, 解析 SARIF。

二者输出统一的 DataFlow 列表。
"""
from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..knowledge import KnowledgeBase
from ..models import DataFlow
from .builtin import analyze_builtin
from .codeql import analyze_codeql, CodeQLError


def extract_dataflows(root: Path, kb: KnowledgeBase, cfg: Config) -> list[DataFlow]:
    """根据配置选择后端提取数据流。

    严格模式 (cfg.codeql_strict=True, 默认): CodeQL 失败直接抛 CodeQLError, 不回退。
    非严格模式: CodeQL 整体失败时回退内置分析器。
    """
    if cfg.use_codeql:
        if cfg.codeql_strict:
            flows = analyze_codeql(root, kb, cfg)   # 失败直接抛, 由 CLI 捕获并报错
            return flows if flows is not None else []
        try:
            flows = analyze_codeql(root, kb, cfg)
            if flows is not None:
                return flows
        except CodeQLError as e:
            print(f"[analysis] CodeQL 后端失败, 回退内置分析器: {e}")
    return analyze_builtin(root, kb)


__all__ = ["extract_dataflows", "analyze_builtin", "analyze_codeql", "CodeQLError"]
