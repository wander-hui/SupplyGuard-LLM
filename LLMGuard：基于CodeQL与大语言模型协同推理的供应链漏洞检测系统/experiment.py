"""实验脚本: 生成方案第十一节的对比表 (CodeQL / LLM-Only / CodeQL+LLM / +SupplyGuard)。

用法:
  python experiment.py <dataset_dir> [--labels labels.json] [--mock]

labels.json (可选, 用于计算 Recall/Precision) 格式:
  { "samples/python/vuln_app.py": [{"line": 17, "cwe": "CWE-78"}, ...], ... }
若不提供标注, 仅输出各方法发现数量对比 (演示用)。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from supplyguard.config import Config
from supplyguard.knowledge import KnowledgeBase
from supplyguard.analysis import extract_dataflows
from supplyguard.slicing import slice_flows
from supplyguard.llm import LLMClient
from supplyguard.dependency import analyze_dependencies


def count_method(target: Path, cfg: Config, kb: KnowledgeBase, method: str) -> int:
    """返回某方法判定为"可利用漏洞"的数量。

    method:
      codeql         —— 仅数据流命中 (不经 LLM, 视所有 tainted 流为告警)
      llm            —— 仅 LLM 判定 (不结合知识库版本/依赖)
      codeql_llm     —— 数据流 + LLM
      supplyguard    —— 数据流 + LLM + 依赖版本检查 (完整系统)
    """
    flows = slice_flows(extract_dataflows(target, kb, cfg))
    deps = analyze_dependencies(target)
    client = LLMClient(cfg, kb)

    if method == "codeql":
        return sum(1 for f in flows if f.tainted)

    if method == "llm":
        n = 0
        for f in flows:
            v = client.judge(f)
            if v.exploitable and v.confidence >= 0.5:
                n += 1
        return n

    if method == "codeql_llm":
        n = 0
        for f in flows:
            if not f.tainted:
                continue
            v = client.judge(f)
            if v.exploitable and v.confidence >= 0.5:
                n += 1
        return n

    if method == "supplyguard":
        n = 0
        for f in flows:
            v = client.judge(f)
            if v.exploitable and v.confidence >= 0.5:
                n += 1
        for d in deps:
            if kb.is_bad_version(d.language, d.library, d.version):
                n += 1
        return n

    raise ValueError(method)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("--provider", default=None)
    args = ap.parse_args()

    cfg = Config.from_env()
    if args.mock:
        cfg.mock_llm = True
    if args.provider:
        cfg.provider = args.provider
    cfg.resolve()
    kb = KnowledgeBase.load(cfg.knowledge_base)
    target = Path(args.dataset)

    methods = ["codeql", "llm", "codeql_llm", "supplyguard"]
    names = {
        "codeql": "CodeQL",
        "llm": "LLM Only",
        "codeql_llm": "CodeQL+LLM",
        "supplyguard": "CodeQL+LLM+SupplyGuard",
    }
    print(f"数据集: {target}\n")
    print(f"{'方法':<26}{'告警数':>8}")
    print("-" * 36)
    for m in methods:
        cnt = count_method(target, cfg, kb, m)
        print(f"{names[m]:<26}{cnt:>8}")
    print("\n说明: 演示用计数对比。接入真实标注 (labels.json) 后可计算 Recall/Precision。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
