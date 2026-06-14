"""主流程编排: 依赖分析 -> 知识库 -> 数据流提取 -> 切片 -> LLM 推理 -> 报告。"""
from __future__ import annotations

from pathlib import Path

from .config import Config
from .knowledge import KnowledgeBase
from .dependency import analyze_dependencies
from .analysis import extract_dataflows
from .slicing import slice_flows
from .llm import LLMClient
from .models import Finding, Dependency, DataFlow, Verdict


def _dep_version_for(flow: DataFlow, deps: list[Dependency]) -> str | None:
    for d in deps:
        if d.language == flow.language and flow.library and \
                d.library.lower() == flow.library.lower():
            return d.version
        # 部分匹配 (artifactId 含库名)
        if d.language == flow.language and flow.library and \
                flow.library.lower() in d.library.lower():
            return d.version
    return None


def run_scan(target: Path, cfg: Config, verbose: bool = True) -> tuple[list[Finding], list[Dependency]]:
    target = Path(target)
    kb = KnowledgeBase.load(cfg.knowledge_base)

    if verbose:
        print(f"[1/5] 依赖分析: {target}")
    deps = analyze_dependencies(target)
    if verbose:
        print(f"      发现 {len(deps)} 个依赖声明")

    if verbose:
        backend = "CodeQL" if cfg.use_codeql else "内置分析器"
        print(f"[2/5] 数据流提取 (后端: {backend})")
    flows = extract_dataflows(target, kb, cfg)
    if verbose:
        print(f"      提取 {len(flows)} 条候选数据流")

    if verbose:
        print("[3/5] 风险传播链切片")
    flows = slice_flows(flows)
    flows = flows[: cfg.max_findings]
    if verbose:
        print(f"      压缩去重后 {len(flows)} 条")

    if verbose:
        mode = "mock" if (cfg.mock_llm or not cfg.api_key) else f"{cfg.provider}/{cfg.model}"
        sym_on = "开" if cfg.use_symbolic else "关"
        print(f"[4/5] 符号执行验证(符号执行:{sym_on}) + LLM 语义推理 (模式: {mode})")
    client = LLMClient(cfg, kb)
    findings: list[Finding] = []
    sym_budget = cfg.symbolic_max_findings
    for i, flow in enumerate(flows, 1):
        version = _dep_version_for(flow, deps)

        # 符号执行验证 (可选): 仅对受支持语言、且在预算内
        sym = None
        if cfg.use_symbolic and sym_budget > 0 and \
                flow.language.lower() in {l.lower() for l in cfg.symbolic_languages}:
            from .symbolic import verify_flow
            sym = verify_flow(flow, cfg, llm_client=client)
            if sym.status in ("reachable", "unreachable"):
                sym_budget -= 1   # 只对真正跑出结论的计入预算

        verdict: Verdict = client.judge(flow, dep_version=version, sym=sym)
        entry = kb.match_api(flow.language, flow.sink_api) or \
            kb.match_library(flow.language, flow.library)
        dep_obj = next((d for d in deps if d.language == flow.language and flow.library
                        and d.library.lower() == flow.library.lower()), None)
        findings.append(Finding(flow=flow, verdict=verdict, dependency=dep_obj,
                                knowledge=entry, symbolic=sym))
        if verbose:
            sym_tag = f" [符号:{sym.status}]" if sym else ""
            print(f"      [{i}/{len(flows)}] {flow.sink} -> "
                  f"{verdict.vulnerability} ({verdict.severity}, {verdict.confidence:.2f}){sym_tag}")

    # 额外: 危险依赖版本 (无需数据流, 直接基于清单 + 知识库)
    for d in deps:
        entry = kb.is_bad_version(d.language, d.library, d.version)
        if entry:
            flow = DataFlow(
                language=d.language, file=d.source_file,
                source="dependency-manifest", source_line=0,
                sink=f"{d.library}@{d.version}", sink_line=0,
                sink_api="", library=d.library,
                key_path=[f"{d.library}@{d.version}"],
                code_snippet=d.raw, tainted=False,
            )
            verdict = Verdict(
                vulnerability="Vulnerable Dependency Version", cwe=entry.cwe,
                exploitable=True, confidence=0.85, severity="high",
                reason=f"依赖 {d.library} 版本 {d.version} 属已知危险版本: {entry.description}",
                raw_response="[version-check]",
            )
            findings.append(Finding(flow=flow, verdict=verdict, dependency=d, knowledge=entry))
            if verbose:
                print(f"      [版本检查] {d.library}@{d.version} -> 已知危险版本")

    if verbose:
        print("[5/5] 生成报告")
    return findings, deps
