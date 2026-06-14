"""模块六：统一漏洞报告生成 (JSON + Markdown)。"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, Dependency

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_SEV_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟩", "unknown": "⬜"}


def build_report(findings: list[Finding], dependencies: list[Dependency],
                 target: str) -> dict:
    findings_sorted = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f.verdict.severity, 4), -f.verdict.confidence),
    )
    by_sev: dict[str, int] = {}
    by_lang: dict[str, int] = {}
    sym_stats = {"reachable": 0, "unreachable": 0, "unknown": 0,
                 "sandbox_validated": 0}
    for f in findings_sorted:
        by_sev[f.verdict.severity] = by_sev.get(f.verdict.severity, 0) + 1
        by_lang[f.flow.language] = by_lang.get(f.flow.language, 0) + 1
        if f.symbolic and f.symbolic.status in sym_stats:
            sym_stats[f.symbolic.status] += 1
        if f.symbolic and f.symbolic.sandbox_validated:
            sym_stats["sandbox_validated"] += 1

    return {
        "tool": "SupplyGuard-LLM",
        "target": target,
        "summary": {
            "total_findings": len(findings_sorted),
            "exploitable": sum(1 for f in findings_sorted if f.verdict.exploitable),
            "by_severity": by_sev,
            "by_language": by_lang,
            "dependencies_scanned": len(dependencies),
            "symbolic": sym_stats,
        },
        "dependencies": [d.to_dict() for d in dependencies],
        "findings": [f.to_dict() for f in findings_sorted],
    }


def write_json(report: dict, path: Path) -> None:
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def write_markdown(report: dict, path: Path) -> None:
    s = report["summary"]
    lines: list[str] = []
    lines.append("# SupplyGuard-LLM 供应链漏洞检测报告\n")
    lines.append(f"- 目标: `{report['target']}`")
    lines.append(f"- 发现总数: **{s['total_findings']}**  (可利用: {s['exploitable']})")
    lines.append(f"- 扫描依赖数: {s['dependencies_scanned']}")
    sev_str = ", ".join(f"{_SEV_EMOJI.get(k,'')}{k}: {v}" for k, v in s["by_severity"].items())
    lines.append(f"- 严重程度分布: {sev_str or '无'}")
    lang_str = ", ".join(f"{k}: {v}" for k, v in s["by_language"].items())
    lines.append(f"- 语言分布: {lang_str or '无'}")
    sym = s.get("symbolic")
    if sym and (sym.get("reachable") or sym.get("unreachable") or sym.get("unknown")):
        lines.append(f"- 符号执行验证: ✅可达 {sym.get('reachable',0)} | "
                     f"❌不可达(误报) {sym.get('unreachable',0)} | "
                     f"⚠️未定 {sym.get('unknown',0)} | "
                     f"🧪沙箱实证 {sym.get('sandbox_validated',0)}")
    lines.append("")

    if report["dependencies"]:
        lines.append("## 依赖清单\n")
        lines.append("| 库 | 版本 | 语言 | 来源 |")
        lines.append("|----|------|------|------|")
        for d in report["dependencies"]:
            lines.append(f"| {d['library']} | {d['version'] or '-'} | {d['language']} | "
                         f"{Path(d['source_file']).name} |")
        lines.append("")

    lines.append("## 漏洞发现\n")
    if not report["findings"]:
        lines.append("_未发现可疑数据流。_\n")
    for i, f in enumerate(report["findings"], 1):
        flow, v = f["flow"], f["verdict"]
        emoji = _SEV_EMOJI.get(v["severity"], "")
        lines.append(f"### {i}. {emoji} {v['vulnerability']}  "
                     f"({v['severity'].upper()}, 置信度 {v['confidence']:.2f})\n")
        lines.append(f"- 文件: `{flow['file']}:{flow['sink_line']}`")
        lines.append(f"- 语言: {flow['language']}  |  CWE: {v['cwe'] or '-'}  |  "
                     f"可利用: {'是' if v['exploitable'] else '否'}")
        lines.append(f"- Source → Sink: `{flow['source']}` → `{flow['sink']}`")
        if flow.get("library"):
            lines.append(f"- 第三方库: `{flow['library']}`")
        if flow.get("key_path"):
            lines.append(f"- 风险传播链: {' → '.join(flow['key_path'])}")
        if f.get("knowledge"):
            k = f["knowledge"]
            lines.append(f"- 知识库: {k['library']} ({k['category']}, {k['cwe']})")
        sym = f.get("symbolic")
        if sym and sym.get("status") not in (None, "not-applicable"):
            status_label = {
                "reachable": "✅ 可达 (符号执行求得 PoC)",
                "unreachable": "❌ 不可达 (判为误报)",
                "unknown": "⚠️ 未定 (超时/路径爆炸)",
                "error": "⚠️ 错误",
            }.get(sym["status"], sym["status"])
            lines.append(f"- 符号执行验证 ({sym.get('engine','')}): {status_label}")
            if sym.get("poc_input"):
                lines.append(f"  - PoC 输入: `{sym['poc_input']}`")
            if sym.get("path_constraint"):
                lines.append(f"  - 路径约束: `{sym['path_constraint']}`")
            if sym.get("sandbox_validated"):
                lines.append(f"  - 🧪 沙箱验证: 通过 — {sym.get('sandbox_evidence','')}")
            elif sym.get("sandbox_evidence"):
                lines.append(f"  - 沙箱: {sym['sandbox_evidence']}")
        if flow.get("code_snippet"):
            lines.append(f"- 代码片段:\n\n  ```{flow['language']}\n  "
                         + flow["code_snippet"].replace("\n", "\n  ") + "\n  ```")
        lines.append(f"- 研判理由: {v['reason']}\n")

    Path(path).write_text("\n".join(lines), encoding="utf-8")
