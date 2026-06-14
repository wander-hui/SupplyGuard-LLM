"""SupplyGuard-LLM 命令行入口。

用法示例:
  python -m supplyguard.cli scan ./samples --mock
  python -m supplyguard.cli scan ./project --provider deepseek --out report
  python -m supplyguard.cli scan ./project --use-codeql --provider glm
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config
from .pipeline import run_scan
from .report import build_report, write_json, write_markdown
from .analysis import CodeQLError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="supplyguard",
        description="SupplyGuard-LLM: 基于程序分析与大语言模型协同推理的跨语言供应链漏洞检测系统",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="扫描目标目录/文件")
    sc.add_argument("target", help="待扫描的源码目录或文件")
    sc.add_argument("--provider", choices=["glm", "deepseek"], default=None,
                    help="LLM 提供商 (默认读环境变量 SUPPLYGUARD_PROVIDER, 否则 glm)")
    sc.add_argument("--model", default=None, help="覆盖默认模型名")
    sc.add_argument("--api-key", default=None, help="API Key (默认读对应环境变量)")
    sc.add_argument("--base-url", default=None, help="覆盖 API base url")
    sc.add_argument("--mock", action="store_true", help="离线模式: 用规则模拟 LLM (无需密钥)")
    sc.add_argument("--use-codeql", action="store_true", help="使用 CodeQL 后端 (需已安装 codeql CLI)")
    sc.add_argument("--codeql-cli", default=None, help="codeql 可执行文件路径")
    sc.add_argument("--codeql-build-command", default=None,
                    help="Java/C++ 编译命令, 如 'mvn compile' 或 'make'; 不指定则用 CodeQL autobuild")
    sc.add_argument("--codeql-lang", default=None,
                    help="限定 CodeQL 只跑哪些语言, 逗号分隔, 如 python,cpp (默认自动探测全部)")
    sc.add_argument("--codeql-no-strict", action="store_true",
                    help="某语言 CodeQL 失败时回退内置分析器 (默认严格: 失败即报错)")
    # 符号执行
    sc.add_argument("--use-symbolic", action="store_true",
                    help="启用动态符号执行验证 (C/C++ 用 angr; 需 pip install angr)")
    sc.add_argument("--no-sandbox", action="store_true",
                    help="符号执行求得 PoC 后不在 Docker 沙箱实际运行验证")
    sc.add_argument("--symbolic-timeout", type=int, default=None,
                    help="单条数据流符号执行超时(秒), 默认 120")
    sc.add_argument("--out", default="report", help="输出文件前缀 (生成 .json 与 .md)")
    sc.add_argument("--quiet", action="store_true", help="减少过程输出")

    kb = sub.add_parser("kb", help="查看知识库统计")
    kb.add_argument("--knowledge-base", default=None)
    return p


def _make_config(args) -> Config:
    cfg = Config.from_env()
    if getattr(args, "provider", None):
        cfg.provider = args.provider
    if getattr(args, "model", None):
        cfg.model = args.model
    if getattr(args, "api_key", None):
        cfg.api_key = args.api_key
    if getattr(args, "base_url", None):
        cfg.base_url = args.base_url
    if getattr(args, "mock", False):
        cfg.mock_llm = True
    if getattr(args, "use_codeql", False):
        cfg.use_codeql = True
    if getattr(args, "codeql_cli", None):
        cfg.codeql_cli = args.codeql_cli
    if getattr(args, "codeql_build_command", None):
        cfg.codeql_build_command = args.codeql_build_command
    if getattr(args, "codeql_lang", None):
        cfg.codeql_languages = [s.strip().lower() for s in args.codeql_lang.split(",") if s.strip()]
    if getattr(args, "codeql_no_strict", False):
        cfg.codeql_strict = False
    if getattr(args, "use_symbolic", False):
        cfg.use_symbolic = True
    if getattr(args, "no_sandbox", False):
        cfg.use_sandbox = False
    if getattr(args, "symbolic_timeout", None):
        cfg.symbolic_timeout = args.symbolic_timeout
    return cfg.resolve()


def cmd_scan(args) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"错误: 目标不存在: {target}", file=sys.stderr)
        return 2
    cfg = _make_config(args)
    verbose = not args.quiet

    try:
        findings, deps = run_scan(target, cfg, verbose=verbose)
    except CodeQLError as e:
        print(f"\n[CodeQL 错误] {e}", file=sys.stderr)
        print("\n提示: 严格模式下 CodeQL 失败即停止。可改用:", file=sys.stderr)
        print("  --codeql-build-command 'mvn compile'   指定 Java/C++ 编译命令", file=sys.stderr)
        print("  --codeql-lang python                   只跑能建库的语言", file=sys.stderr)
        print("  --codeql-no-strict                     失败时回退内置分析器", file=sys.stderr)
        return 3
    report = build_report(findings, deps, target=str(target))

    out_json = Path(f"{args.out}.json")
    out_md = Path(f"{args.out}.md")
    write_json(report, out_json)
    write_markdown(report, out_md)

    s = report["summary"]
    print("\n========== 扫描完成 ==========")
    print(f"发现 {s['total_findings']} 个问题 (可利用 {s['exploitable']}), "
          f"严重程度: {s['by_severity']}")
    sym = s.get("symbolic", {})
    if cfg.use_symbolic:
        print(f"符号执行: 可达 {sym.get('reachable',0)} | 不可达/误报 {sym.get('unreachable',0)} | "
              f"未定 {sym.get('unknown',0)} | 沙箱实证 {sym.get('sandbox_validated',0)}")
    print(f"报告已写入: {out_json}  |  {out_md}")
    return 0


def cmd_kb(args) -> int:
    cfg = Config.from_env()
    if getattr(args, "knowledge_base", None):
        cfg.knowledge_base = Path(args.knowledge_base)
    from .knowledge import KnowledgeBase
    kb = KnowledgeBase.load(cfg.knowledge_base)
    cats: dict[str, int] = {}
    langs: dict[str, int] = {}
    for e in kb.entries:
        cats[e.category] = cats.get(e.category, 0) + 1
        for l in e.languages:
            langs[l] = langs.get(l, 0) + 1
    print(f"知识库条目: {len(kb.entries)}")
    print(f"按类别: {cats}")
    print(f"按语言: {langs}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "kb":
        return cmd_kb(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
