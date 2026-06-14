"""CodeQL 后端。

流程:
  1. 自动探测目标语言 (python / java / cpp);
  2. `codeql database create` 建库 (Python/JS 无需编译; Java/C++ 需可编译, 见 README);
  3. `codeql database analyze` 运行 queries/ 下的自定义查询, 输出 SARIF;
  4. 解析 SARIF -> DataFlow 列表。

对环境的要求 (Ubuntu 上你已安装 CodeQL CLI):
  - `codeql` 在 PATH 中, 或通过 --codeql-cli / CODEQL_CLI 指定;
  - 需要对应语言的 query pack (codeql/python-queries 等), 首次会自动下载。
若任一步骤失败, 抛出 CodeQLError, 由上层回退到内置分析器。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..config import Config
from ..knowledge import KnowledgeBase
from ..models import DataFlow

QUERY_DIR = Path(__file__).parent / "queries"

# CodeQL 语言标识 <-> 文件后缀
LANG_EXT = {
    "python": {".py"},
    "java": {".java"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"},
}


class CodeQLError(Exception):
    pass


def _run(cmd: list[str], timeout: int = 1800) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise CodeQLError(f"找不到可执行文件: {cmd[0]} ({e})")
    except subprocess.TimeoutExpired:
        raise CodeQLError(f"命令超时: {' '.join(cmd)}")


def _detect_languages(root: Path) -> list[str]:
    present: set[str] = set()
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        for lang, exts in LANG_EXT.items():
            if ext in exts:
                present.add(lang)
    # 顺序: python 最易建库, cpp 最难
    return [l for l in ("python", "java", "cpp") if l in present]


def _build_cmd_for(lang: str, cfg: Config) -> Optional[str]:
    """Java/C++ 的编译命令。

    优先用用户通过 --codeql-build-command 指定的命令; 否则:
      - python: 无需编译;
      - java/cpp: 返回 None, 交给 CodeQL autobuild 自动探测。
    """
    if lang == "python":
        return None
    if cfg.codeql_build_command:
        return cfg.codeql_build_command
    return None


def analyze_codeql(root: Path, kb: KnowledgeBase, cfg: Config) -> Optional[list[DataFlow]]:
    root = Path(root)
    cli = cfg.codeql_cli
    if not shutil.which(cli) and not Path(cli).exists():
        raise CodeQLError(f"CodeQL CLI 不可用: {cli}")

    languages = _detect_languages(root)
    if cfg.codeql_languages:
        # 用户显式限定语言, 取交集 (保持顺序)
        wanted = [l.lower() for l in cfg.codeql_languages]
        languages = [l for l in languages if l in wanted]
    if not languages:
        raise CodeQLError("目标目录中未发现受支持的源代码 (python/java/cpp), 或被 --codeql-lang 过滤掉")

    all_flows: list[DataFlow] = []
    workdir = Path(tempfile.mkdtemp(prefix="supplyguard-codeql-"))
    try:
        for lang in languages:
            qfile = QUERY_DIR / lang / "TaintToDangerApi.ql"
            if not qfile.exists():
                msg = f"{lang} 没有对应的 CodeQL 查询文件: {qfile}"
                if cfg.codeql_strict:
                    raise CodeQLError(msg)
                print(f"[codeql] {msg} (跳过)")
                continue

            db = workdir / f"db-{lang}"
            create = [cli, "database", "create", str(db),
                      "--language", lang, "--source-root", str(root), "--overwrite"]
            build_cmd = _build_cmd_for(lang, cfg)
            if build_cmd:
                create += ["--command", build_cmd]
            cp = _run(create)
            if cp.returncode != 0:
                detail = (cp.stderr or cp.stdout or "").strip()[-1500:]
                msg = (f"{lang} 建库失败 (returncode={cp.returncode}).\n"
                       f"  Java/C++ 需要能编译的真实工程, 请用 --codeql-build-command 指定编译命令"
                       f" (如 'mvn compile' / 'make')。\n{detail}")
                if cfg.codeql_strict:
                    raise CodeQLError(msg)
                print(f"[codeql] {msg} (跳过)")
                continue

            sarif = workdir / f"results-{lang}.sarif"
            analyze = [cli, "database", "analyze", str(db), str(qfile),
                       "--format", "sarifv2.1.0", "--output", str(sarif),
                       "--rerun", "--threads", "0"]
            cp = _run(analyze)
            if cp.returncode != 0:
                detail = (cp.stderr or cp.stdout or "").strip()[-1500:]
                msg = f"{lang} 查询失败 (returncode={cp.returncode}).\n{detail}"
                if cfg.codeql_strict:
                    raise CodeQLError(msg)
                print(f"[codeql] {msg} (跳过)")
                continue
            all_flows.extend(_parse_sarif(sarif, lang, kb, root))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return all_flows


def _parse_sarif(sarif_path: Path, language: str, kb: KnowledgeBase,
                 root: Optional[Path] = None) -> list[DataFlow]:
    if not sarif_path.exists():
        return []
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    flows: list[DataFlow] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            msg = result.get("message", {}).get("text", "")
            locs = result.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            art = phys.get("artifactLocation", {}).get("uri", "")
            # SARIF uri 多为相对 source-root 的相对路径; 解析为绝对路径便于后续符号执行/沙箱定位
            if art and root is not None and not Path(art).is_absolute():
                resolved = (Path(root) / art)
                if resolved.exists():
                    art = str(resolved.resolve())
            region = phys.get("region", {})
            sink_line = region.get("startLine", 0)

            # code flows: 取首尾作为 source / sink
            source_line = sink_line
            key_path: list[str] = []
            cflows = result.get("codeFlows", [])
            if cflows:
                tflows = cflows[0].get("threadFlows", [])
                if tflows:
                    steps = tflows[0].get("locations", [])
                    for st in steps:
                        loc = st.get("location", {})
                        t = loc.get("message", {}).get("text", "")
                        if t:
                            key_path.append(t)
                    if steps:
                        first = steps[0].get("location", {}).get("physicalLocation", {}).get("region", {})
                        source_line = first.get("startLine", sink_line)

            # 从 message 中提取精确 sink 名 (查询把 "dangerous API pickle.loads." 写进 message)
            full_sink = _guess_full_sink(msg)            # e.g. "pickle.loads"
            sink_api = full_sink.split(".")[-1] if full_sink else _guess_sink_api(msg, kb, language)
            # 用全限定名精确匹配知识库 (避免 'loads' 同时匹配 pickle/marshal 的歧义)
            entry = (kb.match_api(language, full_sink) if full_sink else None) or \
                (kb.match_api(language, sink_api) if sink_api else None)
            flows.append(DataFlow(
                language=language,
                file=art,
                source="external-input",
                source_line=source_line,
                sink=full_sink or sink_api or msg[:60],
                sink_line=sink_line,
                sink_api=sink_api,
                library=entry.library if entry else "",
                key_path=key_path or [full_sink or sink_api or msg[:60]],
                code_snippet=msg,
                tainted=True,
            ))
    return flows


def _guess_full_sink(msg: str) -> str:
    """从 "dangerous API <name>." 中提取完整 sink 名 (如 pickle.loads / os.system)。"""
    m = re.search(r"dangerous API\s+([\w.]+)", msg)
    return m.group(1).strip(".") if m else ""


def _guess_sink_api(msg: str, kb: KnowledgeBase, language: str) -> str:
    # 我们的查询把精确 sink 名写在 "dangerous API <name>." 处, 优先精确提取。
    m = re.search(r"dangerous API\s+([\w.]+)", msg)
    if m:
        name = m.group(1).strip(".")          # 去掉句尾的点
        return name.split(".")[-1]
    # 兜底: 在知识库 api 中取"在消息中出现且最长"的匹配 (避免 'load' 抢先于 'pickle.loads')
    low = msg.lower()
    best = ""
    for api in kb.all_apis(language):
        if api.lower() in low and len(api) > len(best):
            best = api
    return best.split(".")[-1] if best else ""
