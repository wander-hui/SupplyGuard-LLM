"""内置轻量数据流分析器 (零外部依赖)。

设计目标: 在没有 CodeQL 的环境下也能跑通整套流程, 用于演示与对比基线。

- Python: 使用标准库 `ast`, 做函数内 (intraprocedural) 的污点传播:
    * 识别 source (input/sys.argv/os.environ/Flask request 等);
    * 跟踪被污染的变量;
    * 当污染变量流入知识库中的 danger_api (sink) 时, 记录一条 DataFlow。
- Java / C++: 基于正则的 source/sink 共现分析 (函数级窗口), 精度较低但够演示。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from ..knowledge import KnowledgeBase
from ..models import DataFlow

# --------------------------------------------------------------------------- #
# 通用: 外部输入 source 标识
# --------------------------------------------------------------------------- #
PY_SOURCE_CALLS = {"input", "raw_input"}
PY_SOURCE_ATTRS = {
    "argv",          # sys.argv
    "environ",       # os.environ
    "get", "form", "args", "values", "json", "data", "cookies",  # flask request.*
    "getvalue", "read", "recv",
}
PY_SOURCE_NAMES = {"request", "stdin"}


def _line_snippet(lines: list[str], lineno: int, ctx: int = 1) -> str:
    lo = max(0, lineno - 1 - ctx)
    hi = min(len(lines), lineno + ctx)
    return "\n".join(lines[lo:hi]).strip()


# --------------------------------------------------------------------------- #
# Python (AST)
# --------------------------------------------------------------------------- #
class _PyTaintVisitor(ast.NodeVisitor):
    def __init__(self, kb: KnowledgeBase, path: Path, src_lines: list[str]):
        self.kb = kb
        self.path = path
        self.lines = src_lines
        self.flows: list[DataFlow] = []
        # import 别名: 模块导入名 -> 真实模块  (import yaml as y  =>  {"y": "yaml"})
        self.aliases: dict[str, str] = {}
        # from x import loads  => {"loads": "x"}
        self.from_imports: dict[str, str] = {}

    # ---- imports ---- #
    def visit_Import(self, node: ast.Import):
        for n in node.names:
            self.aliases[n.asname or n.name] = n.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for n in node.names:
            self.from_imports[n.asname or n.name] = mod
        self.generic_visit(node)

    # ---- 每个函数独立做污点跟踪 ---- #
    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._analyze_scope(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._analyze_scope(node)
        self.generic_visit(node)

    # 模块级语句也跟踪一次
    def analyze_module(self, tree: ast.Module):
        self._analyze_scope(tree)

    # --------------------------------------------------------------- #
    def _analyze_scope(self, scope) -> None:
        tainted: set[str] = set()
        # 函数参数视为潜在外部输入 (保守)
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in scope.args.args:
                if arg.arg not in ("self", "cls"):
                    tainted.add(arg.arg)

        for stmt in ast.walk(scope):
            # 赋值: x = <expr>
            if isinstance(stmt, ast.Assign):
                if self._expr_is_tainted(stmt.value, tainted):
                    for tgt in stmt.targets:
                        for name in self._target_names(tgt):
                            tainted.add(name)
            # 调用: 检查是否 sink
            if isinstance(stmt, ast.Call):
                self._check_sink(stmt, tainted)

    def _target_names(self, tgt) -> list[str]:
        if isinstance(tgt, ast.Name):
            return [tgt.id]
        if isinstance(tgt, (ast.Tuple, ast.List)):
            out = []
            for e in tgt.elts:
                out.extend(self._target_names(e))
            return out
        return []

    def _call_name(self, call: ast.Call) -> tuple[str, str]:
        """返回 (完整调用名, 末段名), 如 pickle.loads -> ('pickle.loads','loads')。"""
        func = call.func
        if isinstance(func, ast.Name):
            return func.id, func.id
        if isinstance(func, ast.Attribute):
            parts = []
            cur = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            parts.reverse()
            return ".".join(parts), func.attr
        return "", ""

    def _is_source_call(self, call: ast.Call) -> bool:
        full, short = self._call_name(call)
        if short in PY_SOURCE_CALLS:
            return True
        if isinstance(call.func, ast.Attribute):
            if call.func.attr in PY_SOURCE_ATTRS:
                # request.args.get / sys.argv / os.environ.get ...
                base = full.split(".")[0]
                if base in PY_SOURCE_NAMES or any(b in full for b in ("request", "sys.", "os.environ")):
                    return True
        return False

    def _expr_is_tainted(self, expr, tainted: set[str]) -> bool:
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in tainted:
                return True
            if isinstance(node, ast.Call) and self._is_source_call(node):
                return True
            # sys.argv / os.environ 下标访问
            if isinstance(node, ast.Attribute) and node.attr in ("argv", "environ"):
                return True
        return False

    def _resolve_module(self, full: str, short: str) -> str:
        """把调用名解析为知识库可识别的库名。"""
        base = full.split(".")[0]
        if base in self.aliases:
            return self.aliases[base]
        if short in self.from_imports:        # from pickle import loads
            return self.from_imports[short]
        if base in self.from_imports:
            return self.from_imports[base]
        return base

    def _check_sink(self, call: ast.Call, tainted: set[str]) -> None:
        full, short = self._call_name(call)
        if not short:
            return
        module = self._resolve_module(full, short)
        # 在知识库中匹配 sink (先按模块.api, 再按 api)
        entry = self.kb.match_api("python", f"{module}.{short}") or self.kb.match_api("python", short)
        if not entry:
            return
        # builtins 的 eval/exec 等也算
        tainted_arg = any(self._expr_is_tainted(a, tainted) for a in call.args) or \
            any(self._expr_is_tainted(kw.value, tainted) for kw in call.keywords)
        lineno = getattr(call, "lineno", 0)
        self.flows.append(DataFlow(
            language="python",
            file=str(self.path),
            source="external-input" if tainted_arg else "literal/unknown",
            source_line=lineno,
            sink=f"{module}.{short}",
            sink_line=lineno,
            sink_api=short,
            library=module,
            key_path=[f"{module}.{short}"],
            code_snippet=_line_snippet(self.lines, lineno),
            tainted=tainted_arg,
        ))


def _analyze_python_file(path: Path, kb: KnowledgeBase) -> list[DataFlow]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    v = _PyTaintVisitor(kb, path, lines)
    v.visit(tree)              # 收集 import + 各函数
    v.analyze_module(tree)     # 模块级
    return v.flows


# --------------------------------------------------------------------------- #
# Java / C++ (正则, 函数级窗口共现)
# --------------------------------------------------------------------------- #
JAVA_SOURCES = [
    r"getParameter", r"getHeader", r"getInputStream", r"getReader",
    r"request\.", r"args\[", r"System\.getenv", r"readLine", r"getQueryString",
]
CPP_SOURCES = [
    r"\bscanf\b", r"\bgets\b", r"\bfgets\b", r"\bgetenv\b", r"\bread\b",
    r"\brecv\b", r"\bargv\b", r"std::cin",
]


def _regex_dataflows(path: Path, kb: KnowledgeBase, language: str,
                     source_patterns: list[str]) -> list[DataFlow]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    flows: list[DataFlow] = []
    sink_apis = kb.sink_apis(language)
    if not sink_apis:
        return flows
    src_re = re.compile("|".join(source_patterns))

    # 找到所有 source 行号
    source_lines = [i + 1 for i, ln in enumerate(lines) if src_re.search(ln)]
    has_source_global = bool(source_lines)

    for i, ln in enumerate(lines, start=1):
        for api in sink_apis:
            # 词边界匹配 (api 可能含 '.', 用 re.escape); 大小写不敏感
            pat = re.escape(api)
            if re.search(rf"\b{pat}\b", ln, re.IGNORECASE) or \
                    (("." in api) and api.lower() in ln.lower()):
                entry = kb.match_api(language, api)
                # 判断附近 (±40 行) 是否有 source, 作为污染近似
                near_source = any(abs(sl - i) <= 40 for sl in source_lines)
                tainted = near_source or has_source_global
                lib = entry.library if entry else ""
                flows.append(DataFlow(
                    language=language,
                    file=str(path),
                    source="external-input" if tainted else "unknown",
                    source_line=min(source_lines, key=lambda sl: abs(sl - i)) if source_lines else i,
                    sink=api,
                    sink_line=i,
                    sink_api=api.split(".")[-1],
                    library=lib,
                    key_path=[api],
                    code_snippet=_line_snippet(lines, i),
                    tainted=tainted,
                ))
                break   # 一行命中一个 sink 即可
    return flows


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
PY_EXT = {".py"}
JAVA_EXT = {".java"}
CPP_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}


def analyze_builtin(root: Path, kb: KnowledgeBase) -> list[DataFlow]:
    root = Path(root)
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    flows: list[DataFlow] = []
    for p in files:
        ext = p.suffix.lower()
        try:
            if ext in PY_EXT:
                flows.extend(_analyze_python_file(p, kb))
            elif ext in JAVA_EXT:
                flows.extend(_regex_dataflows(p, kb, "java", JAVA_SOURCES))
            elif ext in CPP_EXT:
                flows.extend(_regex_dataflows(p, kb, "cpp", CPP_SOURCES))
        except Exception:
            continue
    return flows
