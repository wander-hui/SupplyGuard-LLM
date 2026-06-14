"""统一数据模型 (dataclasses)。

整个系统在各模块之间传递的核心结构，便于序列化为 JSON 供 LLM 推理 / 报告生成。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ----------------------------- 依赖分析 ----------------------------- #
@dataclass
class Dependency:
    """一个第三方依赖项。"""
    library: str
    version: str = ""
    language: str = ""          # java / python / cpp
    source_file: str = ""       # 来自哪个清单文件 (pom.xml / requirements.txt ...)
    raw: str = ""               # 原始声明文本

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------- 知识库 ----------------------------- #
@dataclass
class KnowledgeEntry:
    """供应链危险组件知识库中的一条记录。"""
    library: str
    danger_api: list[str] = field(default_factory=list)
    cwe: str = ""
    category: str = ""          # deserialization / command-exec / dynamic-exec / memory / dangerous-version
    languages: list[str] = field(default_factory=list)
    bad_versions: list[str] = field(default_factory=list)   # 已知危险版本 (精确匹配, 第一版够用)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------- 数据流 / 路径 ----------------------------- #
@dataclass
class DataFlow:
    """一条 source -> sink 的数据流 (CodeQL 或内置分析器提取)。"""
    language: str
    file: str
    source: str                 # 污点来源, e.g. input() / request.getParameter
    source_line: int
    sink: str                   # 危险调用, e.g. pickle.loads / parseObject
    sink_line: int
    sink_api: str = ""          # 归一化后的 API 名 (用于匹配知识库)
    library: str = ""           # 关联的第三方库 (若能确定)
    key_path: list[str] = field(default_factory=list)   # 压缩后的关键传播节点
    code_snippet: str = ""      # sink 附近的源码片段
    tainted: bool = True        # 是否确实由外部输入污染 (内置分析器的初步判断)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------- 符号执行验证 ----------------------------- #
@dataclass
class SymbolicResult:
    """动态符号执行对一条数据流的可达性验证结果。

    status 取值:
      reachable      —— 符号执行求解到可达 sink 的输入 (SAT), poc_input 为触发输入;
      unreachable    —— 路径约束不可满足 (UNSAT), 判为误报;
      unknown        —— 超时/路径爆炸/建模不全, 未定;
      not-applicable —— 该语言/场景不做符号执行 (如 Java), 走纯静态判定;
      error          —— 工具/环境错误。
    """
    status: str = "not-applicable"
    engine: str = ""                # angr / crosshair / llm-z3
    poc_input: str = ""             # 触发 sink 的具体输入 (PoC)
    path_constraint: str = ""       # 到达 sink 的路径约束 (可读形式)
    sandbox_validated: bool = False # 是否在沙箱中实际运行 PoC 并确认到达 sink
    sandbox_evidence: str = ""      # 沙箱验证证据 (如标记文件出现 / crash / ASAN 报告)
    detail: str = ""                # 过程说明 / 错误信息
    harness: str = ""               # LLM 生成的符号执行入口脚本 (便于复现与展示)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("harness", None)      # harness 可能较长, 报告里默认不展开
        return d


# ----------------------------- LLM 推理结果 ----------------------------- #
@dataclass
class Verdict:
    """LLM 对一条数据流的语义判定。"""
    vulnerability: str = "Unknown"
    cwe: str = ""
    exploitable: bool = False
    confidence: float = 0.0
    severity: str = "unknown"   # low / medium / high / critical
    reason: str = ""
    raw_response: str = ""      # 原始返回, 便于排查

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw_response", None)   # 报告里默认不展开原始返回
        return d


# ----------------------------- 最终发现 ----------------------------- #
@dataclass
class Finding:
    """一个完整的漏洞发现 = 数据流 + 知识库命中 + 符号验证 + LLM 判定。"""
    flow: DataFlow
    verdict: Verdict
    dependency: Optional[Dependency] = None
    knowledge: Optional[KnowledgeEntry] = None
    symbolic: Optional[SymbolicResult] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow": self.flow.to_dict(),
            "verdict": self.verdict.to_dict(),
            "dependency": self.dependency.to_dict() if self.dependency else None,
            "knowledge": self.knowledge.to_dict() if self.knowledge else None,
            "symbolic": self.symbolic.to_dict() if self.symbolic else None,
        }
