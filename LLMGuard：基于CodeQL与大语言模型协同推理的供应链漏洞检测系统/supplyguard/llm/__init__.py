"""模块五：LLM 语义推理。

统一封装 GLM (智谱) 与 DeepSeek 的调用 (二者均兼容 OpenAI Chat Completions 协议),
对每条 source->sink 数据流结合知识库进行漏洞判定, 返回结构化 Verdict。

提供 mock 模式: 无网络/无密钥时用规则模拟, 保证流程可跑通与对比实验。
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from ..config import Config
from ..knowledge import KnowledgeBase
from ..models import DataFlow, Verdict, KnowledgeEntry

SYSTEM_PROMPT = (
    "You are a senior application security auditor specializing in software "
    "supply-chain vulnerabilities across Java, Python and C/C++. "
    "You receive a compressed data-flow (source -> key path -> sink) together with "
    "third-party dependency and knowledge-base context. "
    "Decide whether the flow is a real, exploitable vulnerability. "
    "Reply ONLY with a single JSON object, no markdown, with keys: "
    "vulnerability (string), cwe (string), exploitable (boolean), "
    "confidence (number 0..1), severity (one of low/medium/high/critical), "
    "reason (string, concise)."
)


def build_user_prompt(flow: DataFlow, entry: KnowledgeEntry | None,
                      dep_version: str | None, sym=None) -> str:
    payload = {
        "language": flow.language,
        "file": flow.file,
        "source": flow.source,
        "sink": flow.sink,
        "sink_api": flow.sink_api,
        "library": flow.library,
        "dependency_version": dep_version or "unknown",
        "key_path": flow.key_path,
        "tainted_by_external_input": flow.tainted,
        "code_snippet": flow.code_snippet,
        "knowledge_base_hint": {
            "category": entry.category if entry else "",
            "cwe": entry.cwe if entry else "",
            "description": entry.description if entry else "",
        },
    }
    if sym is not None and sym.status != "not-applicable":
        payload["symbolic_execution"] = {
            "engine": sym.engine,
            "status": sym.status,            # reachable / unreachable / unknown
            "poc_input": sym.poc_input,
            "path_constraint": sym.path_constraint,
            "sandbox_validated": sym.sandbox_validated,
            "sandbox_evidence": sym.sandbox_evidence,
        }
    guidance = (
        "\n\nIMPORTANT — weigh the symbolic_execution evidence if present:\n"
        "- status 'reachable' + sandbox_validated true => strong proof the sink is truly "
        "reachable from untrusted input; set exploitable=true and high confidence (>=0.9).\n"
        "- status 'unreachable' => the static path is infeasible at runtime; this is likely a "
        "FALSE POSITIVE; set exploitable=false and low confidence.\n"
        "- status 'unknown'/'error' => no dynamic evidence; judge from static context only "
        "with moderate confidence.\n"
    ) if (sym is not None and sym.status != "not-applicable") else ""
    return (
        "Analyze the following supply-chain data flow and judge exploitability.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
        + guidance
        + "\n\nConsider: is the sink reachable from untrusted input? Does the library/"
        "version have a known dangerous behavior? Could it lead to RCE / injection / "
        "memory corruption? Return the JSON verdict now."
    )


# --------------------------------------------------------------------------- #
# 解析 LLM 返回
# --------------------------------------------------------------------------- #
def _extract_json(text: str) -> dict:
    text = text.strip()
    # 去掉 ```json ... ``` 包裹
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            text = brace.group(0)
    return json.loads(text)


def _verdict_from_dict(d: dict, raw: str) -> Verdict:
    sev = str(d.get("severity", "unknown")).lower()
    if sev not in ("low", "medium", "high", "critical"):
        sev = "unknown"
    try:
        conf = float(d.get("confidence", 0.0))
    except (TypeError, ValueError):
        conf = 0.0
    return Verdict(
        vulnerability=str(d.get("vulnerability", "Unknown")),
        cwe=str(d.get("cwe", "")),
        exploitable=bool(d.get("exploitable", False)),
        confidence=max(0.0, min(1.0, conf)),
        severity=sev,
        reason=str(d.get("reason", "")),
        raw_response=raw,
    )


# --------------------------------------------------------------------------- #
# LLM 客户端
# --------------------------------------------------------------------------- #
class LLMClient:
    def __init__(self, cfg: Config, kb: KnowledgeBase):
        self.cfg = cfg
        self.kb = kb

    # ---- 远程调用 (OpenAI 兼容 /chat/completions) ---- #
    def _chat(self, system: str, user: str) -> str:
        url = self.cfg.base_url.rstrip("/") + "/chat/completions"
        body = json.dumps({
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.cfg.api_key}")
        with urllib.request.urlopen(req, timeout=self.cfg.request_timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]

    # ---- 对单条数据流推理 ---- #
    def judge(self, flow: DataFlow, dep_version: str | None = None, sym=None) -> Verdict:
        entry = self.kb.match_api(flow.language, flow.sink_api) or \
            self.kb.match_library(flow.language, flow.library)
        if self.cfg.mock_llm or not self.cfg.api_key:
            return self._adjust_with_symbolic(self._mock_judge(flow, entry), sym)
        user = build_user_prompt(flow, entry, dep_version, sym)
        try:
            raw = self._chat(SYSTEM_PROMPT, user)
            d = _extract_json(raw)
            return _verdict_from_dict(d, raw)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            return Verdict(vulnerability="LLM-error", reason=f"网络/接口错误: {e}",
                           confidence=0.0, raw_response=str(e))
        except (json.JSONDecodeError, KeyError) as e:
            # 解析失败时降级为知识库规则判定 (同样结合符号执行)
            v = self._adjust_with_symbolic(self._mock_judge(flow, entry), sym)
            v.reason = f"[LLM 返回解析失败, 用知识库规则] {v.reason}"
            return v

    # ---- 用符号执行结果修正判定 (mock/兜底路径使用; 真实 LLM 已在 prompt 里被告知) ---- #
    def _adjust_with_symbolic(self, verdict: Verdict, sym) -> Verdict:
        if sym is None or sym.status == "not-applicable":
            return verdict
        if sym.status == "reachable":
            verdict.exploitable = True
            verdict.confidence = max(verdict.confidence, 0.97 if sym.sandbox_validated else 0.9)
            ev = "沙箱已实际触发" if sym.sandbox_validated else "符号执行求得 PoC"
            verdict.reason = f"[符号执行: 可达, {ev}] " + verdict.reason
        elif sym.status == "unreachable":
            verdict.exploitable = False
            verdict.confidence = min(verdict.confidence, 0.2)
            verdict.severity = "low"
            verdict.reason = "[符号执行: 路径不可达, 判为误报] " + verdict.reason
        else:  # unknown / error
            verdict.reason = f"[符号执行: {sym.status}] " + verdict.reason
        return verdict

    # ---- 离线规则模拟 (基线 / 兜底) ---- #
    def _mock_judge(self, flow: DataFlow, entry: KnowledgeEntry | None) -> Verdict:
        if not entry:
            return Verdict(vulnerability="No clear issue", exploitable=False,
                           confidence=0.2, severity="low",
                           reason="未命中知识库危险 API。", raw_response="[mock]")
        cat_to_vuln = {
            "deserialization": ("Unsafe Deserialization", "high"),
            "command-exec": ("OS Command Injection", "critical"),
            "dynamic-exec": ("Code Injection / Dynamic Execution", "high"),
            "memory": ("Memory Corruption / Buffer Overflow", "high"),
            "dangerous-version": ("Vulnerable Dependency Version", "medium"),
        }
        vuln, sev = cat_to_vuln.get(entry.category, ("Suspicious API Usage", "medium"))
        # 受外部输入污染则置信度更高
        conf = 0.9 if flow.tainted else 0.55
        if not flow.tainted:
            sev = "low" if sev in ("high", "critical") else sev
        return Verdict(
            vulnerability=vuln, cwe=entry.cwe, exploitable=flow.tainted,
            confidence=conf, severity=sev,
            reason=(f"命中知识库组件 {entry.library} ({entry.category}); "
                    + ("外部输入可达 sink, " if flow.tainted else "未确认外部输入可达, ")
                    + entry.description),
            raw_response="[mock]",
        )
