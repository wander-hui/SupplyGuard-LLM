"""SupplyGuard-LLM Web 界面 (Flask)。

复用 supplyguard.pipeline.run_scan 与 report.build_report, 不改核心逻辑。
扫描在后台线程执行, 前端轮询 /api/status 获取实时进度与最终报告。

启动:
  python -m webapp.app            # 默认 http://127.0.0.1:5000
  PORT=8080 python -m webapp.app
"""
from __future__ import annotations

import io
import os
import threading
import traceback
from contextlib import redirect_stdout
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from supplyguard.config import Config, PROVIDER_PRESETS
from supplyguard.pipeline import run_scan
from supplyguard.report import build_report
from supplyguard.knowledge import KnowledgeBase

app = Flask(__name__)

# 单次扫描的全局任务状态 (演示用单任务模型)
_JOB = {
    "running": False,
    "logs": [],
    "report": None,
    "error": None,
    "done": False,
}
_LOCK = threading.Lock()


# --------------------------- 实时日志流 --------------------------- #
class _LogStream(io.TextIOBase):
    """把 run_scan 的 print 输出实时写入 _JOB['logs']。"""
    def write(self, s):
        if s and s.strip():
            with _LOCK:
                _JOB["logs"].append(s.rstrip("\n"))
        return len(s)


def _run_job(target: str, cfg: Config):
    try:
        stream = _LogStream()
        with redirect_stdout(stream):
            findings, deps = run_scan(Path(target), cfg, verbose=True)
        report = build_report(findings, deps, target=target)
        with _LOCK:
            _JOB["report"] = report
    except Exception as e:
        with _LOCK:
            _JOB["error"] = f"{e}\n{traceback.format_exc()}"
    finally:
        with _LOCK:
            _JOB["running"] = False
            _JOB["done"] = True


# --------------------------- 路由 --------------------------- #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/providers")
def providers():
    """返回可选厂商及其默认模型/端点, 供前端配置页使用。"""
    data = {}
    for name, preset in PROVIDER_PRESETS.items():
        data[name] = {
            "model": preset["model"],
            "base_url": preset["base_url"],
            "key_env": preset["key_env"],
        }
    # 知识库统计
    try:
        kb = KnowledgeBase.load(Config().knowledge_base)
        kb_stats = {"entries": len(kb.entries)}
    except Exception:
        kb_stats = {"entries": 0}
    return jsonify({"providers": data, "kb": kb_stats})


@app.route("/api/scan", methods=["POST"])
def scan():
    with _LOCK:
        if _JOB["running"]:
            return jsonify({"ok": False, "error": "已有扫描在进行中"}), 409

    body = request.get_json(force=True, silent=True) or {}
    target = (body.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "请填写扫描目标路径"}), 400
    if not Path(target).exists():
        return jsonify({"ok": False, "error": f"目标不存在: {target}"}), 400

    # 组装 Config
    cfg = Config()
    cfg.provider = body.get("provider", "glm")
    cfg.api_key = (body.get("api_key") or "").strip()
    cfg.model = (body.get("model") or "").strip()
    if body.get("base_url"):
        cfg.base_url = body["base_url"].strip()
    try:
        cfg.temperature = float(body.get("temperature", 0.1))
    except (TypeError, ValueError):
        cfg.temperature = 0.1
    cfg.mock_llm = bool(body.get("mock", False))
    # CodeQL
    cfg.use_codeql = bool(body.get("use_codeql", False))
    if body.get("codeql_build_command"):
        cfg.codeql_build_command = body["codeql_build_command"].strip()
    if body.get("codeql_lang"):
        cfg.codeql_languages = [s.strip().lower() for s in body["codeql_lang"].split(",") if s.strip()]
    cfg.codeql_strict = bool(body.get("codeql_strict", False))
    # 符号执行
    cfg.use_symbolic = bool(body.get("use_symbolic", False))
    cfg.use_sandbox = bool(body.get("use_sandbox", False))
    cfg.resolve()

    # 重置任务状态并启动后台线程
    with _LOCK:
        _JOB.update(running=True, logs=[], report=None, error=None, done=False)
    threading.Thread(target=_run_job, args=(target, cfg), daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/status")
def status():
    with _LOCK:
        return jsonify({
            "running": _JOB["running"],
            "done": _JOB["done"],
            "logs": _JOB["logs"],
            "report": _JOB["report"],
            "error": _JOB["error"],
        })


def main():
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"SupplyGuard-LLM Web UI  ->  http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
