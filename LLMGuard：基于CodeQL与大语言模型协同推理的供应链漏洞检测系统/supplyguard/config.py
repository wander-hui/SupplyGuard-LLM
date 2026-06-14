"""全局配置：LLM 提供商 (GLM / DeepSeek)、CodeQL 路径等。

优先级：命令行参数 > 环境变量 > 默认值。
所有路径均使用 pathlib，跨平台 (Windows 开发 / Ubuntu 运行)。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# 各提供商的 OpenAI 兼容端点与默认模型
PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-4-flash",          # 免费/便宜, 演示足够; 可换 glm-4-plus
        "key_env": "GLM_API_KEY",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "key_env": "DEEPSEEK_API_KEY",
    },
}


@dataclass
class Config:
    # ---- LLM ----
    provider: str = "glm"                 # glm | deepseek
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    temperature: float = 0.1
    max_tokens: int = 1024
    request_timeout: int = 60
    mock_llm: bool = False                # 离线模式: 用规则模拟 LLM, 无需联网/密钥

    # ---- CodeQL ----
    use_codeql: bool = False              # 默认关闭, 用内置轻量分析器
    codeql_cli: str = "codeql"            # CodeQL CLI 可执行文件路径
    codeql_strict: bool = True            # True: 建库/查询失败直接报错; False: 该语言回退内置分析器
    codeql_build_command: str = ""        # Java/C++ 编译命令, 如 "mvn compile" / "make"; 空则用 autobuild
    codeql_languages: list[str] = field(default_factory=list)  # 限定只跑哪些语言, 空=自动探测全部

    # ---- 动态符号执行 ----
    use_symbolic: bool = False            # 默认关闭; 开启后对 C/C++(angr)、Python(crosshair) 做可达性验证
    symbolic_languages: list[str] = field(default_factory=lambda: ["cpp", "python"])
    symbolic_timeout: int = 120           # 单条数据流的符号执行超时(秒)
    symbolic_max_findings: int = 20       # 最多对多少条数据流做符号执行(控制开销)
    # 沙箱
    use_sandbox: bool = True              # 是否在沙箱中实际运行 PoC 验证
    sandbox: str = "docker"               # docker / none
    sandbox_image: str = "supplyguard-sandbox:latest"
    sandbox_timeout: int = 30             # 沙箱内单次运行超时(秒)
    cpp_compiler: str = "g++"             # 重新编译被测 C/C++ 以供 angr/沙箱使用
    # Python 符号执行专用 venv (持久, 复用已装依赖; 避免污染主环境)
    crosshair_venv: Path = field(
        default_factory=lambda: Path(__file__).parent.parent / ".sym_venv")
    crosshair_auto_deps: bool = True      # 自动把目标工程 requirements.txt 装进该 venv

    # ---- 其它 ----
    knowledge_base: Path = field(default_factory=lambda: Path(__file__).parent / "data" / "knowledge_base.json")
    max_findings: int = 200

    def resolve(self) -> "Config":
        """根据 provider 预设补全 base_url/model/api_key (若未显式给出)。"""
        preset = PROVIDER_PRESETS.get(self.provider, PROVIDER_PRESETS["glm"])
        if not self.base_url:
            self.base_url = os.environ.get("SUPPLYGUARD_BASE_URL", preset["base_url"])
        if not self.model:
            self.model = os.environ.get("SUPPLYGUARD_MODEL", preset["model"])
        if not self.api_key:
            self.api_key = os.environ.get(preset["key_env"], "") or os.environ.get("SUPPLYGUARD_API_KEY", "")
        return self

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls(
            provider=os.environ.get("SUPPLYGUARD_PROVIDER", "glm"),
            mock_llm=os.environ.get("SUPPLYGUARD_MOCK", "").lower() in ("1", "true", "yes"),
            use_codeql=os.environ.get("SUPPLYGUARD_USE_CODEQL", "").lower() in ("1", "true", "yes"),
            codeql_cli=os.environ.get("CODEQL_CLI", "codeql"),
        )
        return cfg.resolve()
