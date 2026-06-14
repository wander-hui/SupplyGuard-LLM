# SupplyGuard-LLM

> 基于程序分析与大语言模型协同推理的跨语言供应链漏洞检测系统
> Cross-language supply-chain vulnerability detection via program analysis + LLM reasoning

支持 **Java / Python / C·C++**，检测第三方库危险调用、已知漏洞组件、风险传播路径与 API 误用。

---

## 一、核心思想

不是「让 GPT 找漏洞」，也不是「让 CodeQL 报漏洞」，而是 **静态 + 动态 + LLM 三方协同**：

```
依赖分析 → 知识库 → CodeQL数据流 → 风险链切片 → 符号执行验证 → LLM语义研判 → 报告
 (谁在用)  (什么危险)  (从哪流到哪)   (压缩token)   (能否真走通+PoC)  (是否可利用)
```

- **CodeQL 负责找路径**（source → sink 的数据流，可能存在但运行时未必可达）；
- **知识库负责标危险**（25 个典型组件 / 危险 API / CWE / 危险版本）；
- **符号执行负责验证**（angr 求解路径是否真可达，并生成可复现 PoC；不可达→判误报）；
- **LLM 负责判漏洞**（生成符号执行入口、并结合 PoC 证据判断可利用性与置信度）。

## 二、目录结构

```
supplyguard/
  models.py            统一数据模型 (Dependency/DataFlow/SymbolicResult/Verdict/Finding)
  config.py            配置 (GLM/DeepSeek, CodeQL 开关, 符号执行/沙箱开关)
  knowledge.py         模块二: 供应链知识库加载与匹配
  dependency/          模块一: 依赖分析 (pom.xml/requirements.txt/CMake/vcpkg/conan)
  analysis/            模块三: 数据流提取
    builtin.py           内置轻量分析器 (Python ast + Java/C++ 正则), 零依赖, 始终可用
    codeql.py            CodeQL 后端 (建库 + 跑 ql + 解析 SARIF)
    queries/             自定义 CodeQL 查询 (python/java/cpp)
  slicing/             模块四: 风险传播链切片/压缩
  symbolic/            模块五(新): 动态符号执行验证
    harness.py           LLM 生成符号执行入口 (融入【前】)
    angr_backend.py      C/C++ angr 符号执行, 求解 PoC
    sandbox.py           Docker 沙箱实际运行 PoC 验证 sink 真触达
  llm/                 模块六: LLM 推理 (GLM/DeepSeek 统一客户端 + mock 兜底)
  report/              模块七: JSON + Markdown 报告生成
  pipeline.py          主流程编排
  cli.py               命令行入口
  data/knowledge_base.json   危险组件知识库
docker/Dockerfile.sandbox    PoC 沙箱镜像
webapp/                      Web 界面 (Flask): app.py + templates/ + static/
samples/               漏洞示例 (含可编译工程 java_project / cpp_project / python_project)
experiment.py          方案第十一节的方法对比脚本
```

## 三、快速开始 (Ubuntu)

```bash
# 1. 进入虚拟环境 (你已建好)
source venv/bin/activate

# 2. 无需安装任何第三方包 —— 核心仅用标准库
#    (requirements.txt 里的都是可选增强)

# 3. 离线跑通 (用规则模拟 LLM, 不需要密钥/网络)
python -m supplyguard.cli scan ./samples --mock --out report

# 4. 用真实 LLM (二选一)
export GLM_API_KEY=你的智谱key            # 或
export DEEPSEEK_API_KEY=你的deepseek_key

python -m supplyguard.cli scan ./samples --provider glm       --out report
python -m supplyguard.cli scan ./samples --provider deepseek  --out report

# 5. 启用 CodeQL 后端 (你已在 Ubuntu 安装 codeql)
python -m supplyguard.cli scan ./samples --use-codeql --provider glm --out report
#    若 codeql 不在 PATH:  --codeql-cli /opt/codeql/codeql
```

产物：`report.json`（结构化）与 `report.md`（可读报告）。

## 三·五、Web 界面 (推荐演示用)

提供一个图形化界面：配置 LLM 厂商/密钥/模型、开关 CodeQL 与符号执行、实时查看扫描
日志、卡片式浏览漏洞报告（含符号执行徽章与 PoC）。

```bash
pip install flask
python -m webapp.app                 # 打开 http://127.0.0.1:5000
PORT=8080 python -m webapp.app       # 自定义端口
```

三个标签页：
- **⚙️ 配置** — 厂商下拉（GLM / DeepSeek）、API Key、模型、温度；CodeQL / 符号执行 / 沙箱开关（配置存浏览器本地）
- **🔍 扫描** — 填目标路径，实时滚动显示 5 阶段进度日志
- **📊 报告** — 统计概览、依赖清单、可展开的漏洞卡片（严重程度 / 符号执行可达性 / 🧪沙箱实证 / PoC / 研判理由）



```
python -m supplyguard.cli scan <目标目录或文件> [选项]

  --provider {glm,deepseek}   选择 LLM 提供商 (默认 glm)
  --model NAME                覆盖默认模型 (glm-4-flash / deepseek-chat)
  --api-key KEY               直接传 key (默认读环境变量)
  --base-url URL              覆盖 API 端点
  --mock                      离线模式: 规则模拟 LLM
  --use-codeql                启用 CodeQL 后端 (失败自动回退内置分析器)
  --codeql-cli PATH           codeql 可执行文件路径
  --out PREFIX                输出前缀 (默认 report -> report.json / report.md)
  --quiet                     精简输出

python -m supplyguard.cli kb        # 查看知识库统计
```

## 五、LLM 配置

GLM 与 DeepSeek 均兼容 OpenAI Chat Completions 协议，本项目用同一客户端封装：

| 提供商   | 默认端点                                       | 默认模型        | 密钥环境变量        |
|----------|------------------------------------------------|-----------------|---------------------|
| glm      | https://open.bigmodel.cn/api/paas/v4           | glm-4-flash     | `GLM_API_KEY`       |
| deepseek | https://api.deepseek.com/v1                    | deepseek-chat   | `DEEPSEEK_API_KEY`  |

参考 `.env.example`。没有密钥时系统自动进入 `--mock` 等价的规则判定，保证流程可演示。

## 六、CodeQL 后端 (三语言)

CodeQL 是本系统的核心程序分析引擎，负责提取 `source → sink` 数据流路径。

### 6.1 首次使用：安装查询依赖包 (每个语言一次)

```bash
codeql pack install supplyguard/analysis/queries/python
codeql pack install supplyguard/analysis/queries/java
codeql pack install supplyguard/analysis/queries/cpp
```

### 6.2 各语言建库要求

| 语言   | 是否需要编译 | 建库方式 |
|--------|--------------|----------|
| Python | 否           | 直接建库，开箱即用 |
| Java   | **是**       | 需 `mvn compile` 等能成功编译，用 `--codeql-build-command` 指定 |
| C/C++  | **是**       | 需 `make` / `g++` 能成功编译，用 `--codeql-build-command` 指定 |

> Java/C++ 是编译型语言，CodeQL 必须**观察真实编译过程**才能建库。零散代码片段
> （如旧的 `samples/java`、`samples/cpp`）无法建库——请使用可编译工程
> `samples/java_project`（Maven）与 `samples/cpp_project`（Makefile），或真实工程
> （Java: OWASP Benchmark / C·C++: NIST Juliet）。

### 6.3 三语言运行示例

```bash
# Python (无需编译)
python -m supplyguard.cli scan ./samples/python --use-codeql \
  --codeql-lang python --provider glm --out report_py

# Java (Maven 工程, 需联网拉依赖)
python -m supplyguard.cli scan ./samples/java_project --use-codeql \
  --codeql-lang java --codeql-build-command "mvn -q compile" \
  --provider glm --out report_java

# C/C++ (Makefile 工程)
python -m supplyguard.cli scan ./samples/cpp_project --use-codeql \
  --codeql-lang cpp --codeql-build-command "make" \
  --provider glm --out report_cpp
```

### 6.4 CodeQL 相关选项

```
--use-codeql                 启用 CodeQL 后端
--codeql-cli PATH            codeql 可执行文件路径 (默认从 PATH 找)
--codeql-build-command CMD   Java/C++ 编译命令, 如 "mvn compile" / "make"
--codeql-lang LANGS          限定只跑哪些语言, 逗号分隔 (如 python,cpp)
--codeql-no-strict           某语言失败时回退内置分析器 (默认严格: 失败即报错并退出)
```

- **严格模式 (默认)**：任一语言建库/查询失败立即报错退出，便于定位编译问题。
- 自定义查询见 `supplyguard/analysis/queries/{python,java,cpp}/TaintToDangerApi.ql`，
  source 同时覆盖远程输入 (`RemoteFlowSource`) 与本地输入 (`input()`/`argv`/`stdin`/`getenv`/`scanf` 等)。

## 七、动态符号执行验证 (C/C++ + Python, 可选增强)

对 CodeQL 报出的 source→sink 路径做**运行时可达性验证**，并生成可复现 PoC，显著降低误报；
**LLM 深度融入符号执行的前/中/后三个环节**。两种引擎：

| 语言 | 引擎 | 对象 | 符号量 |
|------|------|------|--------|
| C/C++ | **angr** | 编译后的二进制 | stdin/argv/env |
| Python | **CrossHair** | 源码函数 | 函数参数 |
| Java | 暂不做 (走原 CodeQL+LLM) | — | — |

### 7.1 安装

```bash
pip install angr z3-solver crosshair-tool   # 体积较大(数百 MB), 耐心等
# 沙箱验证 (可选): 需要 Docker, 并构建沙箱镜像 (含 g++/strace/python3)
docker build -t supplyguard-sandbox:latest -f docker/Dockerfile.sandbox .
```

### 7.2 运行

```bash
# C/C++ 工程: CodeQL 找路径 + angr 符号执行 + Docker 沙箱(ASAN/strace)验证 PoC
python -m supplyguard.cli scan ./samples/cpp_project \
  --use-codeql --codeql-lang cpp --codeql-build-command "make -B" \
  --use-symbolic --provider glm --out report_cpp

# Python 工程: CodeQL 找路径 + CrossHair 符号执行 + Docker 沙箱(审计钩子)验证
python -m supplyguard.cli scan ./samples/python_project \
  --use-codeql --codeql-lang python \
  --use-symbolic --provider glm --out report_py

# 不想用 Docker 沙箱时加 --no-sandbox (仅用符号执行结论, 不实际运行 PoC)
python -m supplyguard.cli scan ./samples/python_project \
  --use-symbolic --no-sandbox --mock --out report_py
```

> **Python 沙箱原理**：用 `sys.addaudithook` 监听 `pickle.find_class` / `os.system` /
> `subprocess.Popen` / `exec` 等 CPython 审计事件，sink 真被调用时**当场拦截**（不让其
> 实际执行），既「实证触达」又不造成破坏。

### 7.3 LLM 如何融入符号执行 (创新核心)

| 环节 | LLM 的作用 |
|------|-----------|
| **前** | 读 CodeQL 切片，生成 angr harness 规格（哪个变量是符号量 / 入口 / 目标 sink） |
| **中** | 提供路径剪枝提示，引导 angr 定向探索 sink，缓解路径爆炸 |
| **后** | 拿到 PoC / 可达性证据后做研判：可达+沙箱验证→高置信；不可达→判误报 |

### 7.4 符号执行结果含义

| status | 含义 | 对判定的影响 |
|--------|------|-------------|
| `reachable` | 求得到达 sink 的具体输入(SAT) | exploitable=true, 置信度↑ (沙箱验证后 ≥0.97) |
| `unreachable` | 路径约束不可满足(UNSAT) | **判为误报**, 置信度↓ |
| `unknown` | 超时 / 路径爆炸 / 未装 angr | 退回静态判断 |
| `not-applicable` | 该语言不做符号执行 (如 Java) | 走原 CodeQL+LLM 链路 |

### 7.5 符号执行相关选项

```
--use-symbolic           启用动态符号执行验证 (C/C++ angr)
--no-sandbox             不在 Docker 沙箱实际运行 PoC
--symbolic-timeout SEC   单条数据流符号执行超时(秒), 默认 120
```

> **边界说明**：符号执行有路径爆炸问题，只在切片后的小范围上跑、加超时与步数上限；
> Java 暂不做符号执行(走原链路)；`unknown` 时自动退回纯静态判断，不影响出报告。

## 八、对比实验 (方案第十一节)

```bash
python experiment.py ./samples --mock
```

输出 CodeQL / LLM-Only / CodeQL+LLM / **CodeQL+LLM+SupplyGuard** 四种方法的告警数对比，
直观体现「依赖版本检查 + 知识库」带来的增量。接入带标注的数据集
（Java: OWASP Benchmark / C·C++: NIST Juliet / Python: 自构造）后可计算 Recall / Precision。

## 九、创新点

1. **供应链风险传播图**：把 `用户输入 → 第三方库危险API → 危险行为` 显式建模。
2. **跨语言统一风险模型**：三种语言统一抽象为 `Source → Propagation → Third-party Lib → Sink`。
3. **静态+动态+LLM 三方协同**：CodeQL 找路径、符号执行验可达并出 PoC、LLM 做语义研判。
4. **LLM 融入符号执行内部**：LLM 生成符号执行入口、引导剪枝、并基于 PoC 证据研判，
   而非把 LLM 当独立审计员。
5. **风险链切片**：长调用链压缩为关键节点，大幅降低 LLM token 并提升准确率。
