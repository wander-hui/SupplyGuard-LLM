# SupplyGuard-LLM

> 基于程序分析与大语言模型协同推理的跨语言供应链漏洞检测系统
> Cross-language supply-chain vulnerability detection via program analysis + LLM reasoning

支持 **Java / Python / C·C++**，检测第三方库危险调用、已知漏洞组件、风险传播路径与 API 误用。

---

## 〇、项目是做什么的

现代软件大量依赖第三方库，**供应链漏洞**（用了带漏洞的组件、危险 API 被外部输入触达）
是重灾区。市面常见做法要么是「让 GPT 读代码找漏洞」（易漏报/幻觉），要么是「CodeQL 报路径」
（误报多、不懂语义）。

**SupplyGuard-LLM 把三种能力拼成一条流水线，互相补短板：**

| 能力 | 工具 | 解决什么 | 单独用的缺点 |
|------|------|----------|-------------|
| 静态数据流 | **CodeQL** + 内置分析器 | 找出「外部输入 → 危险 API」的路径 | 路径可能运行时走不通（误报） |
| 知识库 | 25 条危险组件库 | 标注哪些库/API/版本危险、对应 CWE | 不懂具体代码上下文 |
| 动态符号执行 | **angr** (C/C++) / **CrossHair** (Python) | 验证路径**真能走通**并生成可复现 **PoC**；走不通就判误报 | 路径爆炸、配置繁琐 |
| 大模型 | **GLM / DeepSeek** | 生成符号执行入口、结合 PoC 证据做语义研判与置信度 | 易幻觉、无铁证 |

一句话：**CodeQL 找路径 → 知识库标危险 → 符号执行验可达并出 PoC → LLM 带证据下结论**，
形成「静态发现 — 动态验证 — 智能研判」闭环，**显著降低误报**且产出可复现 PoC。

## 一、已完成的功能

- ✅ **跨语言依赖分析**：解析 pom.xml / requirements.txt / CMakeLists / vcpkg.json / conanfile
- ✅ **供应链危险组件知识库**：25 条（反序列化 / 命令执行 / 动态执行 / 内存安全 / 危险版本），覆盖 Java·Python·C++
- ✅ **双后端数据流提取**：
  - CodeQL 后端（三语言自定义 taint 查询，建库→分析→解析 SARIF）
  - 内置轻量分析器（Python `ast` 污点跟踪 + Java/C++ 正则），零依赖、始终可用、CodeQL 缺失时兜底
- ✅ **风险传播链切片**：长调用链压缩为关键节点，降低 LLM token
- ✅ **动态符号执行验证**：
  - C/C++ → **angr**：编译二进制、符号化 stdin/argv/env、定向探索 sink、求解 PoC
  - Python → **CrossHair**：函数参数符号化、独立持久 venv、契约求解
  - 结果分 `reachable`(出 PoC) / `unreachable`(判误报) / `unknown`(退回静态)
- ✅ **Docker 沙箱实证**：实际运行 PoC 确认 sink 真被触达（C/C++ 用 ASAN/strace，Python 用审计钩子+sink patch，命中即拦截不造成破坏）
- ✅ **LLM 协同研判**：GLM / DeepSeek 统一客户端，LLM 生成符号执行入口（前）、引导剪枝（中）、带 PoC 证据研判（后）；无密钥时 mock 规则兜底
- ✅ **依赖版本检查**：直接命中已知危险版本（如 fastjson 1.2.24、log4j 2.14.1）
- ✅ **统一报告**：JSON + Markdown，含严重程度、符号执行可达性、PoC、研判理由
- ✅ **Web 图形界面**：Flask，配置厂商/密钥/模型、实时日志、卡片式报告
- ✅ **对比实验脚本**：CodeQL / LLM-Only / CodeQL+LLM / 完整系统 四方法对比

> 现状：C/C++ 与 Python 的「CodeQL→符号执行→沙箱→LLM」完整闭环已在 Ubuntu 实测跑通；
> Java 走「CodeQL + LLM」链路（符号执行暂不覆盖 Java）。

## 二、核心思想

 **静态 + 动态 + LLM 三方协同**：

```
依赖分析 → 知识库 → CodeQL数据流 → 风险链切片 → 符号执行验证 → LLM语义研判 → 报告
 (谁在用)  (什么危险)  (从哪流到哪)   (压缩token)   (能否真走通+PoC)  (是否可利用)
```

### 2.1 LLM 到底参与了哪些环节、怎么参与的

很多同类作品只是「把代码丢给大模型让它找漏洞」。本项目刻意**不让 LLM 单打独斗**，而是
把它嵌进流水线的 **4 个具体位置**，每处都有明确输入/输出，且都带**规则兜底**（无密钥/
mock 时自动降级，保证流程可跑）。下面逐一说明（标注了对应代码位置）：

#### ① 生成符号执行入口 —— C/C++（融入符号执行【前】）
- **位置**：`supplyguard/symbolic/harness.py` → `generate_harness_spec()`
- **做什么**：符号执行最难的手工活是「告诉 angr 哪个变量是外部可控的符号量、从哪个函数
  开始跑、目标 sink 是谁」。这里把 CodeQL 切出的 source→sink 代码片段交给 LLM，让它产出一份
  **结构化 JSON 规格**（`entry` / `symbolic_inputs`(stdin/argv/env) / `sink_function` /
  `sink_argument_index` / `avoid_hints`）。
- **怎么参与**：LLM 读代码语义，判断「这个 sink 的污点参数是第几个、外部输入从哪进来」。
- **兜底**：无 LLM 时用启发式规则（按 sink 名猜输入来源）。

#### ② 精修符号执行参数 —— Python（融入符号执行【前】）
- **位置**：`supplyguard/symbolic/py_harness.py` → `refine_with_llm()`
- **做什么**：CrossHair 把「函数参数」当符号量，但参数的**精确类型**（str / bytes / int）
  影响能否求解。这里把目标函数签名 + sink 交给 LLM，让它推断每个参数最该用的具体类型。
- **怎么参与**：LLM 结合代码用法判断参数类型，提高 CrossHair 求解成功率。
- **兜底**：无 LLM 时用 ast 注解 / 默认 bytes。

#### ③ 引导路径探索（融入符号执行【中】）
- **位置**：harness 规格里的 `avoid_hints` + 风险链切片的关键节点
- **做什么**：符号执行会**路径爆炸**。LLM 在 ① 中产出的 `avoid_hints`（与漏洞无关的分支）
  和 CodeQL 切片的关键节点一起，作为 angr `explore(find=sink, avoid=...)` 的导航提示，
  让搜索定向冲向 sink，而非盲目展开。

#### ④ 带证据的语义研判（融入符号执行【后】，核心）
- **位置**：`supplyguard/llm/__init__.py` → `LLMClient.judge()` / `build_user_prompt()`
- **做什么**：这是 LLM 最关键的角色。它收到一个**结构化证据包**再下结论，而非「看代码猜」：
  ```jsonc
  {
    "language/file/source/sink/sink_api/library": "...",     // CodeQL 数据流
    "dependency_version": "1.2.24",                          // 依赖分析
    "key_path": [...],                                       // 风险链切片
    "knowledge_base_hint": { "category", "cwe", "description" }, // 知识库
    "symbolic_execution": {                                  // ★ 符号执行证据
      "status": "reachable | unreachable | unknown",
      "poc_input": "argv1=b'...'",                           // 可复现 PoC
      "sandbox_validated": true,                             // 沙箱实证
      "sandbox_evidence": "ASAN 检测到内存越界 ..."
    }
  }
  ```
  Prompt 里明确指示 LLM **如何采信符号执行证据**：
  - `reachable` + 沙箱实证 → 判可利用、高置信（≥0.9）
  - `unreachable` → 路径运行时走不通，**判为误报**、低置信
  - `unknown` → 无动态证据，仅凭静态上下文中等置信
- **输出**：结构化 `Verdict`（漏洞类型 / CWE / 是否可利用 / 置信度 / 严重程度 / 研判理由）。
- **兜底**：无密钥/mock 时用知识库规则判定（`_mock_judge`），并同样按符号执行结果调整
  置信度（`_adjust_with_symbolic`），保证离线也能演示完整效果。

#### LLM 参与点速查表

| # | 环节 | 代码位置 | 输入 | 输出 | 无 LLM 时兜底 |
|---|------|----------|------|------|--------------|
| ① | 生成 angr 入口 | `symbolic/harness.py` | source→sink 片段 | harness JSON 规格 | 启发式规则 |
| ② | 精修 Python 参数 | `symbolic/py_harness.py` | 函数签名 + sink | 参数类型 | ast 注解/默认 |
| ③ | 引导路径探索 | `symbolic/__init__.py` 调度 | avoid_hints + 切片 | 定向 explore | 仅用切片节点 |
| ④ | 语义研判 | `llm/__init__.py` | 全证据包(含PoC) | Verdict | 知识库规则 `_mock_judge` |

> 一句话：**LLM 不负责「找」漏洞（那是 CodeQL+符号执行的事），而负责「配置符号执行」与
> 「基于可复现证据做判断」**——这正是区别于「GPT 审计代码」类方案的关键。

#### 厂商与调用方式
- 统一封装在 `supplyguard/llm/__init__.py`，GLM 与 DeepSeek 均走 OpenAI 兼容
  `/chat/completions` 协议，`--provider` 切换；详见 [七、LLM 配置](#七llm-配置)。

## 三、目录结构

```
LLMGuard.../
├── supplyguard/                  核心 Python 包
│   ├── models.py                 统一数据模型 (Dependency/DataFlow/SymbolicResult/Verdict/Finding)
│   ├── config.py                 配置 (GLM/DeepSeek、CodeQL、符号执行、沙箱、专用venv)
│   ├── knowledge.py              模块二: 知识库加载与 API/版本 匹配
│   ├── pipeline.py               主流程编排 (5 阶段)
│   ├── cli.py                    命令行入口 (scan / kb)
│   ├── dependency/__init__.py    模块一: 依赖分析 (pom/requirements/CMake/vcpkg/conan)
│   ├── analysis/                 模块三: 数据流提取
│   │   ├── __init__.py             后端选择 (CodeQL / 内置, 严格模式)
│   │   ├── builtin.py              内置分析器 (Python ast 污点 + Java/C++ 正则)
│   │   ├── codeql.py               CodeQL 后端 (建库/分析/解析 SARIF)
│   │   └── queries/                自定义 CodeQL 查询
│   │       ├── python/TaintToDangerApi.ql
│   │       ├── java/TaintToDangerApi.ql
│   │       └── cpp/TaintToDangerApi.ql
│   ├── slicing/__init__.py       模块四: 风险传播链切片/压缩
│   ├── symbolic/                 模块五: 动态符号执行验证
│   │   ├── __init__.py             verify_flow 调度 (按语言分派)
│   │   ├── harness.py              LLM 生成 angr 入口规格 (C/C++)
│   │   ├── py_harness.py           ast 定位 Python 目标函数 + LLM 精修
│   │   ├── angr_backend.py         C/C++ angr 符号执行 + 求 PoC
│   │   ├── crosshair_backend.py    Python CrossHair 符号执行 (独立持久 venv)
│   │   └── sandbox.py              Docker 沙箱实证 (ASAN/strace + Python 审计钩子)
│   ├── llm/__init__.py           模块六: LLM 推理 (GLM/DeepSeek + mock 兜底)
│   ├── report/__init__.py        模块七: JSON + Markdown 报告
│   └── data/knowledge_base.json  危险组件知识库 (25 条)
├── webapp/                       Web 界面 (Flask)
│   ├── app.py                    后端 (复用 run_scan, 后台线程 + 轮询 API)
│   ├── templates/index.html      单页三标签界面
│   └── static/                   style.css + app.js
├── docker/Dockerfile.sandbox     PoC 沙箱镜像 (g++/strace/python3)
├── samples/                      漏洞示例
│   ├── python/  java/  cpp/        零散代码片段 (内置分析器演示)
│   ├── java_project/               可编译 Maven 工程 (CodeQL 演示)
│   ├── cpp_project/                可编译 Makefile 工程 (CodeQL + angr 演示)
│   └── python_project/             带完整数据流 (CodeQL + CrossHair 演示)
├── experiment.py                 方法对比脚本 (方案第十一节)
├── requirements.txt              依赖说明 (核心零依赖; angr/crosshair/flask 可选)
├── .env.example                  环境变量样例
└── 方案.md / README.md
```

## 四、快速开始 (Ubuntu)

```bash
# 1. 进入虚拟环境
source venv/bin/activate

# 2. 安装库
pip install -r requirements.txt

# 3. 离线跑通 (用规则模拟 LLM, 不需要密钥/网络)
python -m supplyguard.cli scan ./samples --mock --out report

# 4. 用真实 LLM (二选一)
export GLM_API_KEY=你的智谱key            # 或
export DEEPSEEK_API_KEY=你的deepseek_key

python -m supplyguard.cli scan ./samples --provider glm       --out report
python -m supplyguard.cli scan ./samples --provider deepseek  --out report

# 5. 启用 CodeQL 后端 (在 Ubuntu 安装 codeql)
python -m supplyguard.cli scan ./samples --use-codeql --provider glm --out report
#    若 codeql 不在 PATH:  --codeql-cli /opt/codeql/codeql
```

产物：`report.json`（结构化）与 `report.md`（可读报告）。

## 五、Web 界面 (演示用)

图形化界面：配置 LLM 厂商/密钥/模型、开关 CodeQL 与符号执行、实时查看扫描日志、
卡片式浏览漏洞报告（含符号执行徽章与 PoC）。

```bash
pip install flask
python -m webapp.app                          # 默认监听 0.0.0.0:5000 (任意 IP 可访问)
PORT=8080 python -m webapp.app                # 自定义端口
HOST=127.0.0.1 python -m webapp.app           # 只允许本机访问
```

- 默认 `HOST=0.0.0.0`，**局域网/其他机器**可用 `http://<本机IP>:5000` 访问（答辩演示方便）。
- 查本机 IP：`hostname -I` 或 `ip addr`。
- 若访问不通，检查防火墙：`sudo ufw allow 5000`。
- ⚠️ 监听 0.0.0.0 会把界面暴露到网络；API Key 仅存在浏览器本地、不写服务器磁盘，但仍建议只在可信网络内使用。

三个标签页：
- **⚙️ 配置** — 厂商下拉（GLM / DeepSeek）、API Key、模型、温度、自定义端点；CodeQL / 符号执行 / 沙箱开关（配置存浏览器本地，自动回填）
- **🔍 扫描** — 填目标路径，实时滚动显示 5 阶段进度日志
- **📊 报告** — 统计概览、依赖清单、可展开的漏洞卡片（严重程度 / 符号执行可达性 / 🧪沙箱实证 / PoC / 研判理由）

## 六、命令行参数

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

## 七、LLM 配置

GLM 与 DeepSeek 均兼容 OpenAI Chat Completions 协议，本项目用同一客户端封装：

| 提供商   | 默认端点                                       | 默认模型        | 密钥环境变量        |
|----------|------------------------------------------------|-----------------|---------------------|
| glm      | https://open.bigmodel.cn/api/paas/v4           | glm-4-flash     | `GLM_API_KEY`       |
| deepseek | https://api.deepseek.com/v1                    | deepseek-chat   | `DEEPSEEK_API_KEY`  |

参考 `.env.example`。没有密钥时系统自动进入 `--mock` 等价的规则判定，保证流程可演示。

## 八、CodeQL 后端 (三语言)

CodeQL 是本系统的核心程序分析引擎，负责提取 `source → sink` 数据流路径。

### 8.1 首次使用：安装查询依赖包 (每个语言一次)

```bash
codeql pack install supplyguard/analysis/queries/python
codeql pack install supplyguard/analysis/queries/java
codeql pack install supplyguard/analysis/queries/cpp
```

### 8.2 各语言建库要求

| 语言   | 是否需要编译 | 建库方式 |
|--------|--------------|----------|
| Python | 否           | 直接建库，开箱即用 |
| Java   | **是**       | 需 `mvn compile` 等能成功编译，用 `--codeql-build-command` 指定 |
| C/C++  | **是**       | 需 `make` / `g++` 能成功编译，用 `--codeql-build-command` 指定 |

> Java/C++ 是编译型语言，CodeQL 必须**观察真实编译过程**才能建库。零散代码片段
> （如旧的 `samples/java`、`samples/cpp`）无法建库——请使用可编译工程
> `samples/java_project`（Maven）与 `samples/cpp_project`（Makefile），或真实工程
> （Java: OWASP Benchmark / C·C++: NIST Juliet）。

### 8.3 三语言运行示例

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

### 8.4 CodeQL 相关选项

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

## 九、动态符号执行验证 (C/C++ + Python, 可选增强)

对 CodeQL 报出的 source→sink 路径做**运行时可达性验证**，并生成可复现 PoC，显著降低误报；
**LLM 深度融入符号执行的前/中/后三个环节**。两种引擎：

| 语言 | 引擎 | 对象 | 符号量 |
|------|------|------|--------|
| C/C++ | **angr** | 编译后的二进制 | stdin/argv/env |
| Python | **CrossHair** | 源码函数 | 函数参数 |
| Java | 暂不做 (走原 CodeQL+LLM) | — | — |

### 9.1 安装

```bash
pip install angr z3-solver crosshair-tool   # 体积较大(数百 MB), 耐心等
# 沙箱验证 (可选): 需要 Docker, 并构建沙箱镜像 (含 g++/strace/python3)
docker build -t supplyguard-sandbox:latest -f docker/Dockerfile.sandbox .
```

### 9.2 运行

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

### 9.3 LLM 如何融入符号执行 (创新核心)

| 环节 | LLM 的作用 |
|------|-----------|
| **前** | 读 CodeQL 切片，生成 angr harness 规格（哪个变量是符号量 / 入口 / 目标 sink） |
| **中** | 提供路径剪枝提示，引导 angr 定向探索 sink，缓解路径爆炸 |
| **后** | 拿到 PoC / 可达性证据后做研判：可达+沙箱验证→高置信；不可达→判误报 |

### 9.4 符号执行结果含义

| status | 含义 | 对判定的影响 |
|--------|------|-------------|
| `reachable` | 求得到达 sink 的具体输入(SAT) | exploitable=true, 置信度↑ (沙箱验证后 ≥0.97) |
| `unreachable` | 路径约束不可满足(UNSAT) | **判为误报**, 置信度↓ |
| `unknown` | 超时 / 路径爆炸 / 未装 angr | 退回静态判断 |
| `not-applicable` | 该语言不做符号执行 (如 Java) | 走原 CodeQL+LLM 链路 |

### 9.5 符号执行相关选项

```
--use-symbolic           启用动态符号执行验证 (C/C++ angr)
--no-sandbox             不在 Docker 沙箱实际运行 PoC
--symbolic-timeout SEC   单条数据流符号执行超时(秒), 默认 120
```

> **边界说明**：符号执行有路径爆炸问题，只在切片后的小范围上跑、加超时与步数上限；
> Java 暂不做符号执行(走原链路)；`unknown` 时自动退回纯静态判断，不影响出报告。

## 十、对比实验 (方案第十一节)

```bash
python experiment.py ./samples --mock
```

输出 CodeQL / LLM-Only / CodeQL+LLM / **CodeQL+LLM+SupplyGuard** 四种方法的告警数对比，
直观体现「依赖版本检查 + 知识库」带来的增量。接入带标注的数据集
（Java: OWASP Benchmark / C·C++: NIST Juliet / Python: 自构造）后可计算 Recall / Precision。

## 十一、创新点

1. **供应链风险传播图**：把 `用户输入 → 第三方库危险API → 危险行为` 显式建模。
2. **跨语言统一风险模型**：三种语言统一抽象为 `Source → Propagation → Third-party Lib → Sink`。
3. **静态+动态+LLM 三方协同**：CodeQL 找路径、符号执行验可达并出 PoC、LLM 做语义研判。
4. **LLM 融入符号执行内部**：LLM 生成符号执行入口、引导剪枝、并基于 PoC 证据研判，
   而非把 LLM 当独立审计员。
5. **风险链切片**：长调用链压缩为关键节点，大幅降低 LLM token 并提升准确率。
