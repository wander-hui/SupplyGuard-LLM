/**
 * @name Supply-chain taint to dangerous third-party API (Java)
 * @description 追踪 HTTP/外部输入流入危险第三方库 API (Fastjson/SnakeYAML/反序列化/命令执行)。
 *              为 SupplyGuard-LLM 提供 source->sink 路径, 漏洞判定交给 LLM。
 * @kind path-problem
 * @problem.severity warning
 * @id supplyguard/java/taint-to-danger-api
 * @tags security supply-chain
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

/** 危险 sink: 第三方反序列化 / 命令执行 / 动态执行。 */
predicate isDangerSink(DataFlow::Node sink, string name) {
  exists(MethodCall ma, Method m |
    ma.getMethod() = m and
    sink.asExpr() = ma.getAnArgument()
  |
    // Fastjson
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSON") and
    m.hasName(["parseObject", "parse"]) and
    name = "fastjson." + m.getName()
    or
    // SnakeYAML
    m.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml", "Yaml") and
    m.hasName(["load", "loadAll"]) and
    name = "snakeyaml." + m.getName()
    or
    // jackson-databind
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.hasName("readValue") and
    name = "jackson.readValue"
    or
    // native deserialization
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.hasName("readObject") and
    name = "ObjectInputStream.readObject"
    or
    // command execution
    m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    m.hasName("exec") and
    name = "Runtime.exec"
    or
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.hasName(["command", "start"]) and
    name = "ProcessBuilder." + m.getName()
  )
}

/** 本地外部输入 source: main 的 args 参数, 以及 System.in 读取。 */
predicate isLocalSource(DataFlow::Node source) {
  // main(String[] args) 的参数
  exists(Method main, Parameter p |
    main.hasName("main") and
    main.isStatic() and
    p = main.getParameter(0) and
    source.asParameter() = p
  )
  or
  // BufferedReader.readLine() / InputStreamReader 等的返回值 (来自 System.in 链路)
  exists(MethodCall mc |
    mc.getMethod().hasName(["readLine", "read", "readAllBytes", "nextLine", "next"]) and
    source.asExpr() = mc
  )
}

module SupplyChainConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource or isLocalSource(source)
  }

  predicate isSink(DataFlow::Node sink) { isDangerSink(sink, _) }
}

module SupplyChainFlow = TaintTracking::Global<SupplyChainConfig>;

import SupplyChainFlow::PathGraph

from SupplyChainFlow::PathNode source, SupplyChainFlow::PathNode sink, string name
where SupplyChainFlow::flowPath(source, sink) and isDangerSink(sink.getNode(), name)
select sink.getNode(), source, sink,
  "Supply-chain taint flow: external input reaches dangerous API " + name + "."
