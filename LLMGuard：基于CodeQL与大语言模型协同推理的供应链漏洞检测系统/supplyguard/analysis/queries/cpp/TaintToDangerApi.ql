/**
 * @name Supply-chain taint to dangerous third-party API (C/C++)
 * @description 追踪外部输入流入危险 API (命令执行/内存破坏/动态加载)。
 *              为 SupplyGuard-LLM 提供 source->sink 路径, 漏洞判定交给 LLM。
 * @kind path-problem
 * @problem.severity warning
 * @id supplyguard/cpp/taint-to-danger-api
 * @tags security supply-chain
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow

/** 外部输入 source: scanf/gets/fgets/getenv/read/recv 的输出, 以及 argv。 */
predicate isLocalSource(DataFlow::Node source) {
  // 通过参数写入的函数: scanf("%s", buf) / gets(buf) / fgets(buf,...) / read(fd,buf,..)
  exists(FunctionCall fc, string fname |
    fc.getTarget().hasGlobalOrStdName(fname) and
    fname = ["scanf", "fscanf", "sscanf", "gets", "fgets", "read", "recv", "fread"]
  |
    source.asDefiningArgument() = fc.getAnArgument()
  )
  or
  // 返回污点的函数: getenv() / fgets() 返回值
  exists(FunctionCall fc |
    fc.getTarget().hasGlobalOrStdName(["getenv", "fgets", "gets"]) and
    source.asExpr() = fc
  )
  or
  // main 的 argv 参数
  exists(Parameter p, Function main |
    main.hasGlobalName("main") and
    p = main.getParameter(1) and
    source.asParameter() = p
  )
}

/** 危险 sink。name 写入告警信息, 供后续解析。 */
predicate isDangerSink(DataFlow::Node sink, string name) {
  exists(FunctionCall fc, string fname |
    fc.getTarget().hasGlobalOrStdName(fname)
  |
    // 命令执行
    fname = ["system", "popen", "execl", "execlp", "execv", "execvp"] and
    sink.asExpr() = fc.getArgument(0) and
    name = fname
    or
    // 动态加载
    fname = "dlopen" and
    sink.asExpr() = fc.getArgument(0) and
    name = "dlopen"
    or
    // 内存/字符串不安全操作 (取 source 参数)
    fname = ["strcpy", "strcat", "sprintf"] and
    sink.asExpr() = fc.getArgument(1) and
    name = fname
    or
    fname = "memcpy" and
    sink.asExpr() = fc.getArgument(1) and
    name = "memcpy"
  )
}

module SupplyChainConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isLocalSource(source) }

  predicate isSink(DataFlow::Node sink) { isDangerSink(sink, _) }
}

module SupplyChainFlow = TaintTracking::Global<SupplyChainConfig>;

import SupplyChainFlow::PathGraph

from SupplyChainFlow::PathNode source, SupplyChainFlow::PathNode sink, string name
where SupplyChainFlow::flowPath(source, sink) and isDangerSink(sink.getNode(), name)
select sink.getNode(), source, sink,
  "Supply-chain taint flow: external input reaches dangerous API " + name + "."
