/**
 * @name Supply-chain taint to dangerous third-party API (Python)
 * @description 追踪外部输入流入危险第三方/内置 API (反序列化/命令执行/动态执行)。
 *              本查询为 SupplyGuard-LLM 提供 source->sink 路径, 真正的漏洞判定交给 LLM。
 * @kind path-problem
 * @problem.severity warning
 * @id supplyguard/py/taint-to-danger-api
 * @tags security supply-chain
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

/** 危险 sink: 反序列化 / 命令执行 / 动态执行。name 写入告警信息, 供后续解析。 */
predicate isDangerSink(DataFlow::Node sink, string name) {
  exists(API::CallNode c |
    c = API::moduleImport("pickle").getMember(["loads", "load"]).getACall() and
    sink = c.getArg(0) and
    name = "pickle.loads"
  )
  or
  exists(API::CallNode c |
    c = API::moduleImport(["cPickle", "_pickle"]).getMember(["loads", "load"]).getACall() and
    sink = c.getArg(0) and
    name = "pickle.loads"
  )
  or
  exists(API::CallNode c |
    c = API::moduleImport("marshal").getMember(["loads", "load"]).getACall() and
    sink = c.getArg(0) and
    name = "marshal.loads"
  )
  or
  exists(API::CallNode c |
    c = API::moduleImport("yaml").getMember(["load", "full_load", "unsafe_load"]).getACall() and
    sink = c.getArg(0) and
    name = "yaml.load"
  )
  or
  exists(API::CallNode c |
    c = API::moduleImport("os").getMember(["system", "popen"]).getACall() and
    sink = c.getArg(0) and
    name = "os.system"
  )
  or
  exists(API::CallNode c |
    c =
      API::moduleImport("subprocess")
          .getMember(["call", "run", "Popen", "check_output", "check_call"])
          .getACall() and
    sink = c.getArg(0) and
    name = "subprocess.Popen"
  )
  or
  exists(API::CallNode c |
    c = API::builtin(["eval", "exec"]).getACall() and
    sink = c.getArg(0) and
    name = "eval"
  )
}

/** 本地外部输入 source: input() / sys.argv / sys.stdin / os.environ 等。 */
predicate isLocalSource(DataFlow::Node source) {
  // input() / raw_input()
  source = API::builtin(["input", "raw_input"]).getACall()
  or
  // sys.argv (整个列表或其元素)
  source = API::moduleImport("sys").getMember("argv").getAValueReachableFromSource()
  or
  // sys.stdin.read() / sys.stdin.readline() / sys.stdin.buffer.read()
  exists(API::Node stdin |
    stdin = API::moduleImport("sys").getMember("stdin") and
    source =
      [stdin, stdin.getMember("buffer")].getMember(["read", "readline", "readlines"]).getACall()
  )
  or
  // os.environ / os.getenv()
  source = API::moduleImport("os").getMember("environ").getAValueReachableFromSource()
  or
  source = API::moduleImport("os").getMember("getenv").getACall()
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
