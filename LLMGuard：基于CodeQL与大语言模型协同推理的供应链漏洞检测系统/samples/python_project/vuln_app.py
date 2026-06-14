"""SupplyGuard-LLM 演示用 Python 漏洞样本 —— 带完整数据流 (source -> 函数 -> sink)。

双引擎友好设计:
  - CodeQL: __main__ 里用 input()/sys.argv/stdin 作为 source, 经函数参数流向 sink,
    形成可被污点追踪的完整数据流;
  - CrossHair: 每个危险操作封装为「带参数的函数」, 参数即符号量, 验证从参数到 sink
    的可达性 (含一个被永假条件挡住的不可达样本, 演示判误报)。
"""
import os
import pickle
import subprocess
import sys

import yaml


# ---------------- 真实漏洞: 外部输入经参数可达 sink ---------------- #
def deserialize(payload: bytes):
    """CWE-502: 反序列化外部字节。"""
    return pickle.loads(payload)                 # sink: pickle.loads


def load_config(text: str):
    """CWE-502: yaml.load 未用 SafeLoader。"""
    return yaml.load(text, Loader=yaml.Loader)   # sink: yaml.load


def run_ping(host: str):
    """CWE-78: 拼接外部输入到 os.system。"""
    if len(host) > 0:                            # 可满足的分支: 符号执行应判可达
        os.system("ping -c 1 " + host)           # sink: os.system


def run_proc(user: str):
    """CWE-78: subprocess + shell=True。"""
    subprocess.Popen("id " + user, shell=True)   # sink: subprocess.Popen


# ---------------- 不可达样本: 永假条件挡住, 符号执行应判误报 ---------------- #
def guarded_eval(expr: str):
    """看似危险, 但条件 len>3 且 len<2 永不成立, eval 实际不可达。"""
    if len(expr) > 3 and len(expr) < 2:          # 永假: 路径不可达
        return eval(expr)                        # sink: eval (到不了)
    return None


# ---------------- 反例: 安全用法, 不应判高危 ---------------- #
def safe_load(text: str):
    return yaml.safe_load(text)


def main():
    # 每个外部输入 source 经函数参数流向危险 sink, 供 CodeQL 追踪完整数据流。
    raw = sys.stdin.buffer.read()                # source: stdin
    deserialize(raw)                             # stdin -> pickle.loads

    cfg_text = input("config: ")                 # source: input()
    load_config(cfg_text)                        # input -> yaml.load

    if len(sys.argv) > 1:
        host = sys.argv[1]                       # source: argv
        run_ping(host)                           # argv -> os.system
        run_proc(sys.argv[1])                    # argv -> subprocess.Popen
        guarded_eval(sys.argv[1])                # argv -> (eval, 不可达)


if __name__ == "__main__":
    main()
