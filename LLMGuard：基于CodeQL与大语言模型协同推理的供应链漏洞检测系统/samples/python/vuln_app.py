"""Python 供应链漏洞示例样本 (用于 SupplyGuard-LLM 演示)。"""
import os
import sys
import pickle
import subprocess

import yaml


def unsafe_deserialize():
    # CWE-502: 外部输入直接进入 pickle.loads
    data = sys.stdin.buffer.read()
    obj = pickle.loads(data)          # sink: pickle.loads
    return obj


def unsafe_yaml(path):
    with open(path) as f:
        content = f.read()
    return yaml.load(content)         # sink: yaml.load (未用 SafeLoader)


def command_injection():
    cmd = input("enter host: ")
    os.system("ping " + cmd)          # CWE-78: os.system 拼接外部输入


def dynamic_exec():
    expr = sys.argv[1]
    return eval(expr)                 # CWE-94: eval 外部输入


def proc_run(user):
    subprocess.Popen("grep " + user, shell=True)   # subprocess + shell=True


def safe_example():
    # 反例: 字面量, 不应被判为高危
    return yaml.safe_load("a: 1")
