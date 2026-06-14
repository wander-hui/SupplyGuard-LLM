"""模块一：依赖分析。

解析 Java(pom.xml) / Python(requirements.txt) / C++(CMakeLists.txt, vcpkg.json,
conanfile.txt) 中声明的第三方依赖, 输出统一的 Dependency 列表。

不依赖第三方库, 使用标准库 (xml / re / json) 解析, 保证跨平台、零额外依赖。
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Dependency


# --------------------------------------------------------------------------- #
# Java: pom.xml
# --------------------------------------------------------------------------- #
def parse_pom(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return deps
    root = tree.getroot()
    # pom 通常带命名空间, 用通配兼容
    ns = ""
    m = re.match(r"\{(.*)\}", root.tag)
    if m:
        ns = m.group(1)

    def tag(name: str) -> str:
        return f"{{{ns}}}{name}" if ns else name

    # 收集 <properties> 以解析 ${...} 版本占位
    props: dict[str, str] = {}
    for prop_block in root.iter(tag("properties")):
        for child in prop_block:
            local = child.tag.split("}")[-1]
            props[local] = (child.text or "").strip()

    def resolve_version(v: str) -> str:
        v = (v or "").strip()
        m = re.fullmatch(r"\$\{(.+?)\}", v)
        if m:
            return props.get(m.group(1), v)
        return v

    for dep in root.iter(tag("dependency")):
        gid = dep.findtext(tag("groupId")) or ""
        aid = dep.findtext(tag("artifactId")) or ""
        ver = resolve_version(dep.findtext(tag("version")) or "")
        if not aid:
            continue
        deps.append(Dependency(
            library=aid.strip(),
            version=ver,
            language="java",
            source_file=str(path),
            raw=f"{gid.strip()}:{aid.strip()}:{ver}",
        ))
    return deps


# --------------------------------------------------------------------------- #
# Python: requirements.txt
# --------------------------------------------------------------------------- #
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([0-9][\w.\-*]*)?")


def parse_requirements(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#", 1)[0].strip()
        m = _REQ_RE.match(line)
        if not m:
            continue
        name, _op, ver = m.group(1), m.group(2), m.group(3) or ""
        deps.append(Dependency(
            library=name,
            version=ver,
            language="python",
            source_file=str(path),
            raw=line,
        ))
    return deps


# --------------------------------------------------------------------------- #
# C++: CMakeLists.txt / vcpkg.json / conanfile.txt
# --------------------------------------------------------------------------- #
def parse_vcpkg(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return deps
    for item in data.get("dependencies", []):
        if isinstance(item, str):
            deps.append(Dependency(library=item, language="cpp", source_file=str(path), raw=item))
        elif isinstance(item, dict) and item.get("name"):
            deps.append(Dependency(
                library=item["name"],
                version=str(item.get("version>=", item.get("version", ""))),
                language="cpp",
                source_file=str(path),
                raw=json.dumps(item, ensure_ascii=False),
            ))
    return deps


def parse_conanfile(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    in_requires = False
    for line in text.splitlines():
        s = line.strip()
        if s.lower().startswith("[requires]"):
            in_requires = True
            continue
        if s.startswith("[") and s.endswith("]"):
            in_requires = False
            continue
        # conanfile.txt: lib/version  ;  conanfile.py: self.requires("lib/version")
        m = re.search(r'["\']?([A-Za-z0-9_.\-]+)/([0-9][\w.\-]*)', s)
        if (in_requires or "requires" in s) and m:
            deps.append(Dependency(
                library=m.group(1), version=m.group(2),
                language="cpp", source_file=str(path), raw=s,
            ))
    return deps


def parse_cmake(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    text = path.read_text(encoding="utf-8", errors="ignore")
    # find_package(OpenSSL 1.1 REQUIRED) / find_package(yaml-cpp)
    for m in re.finditer(r"find_package\s*\(\s*([A-Za-z0-9_.\-]+)\s*([0-9][\w.\-]*)?", text, re.IGNORECASE):
        deps.append(Dependency(
            library=m.group(1), version=(m.group(2) or ""),
            language="cpp", source_file=str(path), raw=m.group(0),
        ))
    return deps


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
_MANIFEST_DISPATCH = {
    "pom.xml": parse_pom,
    "requirements.txt": parse_requirements,
    "vcpkg.json": parse_vcpkg,
    "conanfile.txt": parse_conanfile,
    "conanfile.py": parse_conanfile,
    "cmakelists.txt": parse_cmake,
}


def analyze_dependencies(root: Path) -> list[Dependency]:
    """递归扫描目录下所有已知清单文件, 汇总依赖。"""
    root = Path(root)
    found: list[Dependency] = []
    if root.is_file():
        candidates = [root]
    else:
        candidates = [p for p in root.rglob("*") if p.is_file()]
    for p in candidates:
        fn = p.name.lower()
        parser = _MANIFEST_DISPATCH.get(fn)
        if parser:
            try:
                found.extend(parser(p))
            except Exception:
                continue
    return found
