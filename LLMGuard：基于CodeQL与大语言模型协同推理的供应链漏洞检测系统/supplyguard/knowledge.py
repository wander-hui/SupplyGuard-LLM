"""模块二：供应链危险组件知识库的加载与查询。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .models import KnowledgeEntry


class KnowledgeBase:
    def __init__(self, entries: list[KnowledgeEntry]):
        self.entries = entries
        # 建立 (语言, api) -> entry 的快速索引
        self._api_index: dict[tuple[str, str], KnowledgeEntry] = {}
        self._lib_index: dict[tuple[str, str], KnowledgeEntry] = {}
        for e in entries:
            for lang in e.languages:
                self._lib_index[(lang, e.library.lower())] = e
                for api in e.danger_api:
                    # 同时索引完整名与最后一段 (parseObject / JSON.parseObject)
                    self._api_index[(lang, api.lower())] = e
                    short = api.split(".")[-1].lower()
                    self._api_index.setdefault((lang, short), e)
                    # 复合索引 library.api (如 pickle.loads), 用于消歧 (loads 同属 pickle/marshal)
                    self._api_index[(lang, f"{e.library.lower()}.{short}")] = e

    @classmethod
    def load(cls, path: Path) -> "KnowledgeBase":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = [KnowledgeEntry(**item) for item in data]
        return cls(entries)

    def match_api(self, language: str, api: str) -> Optional[KnowledgeEntry]:
        """根据 sink API 名匹配知识库条目。"""
        if not api:
            return None
        key = (language, api.lower())
        if key in self._api_index:
            return self._api_index[key]
        short = api.split(".")[-1].lower()
        return self._api_index.get((language, short))

    def match_library(self, language: str, library: str) -> Optional[KnowledgeEntry]:
        return self._lib_index.get((language, library.lower()))

    def all_apis(self, language: str) -> list[str]:
        return sorted({api for (lang, api) in self._api_index if lang == language})

    def sink_apis(self, language: str, min_len: int = 4) -> list[str]:
        """供基于正则的分析器使用的 sink 名单。

        排除 dangerous-version 类别 (这类靠版本检查, 其方法名往往很泛, 如 log/info),
        并过滤过短/过泛的名称以降低误报。
        """
        generic = {"load", "parse", "log", "info", "warn", "error", "read", "get",
                   "post", "start", "call", "run"}
        out: set[str] = set()
        for e in self.entries:
            if language not in e.languages or e.category == "dangerous-version":
                continue
            for api in e.danger_api:
                short = api.split(".")[-1]
                if len(short) >= min_len and short.lower() not in generic:
                    out.add(short)
                if "." in api:
                    out.add(api)   # 保留带限定的全名, 如 Runtime.exec
        return sorted(out)

    def is_bad_version(self, language: str, library: str, version: str) -> Optional[KnowledgeEntry]:
        """判断某依赖的版本是否在已知危险版本列表中。"""
        e = self.match_library(language, library)
        if e and version and version in e.bad_versions:
            return e
        return None
