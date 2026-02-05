from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass
class DedupeCache:
    max_size: int
    hashes: deque[str]
    hash_set: set[str]

    @classmethod
    def empty(cls, max_size: int) -> "DedupeCache":
        return cls(max_size=max_size, hashes=deque(), hash_set=set())

    def add(self, value: str) -> None:
        if value in self.hash_set:
            return
        self.hashes.append(value)
        self.hash_set.add(value)
        while len(self.hashes) > self.max_size:
            removed = self.hashes.popleft()
            self.hash_set.discard(removed)

    def __contains__(self, value: str) -> bool:
        return value in self.hash_set

    def to_list(self) -> list[str]:
        return list(self.hashes)


def load_dedupe_cache(
    path: str | Path,
    *,
    max_size: int = 10_000,
    warn: Callable[[str], None] | None = None,
) -> DedupeCache:
    path = Path(path)
    if not path.exists():
        return DedupeCache.empty(max_size)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        if warn:
            warn(f"Failed to read dedupe cache {path}: {exc}. Proceeding without cache.")
        return DedupeCache.empty(max_size)
    items = data.get("recent_hashes")
    if not isinstance(items, list):
        if warn:
            warn(f"Dedupe cache {path} malformed. Proceeding without cache.")
        return DedupeCache.empty(max_size)
    cache = DedupeCache.empty(max_size)
    for item in items:
        if isinstance(item, str):
            cache.add(item)
    return cache


def save_dedupe_cache(path: str | Path, cache: DedupeCache) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        json.dumps({"recent_hashes": cache.to_list()}), encoding="utf-8"
    )
    tmp_path.replace(path)
