from __future__ import annotations

import json
from pathlib import Path

from app.utils.dedupe_cache import DedupeCache, load_dedupe_cache, save_dedupe_cache


def test_dedupe_cache_eviction() -> None:
    cache = DedupeCache.empty(3)
    cache.add("a")
    cache.add("b")
    cache.add("c")
    cache.add("d")
    assert "a" not in cache
    assert "b" in cache
    assert cache.to_list() == ["b", "c", "d"]


def test_dedupe_cache_persistence(tmp_path: Path) -> None:
    path = tmp_path / "dedupe.json"
    cache = DedupeCache.empty(10)
    cache.add("hash-1")
    cache.add("hash-2")
    save_dedupe_cache(path, cache)

    loaded = load_dedupe_cache(path, max_size=10)
    assert "hash-1" in loaded
    assert "hash-2" in loaded


def test_dedupe_cache_corrupt_fails_open(tmp_path: Path) -> None:
    path = tmp_path / "dedupe.json"
    path.write_text("{not-json")
    warnings: list[str] = []
    cache = load_dedupe_cache(path, warn=warnings.append)
    assert cache.to_list() == []
    assert warnings

    path.write_text(json.dumps({"recent_hashes": "nope"}))
    warnings.clear()
    cache = load_dedupe_cache(path, warn=warnings.append)
    assert cache.to_list() == []
    assert warnings
