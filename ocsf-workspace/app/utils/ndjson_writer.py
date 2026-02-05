from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable


def append_ndjson(
    path: str | Path, records: Iterable[dict], *, fsync_every_n: int = 100
) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")
            count += 1
            if fsync_every_n > 0 and count % fsync_every_n == 0:
                handle.flush()
                os.fsync(handle.fileno())
        if count:
            handle.flush()
            os.fsync(handle.fileno())
    return count
