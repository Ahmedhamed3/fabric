import json
from typing import Iterable, Iterator

from app.plugins.windows_security.parse import (
    iter_windows_security_events,
    iter_windows_security_events_from_events,
)
from app.plugins.windows_security.map_to_ocsf import (
    map_windows_security_authentication_to_ocsf,
    map_windows_security_object_access_to_ocsf,
)


def convert_windows_security_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_windows_security_events(file_path):
        out = map_windows_security_authentication_to_ocsf(ev)
        if out is None:
            out = map_windows_security_object_access_to_ocsf(ev)
        if out is None:
            continue
        yield json.dumps(out, ensure_ascii=False)


def convert_windows_security_events_to_ocsf_jsonl(
    events: Iterable[dict],
) -> Iterator[str]:
    for ev in iter_windows_security_events_from_events(events):
        out = map_windows_security_authentication_to_ocsf(ev)
        if out is None:
            out = map_windows_security_object_access_to_ocsf(ev)
        if out is None:
            continue
        yield json.dumps(out, ensure_ascii=False)
