import json
from typing import Iterable, Iterator

from app.plugins.proxy_http.map_to_ocsf import map_proxy_http_to_ocsf
from app.plugins.proxy_http.parse import iter_proxy_http_events, iter_proxy_http_events_from_events


def convert_proxy_http_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_proxy_http_events(file_path):
        out = map_proxy_http_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)


def convert_proxy_http_events_to_ocsf_jsonl(events: Iterable[dict]) -> Iterator[str]:
    for ev in iter_proxy_http_events_from_events(events):
        out = map_proxy_http_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)
