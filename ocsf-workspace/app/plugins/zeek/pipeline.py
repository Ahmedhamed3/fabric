import json
from typing import Iterable, Iterator

from app.plugins.zeek.parse import iter_zeek_dns_events, iter_zeek_dns_events_from_events
from app.plugins.zeek.map_to_ocsf import map_zeek_dns_to_ocsf


def convert_zeek_dns_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_zeek_dns_events(file_path):
        out = map_zeek_dns_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)


def convert_zeek_dns_events_to_ocsf_jsonl(events: Iterable[dict]) -> Iterator[str]:
    for ev in iter_zeek_dns_events_from_events(events):
        out = map_zeek_dns_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)
