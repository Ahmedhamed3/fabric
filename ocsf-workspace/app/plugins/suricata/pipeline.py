import json
from typing import Iterable, Iterator

from app.plugins.suricata.parse import iter_suricata_events, iter_suricata_events_from_events
from app.plugins.suricata.map_to_ocsf import map_suricata_alert_to_ocsf


def convert_suricata_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_suricata_events(file_path):
        out = map_suricata_alert_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)


def convert_suricata_events_to_ocsf_jsonl(events: Iterable[dict]) -> Iterator[str]:
    for ev in iter_suricata_events_from_events(events):
        out = map_suricata_alert_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)
