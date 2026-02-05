import json
from typing import Iterable, Iterator

from app.plugins.sysmon.parse import iter_sysmon_events, iter_sysmon_events_from_events
from app.plugins.sysmon.map_to_ocsf import (
    map_sysmon_eventid1_to_ocsf,
    map_sysmon_eventid3_to_ocsf,
    map_sysmon_eventid5_to_ocsf,
    map_sysmon_eventid7_to_ocsf,
    map_sysmon_eventid8_to_ocsf,
    map_sysmon_eventid10_to_ocsf,
    map_sysmon_eventid12_to_ocsf,
    map_sysmon_eventid13_to_ocsf,
    map_sysmon_eventid14_to_ocsf,
    map_sysmon_eventid11_to_ocsf,
    map_sysmon_eventid15_to_ocsf,
    map_sysmon_eventid22_to_ocsf,
)

EVENT_MAPPERS = {
    1: map_sysmon_eventid1_to_ocsf,
    3: map_sysmon_eventid3_to_ocsf,
    5: map_sysmon_eventid5_to_ocsf,
    7: map_sysmon_eventid7_to_ocsf,
    8: map_sysmon_eventid8_to_ocsf,
    10: map_sysmon_eventid10_to_ocsf,
    11: map_sysmon_eventid11_to_ocsf,
    15: map_sysmon_eventid15_to_ocsf,
    12: map_sysmon_eventid12_to_ocsf,
    13: map_sysmon_eventid13_to_ocsf,
    14: map_sysmon_eventid14_to_ocsf,
    22: map_sysmon_eventid22_to_ocsf,
}

def convert_sysmon_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    """
    Yields JSONL lines (strings) for mapped events.
    """
    for ev in iter_sysmon_events(file_path):
        mapper = EVENT_MAPPERS.get(ev.event_id)
        if not mapper:
            continue
        out = mapper(ev)
        if out is None:
            continue
        yield json.dumps(out, ensure_ascii=False)


def convert_sysmon_events_to_ocsf_jsonl(events: Iterable[dict]) -> Iterator[str]:
    for ev in iter_sysmon_events_from_events(events):
        mapper = EVENT_MAPPERS.get(ev.event_id)
        if not mapper:
            continue
        out = mapper(ev)
        if out is None:
            continue
        yield json.dumps(out, ensure_ascii=False)
