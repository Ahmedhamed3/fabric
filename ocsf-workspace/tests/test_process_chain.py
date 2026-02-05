from __future__ import annotations

from pathlib import Path

from app.correlation.process_chain import build_process_chains
from app.plugins.sysmon.map_to_ocsf import (
    map_sysmon_eventid1_to_ocsf,
    map_sysmon_eventid5_to_ocsf,
    map_sysmon_eventid7_to_ocsf,
)
from app.plugins.sysmon.parse import iter_sysmon_events


def _load_ocsf_events(sample_paths: list[Path]) -> list[dict]:
    mapper = {
        1: map_sysmon_eventid1_to_ocsf,
        5: map_sysmon_eventid5_to_ocsf,
        7: map_sysmon_eventid7_to_ocsf,
    }
    events: list[dict] = []
    for path in sample_paths:
        for ev in iter_sysmon_events(str(path)):
            mapped = mapper[ev.event_id](ev)
            assert mapped is not None
            events.append(mapped)
    return events


def test_build_process_chains_groups_by_uid_and_orders_by_time():
    sample_dir = Path(__file__).resolve().parents[1] / "samples"
    events = _load_ocsf_events(
        [
            sample_dir / "sysmon_eventid5.json",
            sample_dir / "sysmon_eventid1.json",
            sample_dir / "sysmon_eventid7.json",
        ]
    )

    chains = build_process_chains(events)

    assert len(chains) == 2

    app_chain = next(
        chain
        for chain in chains
        if chain.process_uid == "{A1B2C3D4-1111-2222-3333-444455556666}"
    )
    assert app_chain.parent_process_uid == "{ABCDEF12-3333-4444-5555-666677778888}"
    assert [event["time"] for event in app_chain.events] == sorted(
        [event["time"] for event in app_chain.events]
    )
    assert app_chain.events[0]["activity_id"] == 1
    assert app_chain.events[1]["activity_id"] == 2

    rundll_chain = next(
        chain
        for chain in chains
        if chain.process_uid == "{B1B2C3D4-1111-2222-3333-444455556666}"
    )
    assert len(rundll_chain.events) == 1
