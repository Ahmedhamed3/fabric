from pathlib import Path

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid11_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid11_maps_to_file_create():
    path = Path("samples/sysmon_eventid11.json")

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid11_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 1001
    assert out["activity_id"] == 1
    assert out["type_uid"] == 100101
    assert out["time"] == "2024-03-04T05:06:07.890000Z"
    assert out["file"]["path"] == "C:\\Temp\\created.txt"
    assert out["actor"]["process"]["executable"] == "C:\\Windows\\System32\\notepad.exe"
    assert out["actor"]["process"]["pid"] == 5480
