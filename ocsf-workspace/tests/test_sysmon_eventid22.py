import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid22_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid22_maps_to_dns_query(tmp_path):
    payload = [
        {
            "EventID": 22,
            "UtcTime": "2024-04-05 06:07:08.901",
            "EventData": {
                "ProcessId": "2468",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "QueryName": "example.com",
                "QueryResults": "93.184.216.34",
                "QueryStatus": "0",
            },
        }
    ]
    path = tmp_path / "sysmon.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid22_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 1006
    assert out["activity_id"] == 1
    assert out["type_uid"] == 100601
    assert out["dns"]["question"]["name"] == "example.com"
    assert out["actor"]["process"]["executable"] == "C:\\Windows\\System32\\svchost.exe"
