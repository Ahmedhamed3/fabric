import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid5_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid5_maps_to_process_terminate(tmp_path):
    payload = [
        {
            "EventID": 5,
            "UtcTime": "2024-04-01 10:11:12.000",
            "Computer": "WORKSTATION-1",
            "User": "CONTOSO\\svc",
            "EventData": {
                "ProcessGuid": "{AAAA1111-2222-3333-4444-555555555555}",
                "ProcessId": "4321",
                "Image": "C:\\Windows\\System32\\notepad.exe",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid5.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid5_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 7
    assert out["activity_id"] == 2
    assert out["type_uid"] == 702
    assert out["actor"]["process"]["uid"] == "{AAAA1111-2222-3333-4444-555555555555}"
    assert out["device"]["hostname"] == "WORKSTATION-1"
    assert out["unmapped"]["original_event"]["EventID"] == 5
