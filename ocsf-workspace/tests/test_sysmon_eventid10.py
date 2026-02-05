import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid10_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid10_maps_to_process_open(tmp_path):
    payload = [
        {
            "EventID": 10,
            "UtcTime": "2024-04-02 10:11:12.000",
            "Computer": "WORKSTATION-4",
            "User": "CONTOSO\\analyst",
            "EventData": {
                "SourceProcessGuid": "{EEEE1111-2222-3333-4444-555555555555}",
                "SourceProcessId": "9001",
                "SourceImage": "C:\\Windows\\System32\\wmiprvse.exe",
                "TargetProcessGuid": "{FFFF1111-2222-3333-4444-555555555555}",
                "TargetProcessId": "9002",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1410",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid10.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid10_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 7
    assert out["activity_id"] == 3
    assert out["type_uid"] == 703
    assert out["actor"]["process"]["uid"] == "{EEEE1111-2222-3333-4444-555555555555}"
    assert out["process"]["uid"] == "{FFFF1111-2222-3333-4444-555555555555}"
    assert out["unmapped"]["original_event"]["EventID"] == 10
