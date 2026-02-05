import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid8_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid8_maps_to_process_inject(tmp_path):
    payload = [
        {
            "EventID": 8,
            "UtcTime": "2024-04-02 08:09:10.000",
            "Computer": "WORKSTATION-3",
            "User": "CONTOSO\\attacker",
            "EventData": {
                "SourceProcessGuid": "{CCCC1111-2222-3333-4444-555555555555}",
                "SourceProcessId": "7777",
                "SourceImage": "C:\\Tools\\injector.exe",
                "TargetProcessGuid": "{DDDD1111-2222-3333-4444-555555555555}",
                "TargetProcessId": "8888",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "StartAddress": "0x00007FF6AABBCCDD",
                "StartModule": "C:\\Windows\\System32\\kernel32.dll",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid8.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid8_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 7
    assert out["activity_id"] == 4
    assert out["type_uid"] == 704
    assert out["actor"]["process"]["uid"] == "{CCCC1111-2222-3333-4444-555555555555}"
    assert out["process"]["uid"] == "{DDDD1111-2222-3333-4444-555555555555}"
    assert out["unmapped"]["original_event"]["EventID"] == 8
