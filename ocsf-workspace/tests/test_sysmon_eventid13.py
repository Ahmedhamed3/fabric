import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid13_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid13_maps_to_registry_value_set(tmp_path):
    payload = [
        {
            "EventID": 13,
            "UtcTime": "2024-04-03 11:12:13.500",
            "Computer": "WORKSTATION-6",
            "User": "CONTOSO\\admin",
            "EventData": {
                "ProcessGuid": "{22222222-AAAA-BBBB-CCCC-333333333333}",
                "ProcessId": "6060",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "TargetObject": "HKLM\\Software\\Contoso\\Setting",
                "Details": "DWORD (0x00000001)",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid13.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid13_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 2002
    assert out["activity_id"] == 2
    assert out["type_uid"] == 200202
    assert out["actor"]["process"]["uid"] == "{22222222-AAAA-BBBB-CCCC-333333333333}"
    assert out["reg_value"]["name"] == "Setting"
    assert out["unmapped"]["original_event"]["EventID"] == 13
