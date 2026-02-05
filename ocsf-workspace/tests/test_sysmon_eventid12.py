import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid12_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid12_maps_to_registry_key_create(tmp_path):
    payload = [
        {
            "EventID": 12,
            "UtcTime": "2024-04-03 11:12:13.000",
            "Computer": "WORKSTATION-5",
            "User": "CONTOSO\\admin",
            "EventData": {
                "ProcessGuid": "{11111111-AAAA-BBBB-CCCC-222222222222}",
                "ProcessId": "5050",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "EventType": "CreateKey",
                "TargetObject": "HKLM\\Software\\Contoso",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid12.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid12_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 2001
    assert out["activity_id"] == 1
    assert out["type_uid"] == 200101
    assert out["actor"]["process"]["uid"] == "{11111111-AAAA-BBBB-CCCC-222222222222}"
    assert out["reg_key"]["path"] == "HKLM\\Software\\Contoso"
    assert out["unmapped"]["original_event"]["EventID"] == 12
