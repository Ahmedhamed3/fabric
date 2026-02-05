import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid14_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid14_maps_to_registry_key_rename(tmp_path):
    payload = [
        {
            "EventID": 14,
            "UtcTime": "2024-04-03 11:12:14.000",
            "Computer": "WORKSTATION-7",
            "User": "CONTOSO\\admin",
            "EventData": {
                "ProcessGuid": "{33333333-AAAA-BBBB-CCCC-444444444444}",
                "ProcessId": "7070",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "EventType": "RenameKey",
                "TargetObject": "HKLM\\Software\\Contoso",
                "NewName": "HKLM\\Software\\ContosoRenamed",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid14.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid14_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 2001
    assert out["activity_id"] == 5
    assert out["type_uid"] == 200105
    assert out["actor"]["process"]["uid"] == "{33333333-AAAA-BBBB-CCCC-444444444444}"
    assert out["reg_key"]["path"] == "HKLM\\Software\\ContosoRenamed"
    assert out["prev_reg_key"]["path"] == "HKLM\\Software\\Contoso"
    assert out["unmapped"]["original_event"]["EventID"] == 14
