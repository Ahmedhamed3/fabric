import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid7_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid7_maps_to_module_load(tmp_path):
    payload = [
        {
            "EventID": 7,
            "UtcTime": "2024-04-01 10:11:12.500",
            "Computer": "WORKSTATION-2",
            "User": "CONTOSO\\jdoe",
            "EventData": {
                "ProcessGuid": "{BBBB1111-2222-3333-4444-555555555555}",
                "ProcessId": "2200",
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "ImageLoaded": "C:\\Windows\\System32\\shell32.dll",
            },
        }
    ]
    path = tmp_path / "sysmon_eventid7.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid7_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 5
    assert out["activity_id"] == 1
    assert out["type_uid"] == 501
    assert out["actor"]["process"]["uid"] == "{BBBB1111-2222-3333-4444-555555555555}"
    assert out["module"]["file"]["path"] == "C:\\Windows\\System32\\shell32.dll"
    assert out["unmapped"]["original_event"]["EventID"] == 7
