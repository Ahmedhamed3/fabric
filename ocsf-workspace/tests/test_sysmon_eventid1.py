import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid1_to_ocsf
from app.plugins.sysmon.parse import SysmonNormalized, iter_sysmon_events

def test_eventid1_maps_to_process_launch():
    ev = SysmonNormalized(
        ts="2024-01-01T00:00:00Z",
        host="PC-1",
        user="CONTOSO\\jdoe",
        event_id=1,
        pid=1234,
        image="C:\\Windows\\System32\\cmd.exe",
        cmd="cmd.exe /c whoami",
        parent_pid=2222,
        parent_image="C:\\Windows\\explorer.exe",
        parent_cmd="explorer.exe",
    )

    out = map_sysmon_eventid1_to_ocsf(ev)
    assert out is not None
    assert out["class_uid"] == 7
    assert out["activity_id"] == 1
    assert out["category_uid"] == 1
    assert out["type_uid"] == 701
    assert out["time"] == "2024-01-01T00:00:00Z"
    assert "actor" in out and "device" in out
    assert "process" not in out
    assert out["actor"]["process"]["pid"] == 1234
    assert out["actor"]["process"]["parent_process"]["pid"] == 2222


def test_eventid1_command_line_and_parent_fields_from_eventdata(tmp_path):
    payload = [
        {
            "EventID": 1,
            "UtcTime": "2024-01-01 00:00:00.000",
            "Computer": "PC-1",
            "User": "CONTOSO\\jdoe",
            "EventData": {
                "ProcessId": "1234",
                "ProcessGuid": "{ABC-123}",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "ParentProcessId": "2222",
                "ParentProcessGuid": "{DEF-456}",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "explorer.exe",
                "IntegrityLevel": "High",
                "CurrentDirectory": "C:\\Windows\\System32",
            },
        }
    ]

    file_path = tmp_path / "sysmon_eventid1.json"
    file_path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(file_path)))
    assert len(events) == 1

    out = map_sysmon_eventid1_to_ocsf(events[0])
    assert out is not None
    assert out["actor"]["process"]["command_line"] == "cmd.exe /c whoami"
    assert out["actor"]["process"]["executable"] == "C:\\Windows\\System32\\cmd.exe"
    assert "process" not in out
    assert out["actor"]["process"]["parent_process"]["pid"] == 2222
    assert out["actor"]["process"]["parent_process"]["command_line"] == "explorer.exe"
    assert out["actor"]["process"]["parent_process"]["uid"] == "{DEF-456}"
    assert out["unmapped"]["original_event"] == payload[0]
