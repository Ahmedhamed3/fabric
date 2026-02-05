
import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid3_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events


def test_eventid3_maps_to_network_open(tmp_path):
    payload = [
        {
            "EventID": 3,
            "UtcTime": "2024-02-03 04:05:06.789",
            "Computer": "PC-2",
            "User": "CONTOSO\\alice",
            "ProcessId": 4321,
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
            "SourceIp": "10.0.0.5",
            "SourcePort": "51515",
            "DestinationIp": "93.184.216.34",
            "DestinationPort": "443",
            "Protocol": "tcp",
        }
    ]
    path = tmp_path / "sysmon.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid3_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 4001
    assert out["category_uid"] == 4
    assert out["activity_id"] == 1
    assert out["type_uid"] == 400101
    assert out["time"] == "2024-02-03T04:05:06.789000Z"
    assert out["network"]["src_endpoint"]["ip"] == "10.0.0.5"
    assert out["network"]["src_endpoint"]["port"] == 51515
    assert out["network"]["dst_endpoint"]["ip"] == "93.184.216.34"
    assert out["network"]["dst_endpoint"]["port"] == 443
    assert out["network"]["protocol"] == "tcp"
