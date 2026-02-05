import json

from app.plugins.sysmon.map_to_ocsf import map_sysmon_eventid15_to_ocsf
from app.plugins.sysmon.parse import iter_sysmon_events, parse_sysmon_hashes


def test_parse_sysmon_hashes_string():
    hashes = parse_sysmon_hashes("MD5=abc,SHA256=def")
    assert hashes == {"md5": "abc", "sha256": "def"}


def test_parse_sysmon_hashes_string_with_spaces():
    hashes = parse_sysmon_hashes("SHA256 = abc , MD5= def ")
    assert hashes == {"sha256": "abc", "md5": "def"}


def test_parse_sysmon_hashes_missing_values():
    hashes = parse_sysmon_hashes("SHA256=,MD5=abc")
    assert hashes == {"md5": "abc"}


def test_parse_sysmon_hashes_dict_input():
    hashes = parse_sysmon_hashes({"SHA256": "abc", "MD5": "def"})
    assert hashes == {"sha256": "abc", "md5": "def"}


def test_parse_sysmon_hashes_malformed_input():
    assert parse_sysmon_hashes(None) == {}
    assert parse_sysmon_hashes(123) == {}
    assert parse_sysmon_hashes(["MD5=abc"]) == {}


def test_eventid15_maps_to_file_create_stream_hash(tmp_path):
    payload = [
        {
            "EventID": 15,
            "UtcTime": "2025-01-26 20:31:22.123",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ProcessGuid": "{8f1c2d3e-1111-2222-3333-444455556666}",
            "ProcessId": 4120,
            "TargetFilename": "C:\\Users\\User\\AppData\\Local\\Temp\\dropper.bin",
            "CreationUtcTime": "2025-01-26 20:31:21.900",
            "Hashes": (
                "MD5=9f86d081884c7d659a2feaa0c55ad015,"
                "SHA256=2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae,"
                "IMPHASH=00000000000000000000000000000000"
            ),
            "User": "DESKTOP-1\\User",
        }
    ]
    path = tmp_path / "sysmon_eventid15.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid15_to_ocsf(events[0])
    assert out is not None
    assert out["class_uid"] == 1001
    assert out["activity_id"] == 1
    assert out["type_uid"] == 100101
    assert out["file"]["path"] == "C:\\Users\\User\\AppData\\Local\\Temp\\dropper.bin"
    assert out["file"]["hash"]["sha256"].startswith("2c26b46b")
    assert out["actor"]["process"]["pid"] == 4120
    assert out["actor"]["process"]["executable"].endswith("powershell.exe")
    assert out["unmapped"]["original_event"]["EventID"] == 15


def test_eventid15_maps_with_missing_hashes(tmp_path):
    payload = [
        {
            "EventID": 15,
            "UtcTime": "2025-01-26 20:31:22.123",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ProcessId": 2222,
            "TargetFilename": "C:\\Temp\\nohash.txt",
        }
    ]
    path = tmp_path / "sysmon_eventid15_missing_hashes.json"
    path.write_text(json.dumps(payload))

    events = list(iter_sysmon_events(str(path)))
    assert len(events) == 1

    out = map_sysmon_eventid15_to_ocsf(events[0])
    assert out is not None
    assert out["file"]["path"] == "C:\\Temp\\nohash.txt"
    assert "hash" not in out["file"]
