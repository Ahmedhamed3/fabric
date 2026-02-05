import json

from fastapi.testclient import TestClient

from app.main import app


def test_convert_sysmon_upload_json_array_mixed_events():
    client = TestClient(app)

    payload = [
        {
            "EventID": 1,
            "UtcTime": "2024-01-01 00:00:00.000",
            "Computer": "host1",
            "User": "user1",
            "ProcessId": 1234,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
        {
            "EventID": 3,
            "UtcTime": "2024-01-01 00:00:01.000",
            "Computer": "host1",
            "User": "user1",
            "SourceIp": "10.0.0.1",
            "SourcePort": 12345,
            "DestinationIp": "10.0.0.2",
            "DestinationPort": 443,
            "Protocol": "tcp",
        },
        {
            "EventID": 11,
            "UtcTime": "2024-01-01 00:00:01.500",
            "Computer": "host1",
            "User": "user1",
            "ProcessId": 5555,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "TargetFilename": "C:\\Temp\\created.txt",
        },
        {"EventID": 99, "UtcTime": "2024-01-01 00:00:02.000"},
    ]

    files = {
        "file": (
            "mixed.json",
            json.dumps(payload).encode("utf-8"),
            "application/json",
        )
    }

    response = client.post("/convert/sysmon", files=files)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")

    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) == 4

    events = [json.loads(line) for line in lines]
    type_pairs = {(event["class_uid"], event["type_uid"]) for event in events}

    assert (7, 701) in type_pairs
    assert (4001, 400101) in type_pairs
    assert (1001, 100101) in type_pairs
    assert any(event.get("metadata", {}).get("product") == "Unknown" for event in events)


def test_convert_sysmon_preview_returns_original_and_unified():
    client = TestClient(app)

    payload = [
        {
            "EventID": 11,
            "UtcTime": "2024-01-01 00:00:01.500",
            "Computer": "host1",
            "User": "user1",
            "ProcessId": 5555,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "TargetFilename": "C:\\Temp\\created.txt",
        }
    ]

    files = {
        "file": (
            "preview.json",
            json.dumps(payload).encode("utf-8"),
            "application/json",
        )
    }

    response = client.post("/convert/sysmon/preview", files=files)

    assert response.status_code == 200
    body = response.json()
    assert "original" in body
    assert "unified_ndjson" in body
    assert "\"class_uid\"" in body["unified_ndjson"]
    assert "\"activity_id\"" in body["unified_ndjson"]
    assert "\"type_uid\"" in body["unified_ndjson"]


def test_convert_sysmon_upload_ndjson_eventid15_hashes():
    client = TestClient(app)

    ndjson_line = (
        "{\"EventID\":15,\"UtcTime\":\"2025-01-26 20:31:22.123\","
        "\"Image\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\","
        "\"ProcessGuid\":\"{8f1c2d3e-1111-2222-3333-444455556666}\","
        "\"ProcessId\":4120,"
        "\"TargetFilename\":\"C:\\\\Users\\\\User\\\\AppData\\\\Local\\\\Temp\\\\dropper.bin\","
        "\"CreationUtcTime\":\"2025-01-26 20:31:21.900\","
        "\"Hashes\":\"MD5=9f86d081884c7d659a2feaa0c55ad015,"
        "SHA256=2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae,"
        "IMPHASH=00000000000000000000000000000000\","
        "\"User\":\"DESKTOP-1\\\\User\"}"
    )

    files = {
        "file": ("eventid15.ndjson", ndjson_line.encode("utf-8"), "application/x-ndjson")
    }

    response = client.post("/convert/sysmon", files=files)

    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) == 1

    event = json.loads(lines[0])
    assert event["file"]["hash"]["sha256"].startswith("2c26b46b")
    assert event["unmapped"]["original_event"]["EventID"] == 15
