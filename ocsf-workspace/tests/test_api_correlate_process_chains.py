from fastapi.testclient import TestClient

from app.main import app


def test_correlate_process_chains_returns_empty_for_no_events():
    client = TestClient(app)

    response = client.post("/correlate/process-chains", json=[])

    assert response.status_code == 200
    assert response.json() == []


def test_correlate_process_chains_formats_chain_response():
    client = TestClient(app)

    payload = [
        {
            "time": "2024-01-01T00:00:00Z",
            "activity_id": 1,
            "type_uid": 701001,
            "actor": {
                "process": {
                    "uid": "proc-1",
                    "executable": "cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                    "parent_process": {"uid": "parent-1"},
                }
            },
        },
        {
            "time": "2024-01-01T00:00:01Z",
            "activity_id": 2,
            "type_uid": 701002,
            "actor": {"process": {"uid": "proc-1", "executable": "cmd.exe"}},
            "process": {
                "uid": "target-1",
                "executable": "notepad.exe",
                "command_line": "notepad.exe",
            },
        },
    ]

    response = client.post("/correlate/process-chains", json=payload)

    assert response.status_code == 200
    chains = response.json()
    assert len(chains) == 1
    chain = chains[0]
    assert chain["process_uid"] == "proc-1"
    assert chain["parent_process_uid"] == "parent-1"
    assert chain["event_count"] == 2
    assert chain["events"][0]["activity_id"] == 1
    assert chain["events"][1]["target_process"]["uid"] == "target-1"
