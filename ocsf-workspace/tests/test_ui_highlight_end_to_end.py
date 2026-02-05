import json

from fastapi.testclient import TestClient

from app.main import app


def test_highlighted_values_render_in_convert_response():
    client = TestClient(app)
    shared_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    payload = [
        {
            "EventID": 1,
            "UtcTime": "2024-05-01 09:15:00.000",
            "Computer": "LAB-WIN10-01",
            "User": "CONTOSO\\svc_app",
            "EventData": {
                "ProcessGuid": "{A1B2C3D4-1111-2222-3333-444455556666}",
                "ProcessId": "4110",
                "Image": shared_path,
                "CommandLine": f'"{shared_path}" -NoLogo',
                "ParentProcessGuid": "{ABCDEF12-3333-4444-5555-666677778888}",
                "ParentProcessId": "4000",
                "ParentImage": "C:\\Windows\\System32\\services.exe",
                "ParentCommandLine": "services.exe",
            },
        }
    ]
    response = client.post(
        "/",
        files={"file": ("sysmon.json", json.dumps(payload), "application/json")},
        data={"source": "sysmon", "highlight": "1"},
    )
    assert response.status_code == 200
    assert '<span class="hl"' in response.text
    escaped_path = shared_path.replace("\\", "\\\\")
    assert response.text.count(f">{escaped_path}</span>") >= 2
    assert "<script>" not in response.text
