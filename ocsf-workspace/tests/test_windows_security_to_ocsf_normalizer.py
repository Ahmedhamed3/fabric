from __future__ import annotations

from pathlib import Path
from typing import Dict

from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader
from app.normalizers.windows_security_to_ocsf.io_ndjson import convert_events
from app.utils.raw_envelope import build_security_raw_event


def _build_raw_event(event_id: int, event_data: Dict[str, str], *, record_id: int = 100) -> dict:
    raw_record = {
        "record_id": record_id,
        "time_created_utc": "2024-01-01T12:00:00Z",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": event_id,
        "level": 4,
        "computer": "WIN-TEST",
        "event_data": event_data,
        "raw_xml": None,
    }
    return build_security_raw_event(
        raw_record,
        observed_utc="2024-01-01T12:00:00Z",
        hostname="collector-host",
        timezone_name="UTC+0000",
    )


def _schema_loader() -> OcsfSchemaLoader:
    return OcsfSchemaLoader(Path("app/ocsf_schema"))


def test_windows_security_auth_4624_json() -> None:
    raw_event = _build_raw_event(
        4624,
        {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "TargetUserSid": "S-1-5-21-111",
            "TargetUserName": "alice",
            "TargetDomainName": "CONTOSO",
            "LogonType": "3",
            "IpAddress": "10.0.0.5",
            "IpPort": "12345",
            "WorkstationName": "CLIENT1",
            "AuthenticationPackageName": "Kerberos",
            "LogonProcessName": "User32",
            "LogonId": "0x123",
        },
        record_id=200,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 3002
    assert ocsf_event["activity_id"] == 1
    assert ocsf_event["user"]["name"] == "alice"
    assert ocsf_event["status"] == "Success"


def test_windows_security_auth_4625_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4625</EventID>
        <EventRecordID>201</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:01:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-18</Data>
        <Data Name=\"SubjectUserName\">SYSTEM</Data>
        <Data Name=\"SubjectDomainName\">NT AUTHORITY</Data>
        <Data Name=\"TargetUserSid\">S-1-5-21-222</Data>
        <Data Name=\"TargetUserName\">bob</Data>
        <Data Name=\"TargetDomainName\">CONTOSO</Data>
        <Data Name=\"LogonType\">2</Data>
        <Data Name=\"IpAddress\">10.0.0.10</Data>
        <Data Name=\"IpPort\">55000</Data>
        <Data Name=\"WorkstationName\">CLIENT2</Data>
        <Data Name=\"AuthenticationPackageName\">Negotiate</Data>
        <Data Name=\"LogonProcessName\">User32</Data>
        <Data Name=\"Status\">0xC000006D</Data>
        <Data Name=\"SubStatus\">0xC000006A</Data>
        <Data Name=\"FailureReason\">%%2313</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4625,
        {
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "SYSTEM",
        },
        record_id=201,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["status"] == "Failure"
    assert ocsf_event["status_code"] == "0xC000006D"
    assert "SubStatus" in ocsf_event["status_detail"]


def test_windows_security_unsupported_event() -> None:
    raw_event = _build_raw_event(9999, {"SubjectUserName": "SYSTEM"}, record_id=300)
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert ocsf_event is None
    assert report["status"] == "unsupported"
    assert report["supported"] is False


def test_windows_security_4673_json() -> None:
    raw_event = _build_raw_event(
        4673,
        {
            "SubjectUserSid": "S-1-5-21-555",
            "SubjectUserName": "pat",
            "SubjectDomainName": "CONTOSO",
            "SubjectLogonId": "0xAAA",
            "PrivilegeList": "SeDebugPrivilege SeTcbPrivilege",
            "ProcessId": "0x1234",
            "ProcessName": "C:\\\\Windows\\\\System32\\\\svchost.exe",
            "Service": "WinDefend",
        },
        record_id=310,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert report["supported"] is True
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 3003
    assert ocsf_event["activity_id"] == 1
    assert ocsf_event["metadata"]["event_code"] == "4673"
    assert ocsf_event["user"]["name"] == "pat"
    assert ocsf_event["user"]["uid"] == "S-1-5-21-555"
    assert ocsf_event["session"]["uid"] == "0xAAA"
    assert ocsf_event["privileges"] == ["SeDebugPrivilege", "SeTcbPrivilege"]
    assert "process" not in ocsf_event
    assert ocsf_event["unmapped"]["process"] == {
        "pid": 4660,
        "path": "C:\\\\Windows\\\\System32\\\\svchost.exe",
        "name": "svchost.exe",
        "service": "WinDefend",
    }


def test_windows_security_4673_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4673</EventID>
        <EventRecordID>311</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:04:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-21-666</Data>
        <Data Name=\"SubjectUserName\">riley</Data>
        <Data Name=\"SubjectDomainName\">CONTOSO</Data>
        <Data Name=\"SubjectLogonId\">0xBBB</Data>
        <Data Name=\"PrivilegeList\">SeImpersonatePrivilege SeBackupPrivilege</Data>
        <Data Name=\"ProcessId\">9876</Data>
        <Data Name=\"ProcessName\">C:\\\\Windows\\\\System32\\\\lsass.exe</Data>
        <Data Name=\"ObjectServer\">Security</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4673,
        {
            "SubjectUserSid": "S-1-5-21-666",
            "SubjectUserName": "riley",
        },
        record_id=311,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["user"]["name"] == "riley"
    assert ocsf_event["privileges"] == ["SeImpersonatePrivilege", "SeBackupPrivilege"]
    assert "process" not in ocsf_event
    assert ocsf_event["unmapped"]["process"] == {
        "pid": 9876,
        "path": "C:\\\\Windows\\\\System32\\\\lsass.exe",
        "name": "lsass.exe",
        "object_server": "Security",
    }


def test_windows_security_4673_missing_privileges() -> None:
    raw_event = _build_raw_event(
        4673,
        {
            "SubjectUserSid": "S-1-5-21-777",
            "SubjectUserName": "sasha",
            "SubjectDomainName": "CONTOSO",
        },
        record_id=312,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert ocsf_event is None
    assert report["status"] == "unmapped"
    assert report["supported"] is True
    assert report["missing_fields"] == ["PrivilegeList"]


def test_windows_security_4688_json() -> None:
    raw_event = _build_raw_event(
        4688,
        {
            "SubjectUserSid": "S-1-5-21-123",
            "SubjectUserName": "alice",
            "SubjectDomainName": "CONTOSO",
            "NewProcessId": "0xABC",
            "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": "0x400",
            "ParentProcessName": "C:\\\\Windows\\\\explorer.exe",
        },
        record_id=400,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 1007
    assert ocsf_event["activity_id"] == 1
    assert ocsf_event["type_uid"] == 100701
    assert ocsf_event["process"]["pid"] == 2748
    assert ocsf_event["process"]["path"].endswith("cmd.exe")
    assert ocsf_event["process"]["cmd_line"] == "cmd.exe /c whoami"
    assert ocsf_event["process"]["parent_process"]["pid"] == 1024
    assert ocsf_event["process"]["parent_process"]["path"].endswith("explorer.exe")
    assert ocsf_event["actor"]["user"]["name"] == "alice"
    assert ocsf_event["actor"]["user"]["domain"] == "CONTOSO"
    assert ocsf_event["device"]["hostname"] == "collector-host"


def test_windows_security_4688_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4688</EventID>
        <EventRecordID>401</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:02:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-21-456</Data>
        <Data Name=\"SubjectUserName\">bob</Data>
        <Data Name=\"SubjectDomainName\">CONTOSO</Data>
        <Data Name=\"NewProcessId\">0x600</Data>
        <Data Name=\"NewProcessName\">C:\\\\Windows\\\\System32\\\\notepad.exe</Data>
        <Data Name=\"CommandLine\">notepad.exe C:\\\\temp\\\\notes.txt</Data>
        <Data Name=\"ProcessId\">0x200</Data>
        <Data Name=\"ParentProcessName\">C:\\\\Windows\\\\System32\\\\cmd.exe</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4688,
        {
            "SubjectUserSid": "S-1-5-21-456",
            "SubjectUserName": "bob",
        },
        record_id=401,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["process"]["pid"] == 1536
    assert ocsf_event["process"]["parent_process"]["pid"] == 512
    assert ocsf_event["actor"]["user"]["name"] == "bob"


def test_windows_security_4689_json() -> None:
    raw_event = _build_raw_event(
        4689,
        {
            "SubjectUserSid": "S-1-5-21-777",
            "SubjectUserName": "carol",
            "SubjectDomainName": "CONTOSO",
            "ProcessId": "0x3e8",
            "ProcessName": "C:\\\\Windows\\\\System32\\\\notepad.exe",
        },
        record_id=500,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["activity_id"] == 2
    assert ocsf_event["type_uid"] == 100702
    assert ocsf_event["process"]["pid"] == 1000
    assert ocsf_event["process"]["path"].endswith("notepad.exe")
    assert ocsf_event["process"]["name"] == "notepad.exe"
    assert ocsf_event["actor"]["user"]["name"] == "carol"


def test_windows_security_4689_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4689</EventID>
        <EventRecordID>501</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:03:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-21-888</Data>
        <Data Name=\"SubjectUserName\">dave</Data>
        <Data Name=\"SubjectDomainName\">CONTOSO</Data>
        <Data Name=\"ProcessId\">1234</Data>
        <Data Name=\"ProcessName\">C:\\\\Windows\\\\System32\\\\calc.exe</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4689,
        {
            "SubjectUserSid": "S-1-5-21-888",
            "SubjectUserName": "dave",
        },
        record_id=501,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["process"]["pid"] == 1234
    assert ocsf_event["process"]["name"] == "calc.exe"


def test_windows_security_4689_missing_required_fields() -> None:
    raw_event = _build_raw_event(
        4689,
        {
            "SubjectUserSid": "S-1-5-21-999",
            "SubjectUserName": "erin",
        },
        record_id=502,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert ocsf_event is None
    assert report["status"] == "unmapped"
    assert report["supported"] is True
    assert report["missing_fields"] == ["ProcessId", "ProcessName"]
    assert "missing required fields" in report["message"]


def test_windows_security_4697_json() -> None:
    raw_event = _build_raw_event(
        4697,
        {
            "SubjectUserSid": "S-1-5-21-12345",
            "SubjectUserName": "alex",
            "SubjectDomainName": "CONTOSO",
            "ServiceName": "ExampleService",
            "ServiceFileName": "C:\\\\Program Files\\\\Example\\\\service.exe",
            "ServiceType": "Win32OwnProcess",
            "StartType": "AutoStart",
            "AccountName": "LocalSystem",
            "ProcessId": "0x1f4",
        },
        record_id=600,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert report["supported"] is True
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 1007
    assert ocsf_event["activity_id"] == 1
    assert ocsf_event["process"]["pid"] == 500
    assert ocsf_event["process"]["path"].endswith("service.exe")
    assert ocsf_event["process"]["name"] == "service.exe"
    assert ocsf_event["actor"]["user"]["name"] == "alex"
    assert ocsf_event["unmapped"]["service"] == {
        "name": "ExampleService",
        "start_type": "AutoStart",
        "service_type": "Win32OwnProcess",
        "account": "LocalSystem",
    }


def test_windows_security_4697_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4697</EventID>
        <EventRecordID>601</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:05:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-21-22222</Data>
        <Data Name=\"SubjectUserName\">jamie</Data>
        <Data Name=\"SubjectDomainName\">CONTOSO</Data>
        <Data Name=\"ServiceName\">XmlService</Data>
        <Data Name=\"ServiceFileName\">C:\\\\Services\\\\xmlsvc.exe</Data>
        <Data Name=\"ServiceType\">Win32ShareProcess</Data>
        <Data Name=\"StartType\">DemandStart</Data>
        <Data Name=\"AccountName\">NT AUTHORITY\\\\LocalService</Data>
        <Data Name=\"ProcessId\">4321</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4697,
        {
            "SubjectUserSid": "S-1-5-21-22222",
            "SubjectUserName": "jamie",
        },
        record_id=601,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["process"]["pid"] == 4321
    assert ocsf_event["process"]["name"] == "xmlsvc.exe"
    assert ocsf_event["actor"]["user"]["name"] == "jamie"
    assert ocsf_event["unmapped"]["service"]["name"] == "XmlService"


def test_windows_security_4697_missing_required_fields() -> None:
    raw_event = _build_raw_event(
        4697,
        {
            "SubjectUserSid": "S-1-5-21-33333",
            "SubjectUserName": "lee",
            "ServiceName": "MissingFileName",
        },
        record_id=602,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert ocsf_event is None
    assert report["status"] == "unmapped"
    assert report["supported"] is True
    assert report["schema_valid"] is False
    assert report["missing_fields"] == ["ServiceFileName"]


def test_windows_security_4698_json() -> None:
    raw_event = _build_raw_event(
        4698,
        {
            "SubjectUserSid": "S-1-5-21-44444",
            "SubjectUserName": "morgan",
            "SubjectDomainName": "CONTOSO",
            "TaskName": "\\\\ExampleTask",
            "TaskContent": "<Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>",
            "ProcessName": "C:\\\\Windows\\\\System32\\\\schtasks.exe",
            "ProcessId": "0x2bc",
        },
        record_id=700,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert report["supported"] is True
    assert ocsf_event is not None
    assert ocsf_event["class_uid"] == 1007
    assert ocsf_event["activity_id"] == 1
    assert ocsf_event["process"]["pid"] == 700
    assert ocsf_event["process"]["name"] == "schtasks.exe"
    assert ocsf_event["actor"]["user"]["name"] == "morgan"
    assert ocsf_event["unmapped"]["scheduled_task"] == {
        "name": "\\\\ExampleTask",
        "xml": "<Task><Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>",
        "command": "C:\\\\Windows\\\\System32\\\\schtasks.exe",
    }


def test_windows_security_4698_xml() -> None:
    xml_payload = """
    <Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">
      <System>
        <EventID>4698</EventID>
        <EventRecordID>701</EventRecordID>
        <TimeCreated SystemTime=\"2024-01-01T12:06:00.000Z\" />
        <Computer>WIN-TEST</Computer>
      </System>
      <EventData>
        <Data Name=\"SubjectUserSid\">S-1-5-21-55555</Data>
        <Data Name=\"SubjectUserName\">taylor</Data>
        <Data Name=\"SubjectDomainName\">CONTOSO</Data>
        <Data Name=\"TaskName\">\\\\XmlTask</Data>
        <Data Name=\"TaskXml\"><Task /></Data>
        <Data Name=\"ProcessName\">C:\\\\Windows\\\\System32\\\\taskeng.exe</Data>
        <Data Name=\"ProcessId\">2048</Data>
      </EventData>
    </Event>
    """.strip()
    raw_event = _build_raw_event(
        4698,
        {
            "SubjectUserSid": "S-1-5-21-55555",
            "SubjectUserName": "taylor",
        },
        record_id=701,
    )
    raw_event["raw"]["format"] = "xml"
    raw_event["raw"]["data"] = xml_payload
    raw_event["raw"]["xml"] = xml_payload
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert report["status"] == "valid"
    assert report["schema_valid"] is True
    assert ocsf_event is not None
    assert ocsf_event["process"]["pid"] == 2048
    assert ocsf_event["process"]["name"] == "taskeng.exe"
    assert ocsf_event["actor"]["user"]["name"] == "taylor"
    assert ocsf_event["unmapped"]["scheduled_task"]["name"] == "\\\\XmlTask"


def test_windows_security_4698_missing_required_fields() -> None:
    raw_event = _build_raw_event(
        4698,
        {
            "SubjectUserSid": "S-1-5-21-66666",
            "SubjectUserName": "casey",
            "ProcessName": "C:\\\\Windows\\\\System32\\\\taskeng.exe",
        },
        record_id=702,
    )
    schema_loader = _schema_loader()
    ocsf_event, report = next(
        convert_events([raw_event], schema_loader=schema_loader, strict=False)
    )
    assert ocsf_event is None
    assert report["status"] == "unmapped"
    assert report["supported"] is True
    assert report["schema_valid"] is False
    assert report["missing_fields"] == ["TaskName"]
