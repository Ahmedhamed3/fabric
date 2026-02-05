import json

from app.detect import auto_detect_source
from app.ocsf.constants import (
    FILE_SYSTEM_ACTIVITY_CLASS_UID,
    FILE_SYSTEM_ACTIVITY_DELETE_ID,
    FILE_SYSTEM_ACTIVITY_MODIFY_ID,
    FILE_SYSTEM_ACTIVITY_READ_ID,
    calc_type_uid,
)
from app.plugins.windows_security.parse import (
    WindowsSecurityObjectAccessNormalized,
    normalize_windows_security_event,
)
from app.plugins.windows_security.pipeline import convert_windows_security_events_to_ocsf_jsonl


def test_windows_security_4663_detects_plugin():
    events = [
        {
            "EventID": 4663,
            "Channel": "Security",
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": "2024-05-01T12:34:56.789Z",
            "EventData": {
                "ObjectName": "C:\\Windows\\Temp\\readme.txt",
                "ObjectType": "File",
                "AccessMask": "0x1",
            },
        }
    ]

    detection = auto_detect_source(events)

    assert detection["source_type"] == "windows-security"
    assert detection["confidence"] >= 0.6


def test_windows_security_4663_parse_normalization():
    event = {
        "Event": {
            "System": {
                "EventID": 4663,
                "TimeCreated": {"SystemTime": "2024-05-01T12:34:56.789Z"},
                "Computer": "FILESRV01",
            },
            "EventData": {
                "Data": [
                    {"Name": "SubjectUserSid", "Value": "S-1-5-21-1"},
                    {"Name": "SubjectUserName", "Value": "alice"},
                    {"Name": "SubjectDomainName", "Value": "CONTOSO"},
                    {"Name": "SubjectLogonId", "Value": "0x1234"},
                    {"Name": "ObjectType", "Value": "File"},
                    {"Name": "ObjectName", "Value": "C:\\Data\\report.txt"},
                    {"Name": "ProcessName", "Value": "C:\\Windows\\System32\\notepad.exe"},
                    {"Name": "ProcessId", "Value": "0x1f4"},
                    {"Name": "AccessMask", "Value": "0x1"},
                    {"Name": "AccessList", "Value": "%%4416"},
                ]
            },
        }
    }

    normalized = normalize_windows_security_event(event)

    assert isinstance(normalized, WindowsSecurityObjectAccessNormalized)
    assert normalized.subject_username == "alice"
    assert normalized.subject_domain == "CONTOSO"
    assert normalized.subject_sid == "S-1-5-21-1"
    assert normalized.object_name == "C:\\Data\\report.txt"
    assert normalized.process_name.endswith("notepad.exe")
    assert normalized.access_mask == "0x1"
    assert normalized.access_list == ["%%4416"]


def test_windows_security_4663_mapping_activity_ids_and_unmapped():
    events = [
        {
            "EventID": 4663,
            "Channel": "Security",
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": "2024-05-01T12:34:56.789Z",
            "EventData": {
                "SubjectUserName": "alice",
                "SubjectDomainName": "CONTOSO",
                "ObjectType": "File",
                "ObjectName": "C:\\Data\\read.txt",
                "ProcessName": "C:\\Windows\\System32\\notepad.exe",
                "ProcessId": "0x1f4",
                "AccessMask": "0x1",
                "AccessList": "%%4416",
            },
        },
        {
            "EventID": 4663,
            "Channel": "Security",
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": "2024-05-01T12:35:56.789Z",
            "EventData": {
                "SubjectUserName": "alice",
                "SubjectDomainName": "CONTOSO",
                "ObjectType": "File",
                "ObjectName": "C:\\Data\\write.txt",
                "ProcessName": "C:\\Windows\\System32\\notepad.exe",
                "ProcessId": "0x1f4",
                "AccessMask": "0x2",
                "AccessList": "%%4417",
            },
        },
        {
            "EventID": 4663,
            "Channel": "Security",
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": "2024-05-01T12:36:56.789Z",
            "EventData": {
                "SubjectUserName": "alice",
                "SubjectDomainName": "CONTOSO",
                "ObjectType": "File",
                "ObjectName": "C:\\Data\\delete.txt",
                "ProcessName": "C:\\Windows\\System32\\notepad.exe",
                "ProcessId": "0x1f4",
                "AccessMask": "0x10000",
                "AccessList": ["%%1537"],
            },
        },
    ]

    output_lines = list(convert_windows_security_events_to_ocsf_jsonl(events))
    assert len(output_lines) == 3

    parsed = [json.loads(line) for line in output_lines]
    activity_ids = [entry["activity_id"] for entry in parsed]
    assert activity_ids == [
        FILE_SYSTEM_ACTIVITY_READ_ID,
        FILE_SYSTEM_ACTIVITY_MODIFY_ID,
        FILE_SYSTEM_ACTIVITY_DELETE_ID,
    ]
    assert parsed[0]["class_uid"] == FILE_SYSTEM_ACTIVITY_CLASS_UID
    assert parsed[0]["type_uid"] == calc_type_uid(
        FILE_SYSTEM_ACTIVITY_CLASS_UID, FILE_SYSTEM_ACTIVITY_READ_ID
    )
    assert parsed[0]["unmapped"]["original_event"]["EventID"] == 4663
