import json
from pathlib import Path

from app.ocsf.constants import AUTHENTICATION_ACTIVITY_CLASS_UID, calc_type_uid
from app.plugins.azure_ad_signin.detect import score_events
from app.plugins.azure_ad_signin.map_to_ocsf import (
    AUTH_LOGON_FAILURE_ID,
    AUTH_LOGON_SUCCESS_ID,
    map_azure_ad_signin_to_ocsf,
)
from app.plugins.azure_ad_signin.parse import normalize_azure_ad_signin_event
from app.plugins.azure_ad_signin.pipeline import convert_azure_ad_signin_events_to_ocsf_jsonl


def _load_ndjson(sample_path: Path) -> list[dict]:
    events = []
    for line in sample_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def test_azure_ad_signin_detection_and_success_mapping():
    sample_path = Path("samples") / "azure_ad_signin_success.ndjson"
    events = _load_ndjson(sample_path)

    confidence, reason = score_events(events)
    assert confidence >= 0.6, reason

    output_lines = list(convert_azure_ad_signin_events_to_ocsf_jsonl(events))
    assert output_lines

    parsed = json.loads(output_lines[0])
    expected_type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, AUTH_LOGON_SUCCESS_ID)
    assert parsed["class_uid"] == AUTHENTICATION_ACTIVITY_CLASS_UID
    assert parsed["activity_id"] == AUTH_LOGON_SUCCESS_ID
    assert parsed["type_uid"] == expected_type_uid
    assert parsed["actor"]["user"]["name"]
    assert parsed["src_endpoint"]["ip"]
    assert parsed["service"]["name"]
    assert parsed["auth"]["result"] == "success"
    assert "original_event" in parsed["unmapped"]

    mfa_mapped = parsed.get("auth", {}).get("mfa")
    assert mfa_mapped or "mfa_detail" in parsed["unmapped"]


def test_azure_ad_signin_failure_mapping_and_optional_fields():
    sample_path = Path("samples") / "azure_ad_signin_failure.ndjson"
    events = _load_ndjson(sample_path)

    output_lines = list(convert_azure_ad_signin_events_to_ocsf_jsonl(events))
    assert output_lines

    parsed = json.loads(output_lines[0])
    expected_type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, AUTH_LOGON_FAILURE_ID)
    assert parsed["class_uid"] == AUTHENTICATION_ACTIVITY_CLASS_UID
    assert parsed["activity_id"] == AUTH_LOGON_FAILURE_ID
    assert parsed["type_uid"] == expected_type_uid
    assert parsed["auth"]["result"] == "failure"
    assert parsed["auth"]["failure_reason"]
    assert parsed["src_endpoint"]["ip"]
    assert "original_event" in parsed["unmapped"]

    minimal_event = {
        "category": "SignInLogs",
        "time": "2025-01-30T10:00:00Z",
        "userPrincipalName": "minimal@contoso.com",
        "appDisplayName": "OfficeHome",
        "status": {"errorCode": 0},
    }
    normalized = normalize_azure_ad_signin_event(minimal_event)
    mapped = map_azure_ad_signin_to_ocsf(normalized)
    assert mapped is not None
    assert mapped["auth"]["result"] == "success"
    assert "original_event" in mapped["unmapped"]
