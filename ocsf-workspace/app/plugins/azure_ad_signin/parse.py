import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple


@dataclass
class AzureAdSigninNormalized:
    category: Optional[str]
    time: Optional[Any]
    user_principal_name: Optional[str]
    user_id: Optional[str]
    app_display_name: Optional[str]
    ip_address: Optional[str]
    status_error_code: Optional[int]
    status_failure_reason: Optional[str]
    location_city: Optional[str]
    location_country: Optional[str]
    conditional_access_status: Optional[str]
    mfa_auth_method: Optional[str]
    mfa_result: Optional[str]
    mfa_detail: Optional[Any]
    client_app_used: Optional[str]
    device_detail: Optional[Dict[str, Any]]
    user_agent: Optional[str]
    original_event: Dict[str, Any]


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _extract_mfa_detail(ev: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[Any]]:
    for key in ("mfaDetail", "mfaDetails"):
        detail = ev.get(key)
        if isinstance(detail, dict):
            method = _as_str(detail.get("authMethod") or detail.get("authenticationMethod"))
            result = _as_str(detail.get("result"))
            return method, result, detail
        if isinstance(detail, list):
            for item in detail:
                if not isinstance(item, dict):
                    continue
                method = _as_str(item.get("authMethod") or item.get("authenticationMethod"))
                result = _as_str(item.get("result"))
                if method or result:
                    return method, result, detail
            return None, None, detail

    auth_details = ev.get("authenticationDetails")
    if isinstance(auth_details, list):
        for item in auth_details:
            if not isinstance(item, dict):
                continue
            method = _as_str(item.get("authenticationMethod") or item.get("authMethod"))
            result = item.get("result")
            if result is None:
                succeeded = item.get("succeeded")
                if isinstance(succeeded, bool):
                    result = "success" if succeeded else "failure"
            result_str = _as_str(result)
            if method or result_str:
                return method, result_str, auth_details
        return None, None, auth_details

    return None, None, None


def _extract_fields(ev: Dict[str, Any]) -> AzureAdSigninNormalized:
    status = ev.get("status") if isinstance(ev.get("status"), dict) else {}
    location = ev.get("location") if isinstance(ev.get("location"), dict) else {}
    device_detail = ev.get("deviceDetail") if isinstance(ev.get("deviceDetail"), dict) else None

    mfa_auth_method, mfa_result, mfa_detail = _extract_mfa_detail(ev)

    return AzureAdSigninNormalized(
        category=_as_str(ev.get("category")),
        time=ev.get("time") or ev.get("createdDateTime"),
        user_principal_name=_as_str(ev.get("userPrincipalName")),
        user_id=_as_str(ev.get("userId") or ev.get("id")),
        app_display_name=_as_str(ev.get("appDisplayName")),
        ip_address=_as_str(ev.get("ipAddress")),
        status_error_code=_safe_int(status.get("errorCode")),
        status_failure_reason=_as_str(status.get("failureReason")),
        location_city=_as_str(location.get("city")),
        location_country=_as_str(location.get("countryOrRegion")),
        conditional_access_status=_as_str(ev.get("conditionalAccessStatus")),
        mfa_auth_method=mfa_auth_method,
        mfa_result=mfa_result,
        mfa_detail=mfa_detail,
        client_app_used=_as_str(ev.get("clientAppUsed")),
        device_detail=device_detail,
        user_agent=_as_str(ev.get("userAgent")),
        original_event=dict(ev),
    )


def normalize_azure_ad_signin_event(ev: Dict[str, Any]) -> AzureAdSigninNormalized:
    return _extract_fields(ev)


def iter_azure_ad_signin_events_from_events(
    events: Iterable[Dict[str, Any]],
) -> Iterator[AzureAdSigninNormalized]:
    for ev in events:
        if isinstance(ev, dict):
            yield _extract_fields(ev)


def iter_azure_ad_signin_events(file_path: str) -> Iterator[AzureAdSigninNormalized]:
    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if isinstance(ev, dict):
                yield _extract_fields(ev)
