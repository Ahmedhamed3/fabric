from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.ocsf.constants import (
    AUTHENTICATION_ACTIVITY_CLASS_UID,
    CATEGORY_UID_SYSTEM,
    calc_type_uid,
)
from app.plugins.azure_ad_signin.parse import AzureAdSigninNormalized

AUTH_LOGON_SUCCESS_ID = 1
AUTH_LOGON_FAILURE_ID = 2


def _to_iso8601_utc(ts: Optional[Any]) -> str:
    if ts is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(ts, str):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
        try:
            normalized = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _derive_auth_result(error_code: Optional[int]) -> str:
    if error_code is None:
        return "unknown"
    if error_code == 0:
        return "success"
    return "failure"


def map_azure_ad_signin_to_ocsf(ev: AzureAdSigninNormalized) -> Optional[Dict[str, Any]]:
    if ev.category and ev.category.lower() != "signinlogs":
        return None
    if ev.status_error_code is None and not (ev.user_principal_name or ev.user_id):
        return None

    result = _derive_auth_result(ev.status_error_code)
    activity_id = AUTH_LOGON_SUCCESS_ID if result == "success" else AUTH_LOGON_FAILURE_ID
    type_uid = calc_type_uid(AUTHENTICATION_ACTIVITY_CLASS_UID, activity_id)

    actor: Dict[str, Any] = {}
    user: Dict[str, Any] = {}
    if ev.user_principal_name:
        user["name"] = ev.user_principal_name
    if ev.user_id:
        user["uid"] = ev.user_id
    if user:
        actor["user"] = user

    auth: Dict[str, Any] = {
        "result": result,
    }
    if result == "failure" and ev.status_failure_reason:
        auth["failure_reason"] = ev.status_failure_reason

    if ev.mfa_auth_method or ev.mfa_result:
        mfa: Dict[str, Any] = {}
        if ev.mfa_auth_method:
            mfa["method"] = ev.mfa_auth_method
        if ev.mfa_result:
            mfa["result"] = ev.mfa_result
        if mfa:
            auth["mfa"] = mfa

    ocsf_event: Dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_UID_SYSTEM,
        "class_uid": AUTHENTICATION_ACTIVITY_CLASS_UID,
        "type_uid": type_uid,
        "time": _to_iso8601_utc(ev.time),
        "metadata": {"product": "Azure AD Sign-In"},
        "auth": auth,
        "unmapped": {"original_event": ev.original_event},
    }

    if actor:
        ocsf_event["actor"] = actor

    if ev.ip_address:
        src_endpoint: Dict[str, Any] = {"ip": ev.ip_address}
        location: Dict[str, Any] = {}
        if ev.location_city:
            location["city"] = ev.location_city
        if ev.location_country:
            location["country"] = ev.location_country
        if location:
            src_endpoint["location"] = location
        ocsf_event["src_endpoint"] = src_endpoint
    elif ev.location_city or ev.location_country:
        location: Dict[str, Any] = {}
        if ev.location_city:
            location["city"] = ev.location_city
        if ev.location_country:
            location["country"] = ev.location_country
        if location:
            ocsf_event["location"] = location

    if ev.app_display_name:
        ocsf_event["service"] = {"name": ev.app_display_name}

    if ev.conditional_access_status:
        ocsf_event["unmapped"]["conditional_access_status"] = ev.conditional_access_status
    if ev.client_app_used:
        ocsf_event["unmapped"]["client_app_used"] = ev.client_app_used
    if ev.device_detail:
        ocsf_event["unmapped"]["device_detail"] = ev.device_detail
    if ev.user_agent:
        ocsf_event["unmapped"]["user_agent"] = ev.user_agent
    if ev.mfa_detail is not None:
        ocsf_event["unmapped"]["mfa_detail"] = ev.mfa_detail

    return ocsf_event
