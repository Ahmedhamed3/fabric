from typing import Any, List, Tuple


def _has_status_error_code(ev: dict) -> bool:
    status = ev.get("status")
    if isinstance(status, dict):
        return "errorCode" in status
    return False


def _looks_like_azure_ad_signin(ev: Any) -> bool:
    if not isinstance(ev, dict):
        return False

    category = ev.get("category")
    has_category = isinstance(category, str) and category.lower() == "signinlogs"

    has_user = bool(ev.get("userPrincipalName") or ev.get("userId") or ev.get("id"))
    has_app = bool(ev.get("appDisplayName"))
    has_ip = bool(ev.get("ipAddress"))
    has_status = _has_status_error_code(ev)
    has_conditional_access = "conditionalAccessStatus" in ev

    primary_match = has_category and has_status and (has_user or has_app)
    secondary_match = has_user and has_app and has_ip and has_status and has_conditional_access

    return primary_match or secondary_match


def score_events(events: List[dict]) -> Tuple[float, str]:
    if not events:
        return 0.0, "No events provided for detection."

    total = 0
    matched = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        total += 1
        if _looks_like_azure_ad_signin(ev):
            matched += 1

    if total == 0:
        return 0.0, "No JSON objects to score."

    score = matched / total
    reason = f"Matched {matched}/{total} events with Azure AD Sign-In fields."
    return score, reason
