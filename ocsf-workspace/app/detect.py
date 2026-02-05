from typing import Dict, List

from app.formats.reader import PARSE_ERROR_KEY
from app.plugins.file_artifact.detect import score_events as score_file_artifact
from app.plugins.azure_ad_signin.detect import score_events as score_azure_ad_signin
from app.plugins.suricata.detect import score_events as score_suricata
from app.plugins.sysmon.detect import score_events as score_sysmon
from app.plugins.windows_security.detect import score_events as score_windows_security
from app.plugins.zeek.detect import score_events as score_zeek
from app.plugins.zeek_http.detect import score_events as score_zeek_http
from app.plugins.proxy_http.detect import score_events as score_proxy_http


SCORE_FUNCS = {
    "azure_ad_signin": score_azure_ad_signin,
    "windows-security": score_windows_security,
    "sysmon": score_sysmon,
    "suricata": score_suricata,
    "zeek": score_zeek,
    "zeek_http": score_zeek_http,
    "proxy_http": score_proxy_http,
    "file-artifact": score_file_artifact,
}


def auto_detect_source(
    events: List[dict],
    *,
    threshold: float = 0.6,
) -> Dict[str, object]:
    if not events:
        return {
            "source_type": "unknown",
            "confidence": 0.0,
            "reason": "No events provided for detection.",
        }

    scored = []
    for source_type, scorer in SCORE_FUNCS.items():
        confidence, reason = scorer(events)
        scored.append((source_type, confidence, reason))

    best_source, best_confidence, best_reason = max(scored, key=lambda item: item[1])

    if best_confidence < threshold:
        return {
            "source_type": "unknown",
            "confidence": best_confidence,
            "reason": (
                f"Low confidence. Best guess: {best_source}. {best_reason}"
            ),
        }

    return {
        "source_type": best_source,
        "confidence": best_confidence,
        "reason": best_reason,
    }


def detect_event(
    event: dict,
    *,
    threshold: float = 0.6,
) -> Dict[str, object]:
    if not event:
        return {
            "source_type": "unknown",
            "confidence": 0.0,
            "reason": "No event provided for detection.",
        }
    if PARSE_ERROR_KEY in event:
        return {
            "source_type": "unknown",
            "confidence": 0.0,
            "reason": "Parse error event.",
        }

    scored = []
    for source_type, scorer in SCORE_FUNCS.items():
        confidence, reason = scorer([event])
        scored.append((source_type, confidence, reason))

    best_source, best_confidence, best_reason = max(scored, key=lambda item: item[1])

    if best_confidence < threshold:
        return {
            "source_type": "unknown",
            "confidence": best_confidence,
            "reason": (
                f"Low confidence. Best guess: {best_source}. {best_reason}"
            ),
        }

    return {
        "source_type": best_source,
        "confidence": best_confidence,
        "reason": best_reason,
    }


def summarize_event_detection(
    events: List[dict],
    *,
    threshold: float = 0.6,
    mixed_ratio_threshold: float = 0.85,
) -> Dict[str, object]:
    if not events:
        return {
            "source_type": "unknown",
            "confidence": 0.0,
            "reason": "No events provided for detection.",
            "breakdown": [],
        }

    counts = {source_type: 0 for source_type in SCORE_FUNCS}
    counts["unknown"] = 0
    for event in events:
        detection = detect_event(event, threshold=threshold)
        source_type = detection.get("source_type", "unknown")
        if source_type not in counts:
            counts[source_type] = 0
        counts[source_type] += 1

    total = len(events)
    breakdown = []
    for source_type, count in counts.items():
        ratio = count / total if total else 0.0
        breakdown.append(
            {
                "source": source_type,
                "count": count,
                "total": total,
                "ratio": ratio,
            }
        )

    breakdown.sort(key=lambda item: (item["count"], item["source"]), reverse=True)
    top = max(counts.items(), key=lambda item: item[1])
    top_source, top_count = top
    top_ratio = top_count / total if total else 0.0

    if top_ratio >= mixed_ratio_threshold:
        reason = (
            f"Per-event detection matched {top_source} for {top_count}/{total} events."
        )
        return {
            "source_type": top_source,
            "confidence": top_ratio,
            "reason": reason,
            "breakdown": breakdown,
        }

    summary = ", ".join(
        f"{item['source']}={item['count']}" for item in breakdown
    )
    reason = (
        "Mixed-source file: per-event detection found multiple sources. "
        "Conversion routed events per source. "
        f"{summary}"
    )
    return {
        "source_type": "mixed",
        "confidence": 1.0,
        "reason": reason,
        "breakdown": breakdown,
    }
