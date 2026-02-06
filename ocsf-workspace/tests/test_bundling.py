from datetime import datetime, timezone

from app.bundling import TimeWindowBundler, canonical_json, sha256_hex


def test_time_window_bundle_flush_and_manifest_shape() -> None:
    bundler = TimeWindowBundler(window_minutes=5)
    source = {
        "type": "windows_sysmon",
        "vendor": "microsoft",
        "product": "sysmon",
        "channel": "eventlog",
        "host": "host-a",
        "collector": {"name": "collector-a", "instance_id": "inst-1"},
        "ocsf_version": "1.1.0",
    }
    raw_event = {"a": 1}
    ocsf_event = {"class_uid": 1001, "time": "2026-01-01T12:01:10Z", "metadata": {"version": "1.1.0"}}

    bundler.add_event(raw_envelope=raw_event, ocsf_event=ocsf_event, source=source, event_time_utc="2026-01-01T12:01:10Z")

    assert bundler.flush_ready(datetime(2026, 1, 1, 12, 4, 59, tzinfo=timezone.utc)) == []
    flushed = bundler.flush_ready(datetime(2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc))
    assert len(flushed) == 1

    bundle = flushed[0]
    assert bundle.manifest["event_count"] == 1
    assert bundle.manifest["time_window"]["start_utc"] == "2026-01-01T12:00:00Z"
    assert bundle.manifest["time_window"]["end_utc"] == "2026-01-01T12:05:00Z"
    assert bundle.manifest["ocsf"]["class_uid_counts"] == {"1001": 1}
    assert bundle.manifest["storage"]["raw_ref"] == f"local://bundles/{bundle.bundle_id}/raw.ndjson"
    assert bundle.manifest["storage"]["ocsf_ref"] == f"local://bundles/{bundle.bundle_id}/ocsf.ndjson"


def test_bundle_id_is_deterministic_formula() -> None:
    bundler = TimeWindowBundler(window_minutes=5)
    source = {
        "type": "windows_sysmon",
        "vendor": "microsoft",
        "product": "sysmon",
        "channel": "eventlog",
        "host": "host-a",
        "collector": {"name": "collector-a", "instance_id": "inst-1"},
        "ocsf_version": "1.1.0",
    }
    raw_event = {"a": 1}
    ocsf_event = {"class_uid": 1001, "time": "2026-01-01T12:01:10Z", "metadata": {"version": "1.1.0"}}

    bundler.add_event(raw_envelope=raw_event, ocsf_event=ocsf_event, source=source, event_time_utc="2026-01-01T12:01:10Z")
    bundle = bundler.flush_ready(datetime(2026, 1, 1, 12, 5, 0, tzinfo=timezone.utc))[0]

    ocsf_ndjson = canonical_json(ocsf_event) + "\n"
    expected = sha256_hex(
        source["host"]
        + source["type"]
        + "2026-01-01T12:00:00Z"
        + "2026-01-01T12:05:00Z"
        + sha256_hex(ocsf_ndjson)
    )
    assert bundle.bundle_id == expected
