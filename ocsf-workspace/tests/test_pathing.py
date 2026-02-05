from datetime import datetime, timezone
from pathlib import Path

from app.utils.pathing import build_elastic_output_path, build_output_paths


def test_daily_events_path() -> None:
    paths = build_output_paths("out/raw/endpoint/windows_sysmon", "HOST")
    when = datetime(2024, 2, 3, tzinfo=timezone.utc)
    expected = Path("out/raw/endpoint/windows_sysmon/HOST/2024/02/03/events.ndjson")
    assert paths.daily_events_path(when) == expected


def test_daily_security_events_path() -> None:
    paths = build_output_paths("out/raw/endpoint/windows_security", "HOST")
    when = datetime(2024, 4, 5, tzinfo=timezone.utc)
    expected = Path("out/raw/endpoint/windows_security/HOST/2024/04/05/events.ndjson")
    assert paths.daily_events_path(when) == expected


def test_elastic_events_path() -> None:
    when = datetime(2024, 6, 7, tzinfo=timezone.utc)
    expected = Path("out/raw/siem/elastic/local/logs-app/2024/06/07/events.ndjson")
    assert (
        build_elastic_output_path("out/raw/siem/elastic", "logs-app", when) == expected
    )
