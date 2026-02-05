import json
from typing import Iterable, Iterator

from app.plugins.file_artifact.parse import (
    iter_file_artifact_events,
    iter_file_artifact_events_from_records,
)
from app.plugins.file_artifact.map_to_ocsf import map_file_artifact_to_ocsf


def convert_file_artifact_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_file_artifact_events(file_path):
        out = map_file_artifact_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)


def convert_file_artifact_events_to_ocsf_jsonl(
    events: Iterable[dict],
) -> Iterator[str]:
    for ev in iter_file_artifact_events_from_records(events):
        out = map_file_artifact_to_ocsf(ev)
        yield json.dumps(out, ensure_ascii=False)
