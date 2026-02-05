import json
from typing import Iterable, Iterator

from app.plugins.azure_ad_signin.map_to_ocsf import map_azure_ad_signin_to_ocsf
from app.plugins.azure_ad_signin.parse import (
    iter_azure_ad_signin_events,
    iter_azure_ad_signin_events_from_events,
)


def convert_azure_ad_signin_file_to_ocsf_jsonl(file_path: str) -> Iterator[str]:
    for ev in iter_azure_ad_signin_events(file_path):
        out = map_azure_ad_signin_to_ocsf(ev)
        if out:
            yield json.dumps(out, ensure_ascii=False)


def convert_azure_ad_signin_events_to_ocsf_jsonl(events: Iterable[dict]) -> Iterator[str]:
    for ev in iter_azure_ad_signin_events_from_events(events):
        out = map_azure_ad_signin_to_ocsf(ev)
        if out:
            yield json.dumps(out, ensure_ascii=False)
