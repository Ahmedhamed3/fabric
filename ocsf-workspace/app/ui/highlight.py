from __future__ import annotations

import hashlib
import html
import json
from typing import Iterable, List, Set

HIGHLIGHT_PALETTE = [
    "#fde68a",
    "#a7f3d0",
    "#bfdbfe",
    "#fecaca",
    "#e9d5ff",
    "#fbcfe8",
    "#bae6fd",
    "#bbf7d0",
]


def extract_values(obj: object, path: tuple[str, ...] = ()) -> Set[str]:
    values: Set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "original_event" and path and path[-1] == "unmapped":
                continue
            values.update(extract_values(value, path + (str(key),)))
    elif isinstance(obj, list):
        for item in obj:
            values.update(extract_values(item, path))
    elif isinstance(obj, str):
        candidate = obj.strip()
        if len(candidate) >= 4:
            values.add(candidate)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        if isinstance(obj, int):
            abs_value = abs(obj)
            if abs_value >= 1024 or len(str(abs_value)) >= 4:
                values.add(str(obj))
        elif abs(obj) >= 1024:
            values.add(str(obj))
    return values


def stable_color_for(value: str, palette: Iterable[str] = HIGHLIGHT_PALETTE) -> str:
    colors = list(palette)
    if not colors:
        raise ValueError("Palette must include at least one color.")
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()
    index = int(digest[:8], 16) % len(colors)
    return colors[index]


def _collect_unmapped_original_events(obj: object, path: tuple[str, ...] = ()) -> List[str]:
    preserved: List[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "original_event" and path and path[-1] == "unmapped" and isinstance(value, str):
                preserved.append(value)
                continue
            preserved.extend(_collect_unmapped_original_events(value, path + (str(key),)))
    elif isinstance(obj, list):
        for item in obj:
            preserved.extend(_collect_unmapped_original_events(item, path))
    return preserved


def highlight_json_text(
    json_text: str,
    shared_values: Set[str],
    preserve_values: Iterable[str] = (),
) -> str:
    highlighted = html.escape(json_text)
    placeholders = {}
    for index, value in enumerate(preserve_values):
        if not value:
            continue
        safe_value = html.escape(json.dumps(value, ensure_ascii=False)[1:-1])
        placeholder = f"__PRESERVE_{index}__"
        highlighted = highlighted.replace(safe_value, placeholder)
        placeholders[placeholder] = safe_value
    for value in sorted(shared_values, key=len, reverse=True):
        if not value:
            continue
        safe_value = html.escape(json.dumps(value, ensure_ascii=False)[1:-1])
        highlighted = highlighted.replace(
            safe_value,
            f'<span class="hl" style="background-color: {stable_color_for(value)}">{safe_value}</span>',
        )
    for placeholder, safe_value in placeholders.items():
        highlighted = highlighted.replace(placeholder, safe_value)
    return highlighted


def collect_unmapped_original_events(obj: object) -> List[str]:
    return _collect_unmapped_original_events(obj)
