from __future__ import annotations

import re
from typing import Dict, Iterable, List

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


def hash_token(token: str) -> int:
    hash_value = 0
    for char in token:
        hash_value = (hash_value << 5) - hash_value + ord(char)
        hash_value &= 0xFFFFFFFF
    if hash_value & 0x80000000:
        hash_value -= 0x100000000
    return hash_value


def assign_token_color(token: str, palette: Iterable[str] = HIGHLIGHT_PALETTE) -> str:
    colors = list(palette)
    if not colors:
        raise ValueError("Palette must include at least one color.")
    index = abs(hash_token(token)) % len(colors)
    return colors[index]


def escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def mark_tokens(text: str, token_to_color: Dict[str, str]) -> str:
    highlighted = escape_html(text)
    sorted_tokens: List[str] = sorted(token_to_color.keys(), key=len, reverse=True)
    for token in sorted_tokens:
        if not token:
            continue
        safe_token = escape_html(token)
        pattern = re.escape(safe_token)
        highlighted = re.sub(
            pattern,
            f'<mark class="highlight" style="background: {token_to_color[token]};">{safe_token}</mark>',
            highlighted,
        )
    return highlighted
