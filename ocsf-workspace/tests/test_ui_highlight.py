import json

from app.ui.highlight import HIGHLIGHT_PALETTE, extract_values, highlight_json_text, stable_color_for


def test_stable_color_for_is_deterministic():
    first = stable_color_for("ProcessGuid")
    second = stable_color_for("ProcessGuid")
    assert first == second
    assert first in HIGHLIGHT_PALETTE


def test_shared_values_are_highlighted_in_both_panels():
    shared_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    original_event = {"EventData": {"Image": shared_path}}
    ocsf_event = {"actor": {"process": {"executable": shared_path}}}
    shared_values = extract_values(original_event) & extract_values(ocsf_event)

    original_json = json.dumps(original_event, indent=2)
    ocsf_json = json.dumps(ocsf_event, indent=2)
    original_html = highlight_json_text(original_json, shared_values)
    unified_html = highlight_json_text(ocsf_json, shared_values)

    assert '<span class="hl"' in original_html
    assert '<span class="hl"' in unified_html
    assert shared_path.replace("\\", "\\\\") in original_html
    assert shared_path.replace("\\", "\\\\") in unified_html
