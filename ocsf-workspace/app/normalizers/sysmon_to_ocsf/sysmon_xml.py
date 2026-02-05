from __future__ import annotations

from xml.etree import ElementTree
from typing import Dict


def parse_event_data(xml: str) -> Dict[str, str]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {}
    namespace = ""
    if "}" in root.tag:
        namespace = root.tag.split("}")[0].strip("{")
    ns = {"e": namespace} if namespace else {}
    event_data = root.find("e:EventData", ns) if ns else root.find("EventData")
    if event_data is None:
        return {}
    data: Dict[str, str] = {}
    for child in event_data.findall("e:Data", ns) if ns else event_data.findall("Data"):
        name = child.attrib.get("Name")
        if not name:
            continue
        text = child.text or ""
        data[name] = text
    return data


def parse_system_time(xml: str) -> str | None:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None
    namespace = ""
    if "}" in root.tag:
        namespace = root.tag.split("}")[0].strip("{")
    ns = {"e": namespace} if namespace else {}
    system = root.find("e:System", ns) if ns else root.find("System")
    if system is None:
        return None
    time_node = system.find("e:TimeCreated", ns) if ns else system.find("TimeCreated")
    if time_node is None:
        return None
    return time_node.attrib.get("SystemTime")
