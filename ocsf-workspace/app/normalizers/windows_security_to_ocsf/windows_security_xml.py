from __future__ import annotations

from typing import Dict
from xml.etree import ElementTree


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
        data[name] = child.text or ""
    return data


def parse_system_data(xml: str) -> Dict[str, str]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {}
    namespace = ""
    if "}" in root.tag:
        namespace = root.tag.split("}")[0].strip("{")
    ns = {"e": namespace} if namespace else {}
    system = root.find("e:System", ns) if ns else root.find("System")
    if system is None:
        return {}
    data: Dict[str, str] = {}
    record_id = system.findtext("e:EventRecordID", namespaces=ns) if ns else system.findtext("EventRecordID")
    if record_id:
        data["record_id"] = record_id
    event_id = system.findtext("e:EventID", namespaces=ns) if ns else system.findtext("EventID")
    if event_id:
        data["event_id"] = event_id
    computer = system.findtext("e:Computer", namespaces=ns) if ns else system.findtext("Computer")
    if computer:
        data["computer"] = computer
    time_node = system.find("e:TimeCreated", ns) if ns else system.find("TimeCreated")
    if time_node is not None:
        time_value = time_node.attrib.get("SystemTime")
        if time_value:
            data["time_created"] = time_value
    return data
