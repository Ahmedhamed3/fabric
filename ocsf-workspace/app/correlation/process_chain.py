from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class ProcessBehaviorChain:
    process_uid: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    parent_process_uid: Optional[str] = None


def _extract_process_uid(event: Dict[str, Any]) -> Optional[str]:
    actor_process = event.get("actor", {}).get("process", {})
    if isinstance(actor_process, dict):
        uid = actor_process.get("uid")
        if uid:
            return uid

    process = event.get("process", {})
    if isinstance(process, dict):
        uid = process.get("uid")
        if uid:
            return uid

    return None


def _extract_parent_process_uid(event: Dict[str, Any]) -> Optional[str]:
    actor_process = event.get("actor", {}).get("process", {})
    if isinstance(actor_process, dict):
        parent = actor_process.get("parent_process", {})
        if isinstance(parent, dict):
            uid = parent.get("uid")
            if uid:
                return uid

    process = event.get("process", {})
    if isinstance(process, dict):
        parent = process.get("parent_process", {})
        if isinstance(parent, dict):
            uid = parent.get("uid")
            if uid:
                return uid

    return None


def _sort_events_by_time(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    indexed_events = list(enumerate(events))

    def _key(item: tuple[int, Dict[str, Any]]) -> tuple[bool, str, int]:
        index, event = item
        time_value = event.get("time")
        if time_value is None:
            return True, "", index
        return False, str(time_value), index

    indexed_events.sort(key=_key)
    return [event for _, event in indexed_events]


def build_process_chains(events: List[Dict[str, Any]]) -> List[ProcessBehaviorChain]:
    chains: Dict[str, ProcessBehaviorChain] = {}

    for event in events:
        process_uid = _extract_process_uid(event)
        if not process_uid:
            continue

        chain = chains.get(process_uid)
        if chain is None:
            chain = ProcessBehaviorChain(process_uid=process_uid)
            chains[process_uid] = chain

        parent_uid = _extract_parent_process_uid(event)
        if parent_uid and not chain.parent_process_uid:
            chain.parent_process_uid = parent_uid

        chain.events.append(event)

    for chain in chains.values():
        chain.events = _sort_events_by_time(chain.events)

    return list(chains.values())
