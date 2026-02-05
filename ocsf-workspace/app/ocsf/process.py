import os
from typing import Any, Dict, Optional

from app.ocsf.constants import DEFAULT_FILE_TYPE_ID


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.basename(path)


def build_process(
    *,
    pid: Optional[int] = None,
    uid: Optional[str] = None,
    executable: Optional[str] = None,
    command_line: Optional[str] = None,
    include_file: bool = True,
) -> Dict[str, Any]:
    process: Dict[str, Any] = {}
    if pid is not None:
        process["pid"] = pid
    if uid:
        process["uid"] = uid
    if command_line:
        process["command_line"] = command_line
    if executable:
        process["executable"] = executable
        if include_file:
            fname = _basename(executable)
            process["file"] = {
                "name": fname or "unknown",
                "type_id": DEFAULT_FILE_TYPE_ID,
                "path": executable,
            }
    return process


def build_parent_process(
    *,
    pid: Optional[int] = None,
    uid: Optional[str] = None,
    executable: Optional[str] = None,
    command_line: Optional[str] = None,
) -> Dict[str, Any]:
    return build_process(
        pid=pid,
        uid=uid,
        executable=executable,
        command_line=command_line,
        include_file=False,
    )
