from __future__ import annotations

from pathlib import Path
from typing import Optional

from app.normalizers.sysmon_to_ocsf.validator import OcsfSchemaLoader


_OCSF_SCHEMA_LOADER: Optional[OcsfSchemaLoader] = None


def get_ocsf_schema_loader() -> OcsfSchemaLoader:
    global _OCSF_SCHEMA_LOADER
    if _OCSF_SCHEMA_LOADER is None:
        _OCSF_SCHEMA_LOADER = OcsfSchemaLoader(Path("app/ocsf_schema"))
    return _OCSF_SCHEMA_LOADER
