from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import jsonschema


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: List[str]


class OcsfSchemaLoader:
    def __init__(self, schema_root: Path) -> None:
        self.schema_root = schema_root
        self._dictionary = self._load_json(schema_root / "dictionary.json")
        self._version = self._load_json(schema_root / "version.json")["version"]
        self._object_cache: Dict[str, Dict[str, Any]] = {}
        self._object_stack: set[str] = set()

    @property
    def version(self) -> str:
        return self._version

    def validate_event(self, event: Dict[str, Any], class_path: str) -> ValidationResult:
        schema = self._event_schema(class_path)
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(event), key=lambda err: err.path)
        if not errors:
            return ValidationResult(True, [])
        messages = [self._format_error(err) for err in errors]
        return ValidationResult(False, messages)

    def _format_error(self, error: jsonschema.ValidationError) -> str:
        path = ".".join(str(part) for part in error.path)
        if path:
            return f"{path}: {error.message}"
        return error.message

    def _event_schema(self, class_path: str) -> Dict[str, Any]:
        return self._build_event_schema(class_path)

    @lru_cache(maxsize=None)
    def _build_event_schema(self, class_path: str) -> Dict[str, Any]:
        event_path = self.schema_root / "events" / f"{class_path}.json"
        event_def = self._load_json(event_path)
        category_dir = Path(class_path).parent
        chain = self._resolve_event_chain(event_def, category_dir)
        attributes = self._merge_attributes(chain)
        properties, required = self._build_properties(attributes)
        schema: Dict[str, Any] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = sorted(required)
        constraints = self._merge_constraints(chain)
        if constraints:
            schema.update(constraints)
        return schema

    def _resolve_event_chain(self, event_def: Dict[str, Any], category_dir: Path) -> List[Dict[str, Any]]:
        chain = [event_def]
        extends = event_def.get("extends")
        while extends:
            base_path = self.schema_root / "events" / f"{extends}.json"
            if not base_path.exists():
                nested_path = self.schema_root / "events" / category_dir / f"{extends}.json"
                if nested_path.exists():
                    base_path = nested_path
            base = self._load_json(base_path)
            chain.append(base)
            extends = base.get("extends")
        return list(reversed(chain))

    def _merge_attributes(self, chain: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        for definition in chain:
            attrs = definition.get("attributes") or {}
            merged.update(self._expand_attributes(attrs))
        return merged

    def _merge_constraints(self, chain: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        constraints = []
        for definition in chain:
            definition_constraints = definition.get("constraints") or {}
            if "at_least_one" in definition_constraints:
                constraints.append(definition_constraints["at_least_one"])
        if not constraints:
            return {}
        any_of = []
        for group in constraints:
            for attr in group:
                any_of.append({"required": [attr]})
        return {"anyOf": any_of}

    def _expand_attributes(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        includes = attrs.get("$include") or []
        expanded: Dict[str, Any] = {k: v for k, v in attrs.items() if k != "$include"}
        for include in includes:
            if include.startswith("profiles/"):
                profile = self._load_json(self.schema_root / include)
                expanded.update(self._normalize_profile_attributes(profile.get("attributes") or {}))
        return expanded

    def _normalize_profile_attributes(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        normalized: Dict[str, Any] = {}
        for key, value in attrs.items():
            if key == "$include":
                continue
            attr = dict(value)
            if attr.get("requirement") == "required":
                attr["requirement"] = "optional"
            normalized[key] = attr
        return normalized

    def _build_properties(self, attributes: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for name, attr in attributes.items():
            properties[name] = self._attribute_schema(name, attr)
            if attr.get("requirement") == "required":
                required.append(name)
        return properties, required

    def _attribute_schema(self, name: str, attr: Dict[str, Any]) -> Dict[str, Any]:
        dictionary_attr = self._dictionary["attributes"].get(name, {})
        type_name = attr.get("type") or dictionary_attr.get("type") or "object"
        schema = self._type_schema(type_name, dictionary_attr)
        attr_enum = attr.get("enum")
        if name in {"category_uid", "class_uid"} and attr_enum and set(attr_enum.keys()) == {"0"}:
            attr_enum = None
        schema = self._apply_enum(schema, dictionary_attr, attr_enum)
        if attr.get("is_array") or dictionary_attr.get("is_array"):
            schema = {"type": "array", "items": schema}
        return schema

    def _object_schema(self, object_name: str) -> Dict[str, Any]:
        cached = self._object_cache.get(object_name)
        if cached is not None:
            return cached
        if object_name in self._object_stack:
            return {"type": "object"}
        self._object_stack.add(object_name)
        obj_def = self._load_json(self.schema_root / "objects" / f"{object_name}.json")
        chain = self._resolve_object_chain(obj_def)
        attributes = self._merge_object_attributes(chain)
        properties, required = self._build_properties(attributes)
        schema: Dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = sorted(required)
        constraints = self._merge_object_constraints(chain)
        if constraints:
            schema.update(constraints)
        self._object_stack.remove(object_name)
        self._object_cache[object_name] = schema
        return schema

    def _resolve_object_chain(self, obj_def: Dict[str, Any]) -> List[Dict[str, Any]]:
        chain = [obj_def]
        extends = obj_def.get("extends")
        while extends:
            base_path = self.schema_root / "objects" / f"{extends}.json"
            if not base_path.exists():
                break
            base = self._load_json(base_path)
            chain.append(base)
            extends = base.get("extends")
        return list(reversed(chain))

    def _merge_object_attributes(self, chain: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        merged: Dict[str, Any] = {}
        for definition in chain:
            attrs = definition.get("attributes") or {}
            merged.update(self._expand_attributes(attrs))
        return merged

    def _merge_object_constraints(self, chain: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        constraints = []
        for definition in chain:
            definition_constraints = definition.get("constraints") or {}
            if "at_least_one" in definition_constraints:
                constraints.append(definition_constraints["at_least_one"])
        if not constraints:
            return {}
        any_of = []
        for group in constraints:
            for attr in group:
                any_of.append({"required": [attr]})
        return {"anyOf": any_of}

    def _type_schema(self, type_name: str, dictionary_attr: Dict[str, Any]) -> Dict[str, Any]:
        if type_name == "object":
            return {"type": "object"}
        if type_name in self._object_types():
            return self._object_schema(type_name)
        if type_name == "json_t":
            return {"type": "object"}
        if type_name == "boolean_t":
            return {"type": "boolean"}
        if type_name == "timestamp_t":
            return {"type": "string", "format": "date-time"}
        if type_name in {
            "integer_t",
            "long_t",
            "short_t",
            "unsigned_long_t",
            "unsigned_integer_t",
            "port_t",
        }:
            return self._apply_enum({"type": "integer"}, dictionary_attr)
        if type_name in {"float_t", "double_t", "number_t"}:
            return {"type": "number"}
        if type_name.endswith("_t"):
            return self._apply_enum({"type": "string"}, dictionary_attr)
        return self._apply_enum({"type": "string"}, dictionary_attr)

    def _apply_enum(
        self,
        schema: Dict[str, Any],
        dictionary_attr: Dict[str, Any],
        attr_enum: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        enum_def = attr_enum or dictionary_attr.get("enum")
        if not enum_def:
            return schema
        values = []
        for key in enum_def.keys():
            try:
                values.append(int(key))
            except ValueError:
                values.append(key)
        schema = dict(schema)
        schema["enum"] = values
        return schema

    @lru_cache(maxsize=None)
    def _object_types(self) -> set[str]:
        return {path.stem for path in (self.schema_root / "objects").glob("*.json")}

    def _load_json(self, path: Path) -> Dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))
