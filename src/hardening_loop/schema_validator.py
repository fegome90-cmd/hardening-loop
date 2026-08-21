"""Deterministic fail-closed JSON Schema validation for all hardening artifacts."""

from __future__ import annotations

import json
import os
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker
from jsonschema.protocols import Validator


class SchemaValidationError(Exception):
    """Raised when an artifact or payload violates its normative JSON Schema."""

    def __init__(self, schema_name: str, errors: list[str], payload: dict[str, Any] | None = None):
        self.schema_name = schema_name
        self.errors = errors
        self.payload = payload
        error_summary = "; ".join(errors)
        super().__init__(f"[FAIL-CLOSED] Schema validation failed for '{schema_name}': {error_summary}")


_SCHEMA_CACHE: dict[str, dict[str, Any]] = {}


def get_schemas_dir() -> str:
    """Resolves the directory containing normative JSON Schemas."""
    # 1. Check relative to package location in repository
    current_dir = os.path.dirname(os.path.abspath(__file__))
    repo_schemas = os.path.abspath(os.path.join(current_dir, "..", "..", "schemas"))
    if os.path.isdir(repo_schemas):
        return repo_schemas

    # 2. Check current working directory
    cwd_schemas = os.path.abspath("schemas")
    if os.path.isdir(cwd_schemas):
        return cwd_schemas

    raise FileNotFoundError(f"Could not locate normative schemas directory (checked {repo_schemas} and {cwd_schemas}).")


def _validator_class_for(raw_schema: dict[str, Any]) -> type[Validator]:
    """Selects the jsonschema validator class from the schema's declared $schema dialect."""
    declared = str(raw_schema.get("$schema", "") or "")
    if "2020-12" in declared:
        return Draft202012Validator
    return Draft7Validator


def load_schema(schema_name: str) -> dict[str, Any]:
    """Loads and caches a JSON Schema by canonical name."""
    clean_name = schema_name.replace(".schema.json", "").replace(".json", "")
    if clean_name in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[clean_name]

    schemas_dir = get_schemas_dir()
    candidates = [f"{clean_name}.schema.json", f"{clean_name}.json"]
    tried_paths = [os.path.join(schemas_dir, candidate) for candidate in candidates]
    schema_path = next((path for path in tried_paths if os.path.isfile(path)), None)
    if schema_path is None:
        raise FileNotFoundError("Normative schema file not found; tried: " + ", ".join(tried_paths))

    with open(schema_path, encoding="utf-8") as f:
        raw_schema = json.load(f)

    if not isinstance(raw_schema, dict):
        raise ValueError(f"Schema at {schema_path} must be a JSON object, got {type(raw_schema).__name__}")

    _validator_class_for(raw_schema).check_schema(raw_schema)
    _SCHEMA_CACHE[clean_name] = raw_schema
    return raw_schema


def validate_payload(data: dict[str, Any], schema_name: str) -> None:
    """Validates a payload against a normative JSON Schema in strict fail-closed mode."""
    schema = load_schema(schema_name)
    validator = _validator_class_for(schema)(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)

    if errors:
        error_msgs = []
        for err in errors:
            path_str = ".".join(str(p) for p in err.path) if err.path else "root"
            error_msgs.append(f"at '{path_str}': {err.message}")
        raise SchemaValidationError(schema_name=schema_name, errors=error_msgs, payload=data)


class SchemaValidator:
    """Convenience wrapper for schema validation."""

    @staticmethod
    def validate_or_raise(schema_name: str, data: dict[str, Any]) -> None:
        validate_payload(data, schema_name)
