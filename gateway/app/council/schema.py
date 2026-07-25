"""Pydantic -> Anthropic structured-outputs JSON Schema.

The structured-outputs subset is narrower than what Pydantic emits: numeric and
string constraints are unsupported, every object must set
`additionalProperties: false`, and every property must appear in `required`.
Pydantic marks defaulted fields optional, so we widen `required` ourselves and
let the model emit the default value explicitly.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

# Keywords the structured-outputs validator rejects or ignores.
_STRIP = {
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
    "default",
}


def _sanitize(node: Any) -> Any:
    if isinstance(node, list):
        return [_sanitize(n) for n in node]
    if not isinstance(node, dict):
        return node

    out: dict[str, Any] = {k: _sanitize(v) for k, v in node.items() if k not in _STRIP}

    if out.get("type") == "object" or "properties" in out:
        out["type"] = "object"
        props = out.get("properties", {})
        out["additionalProperties"] = False
        # Structured outputs requires every property to be required.
        out["required"] = list(props.keys())
    return out


def strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    return _sanitize(model.model_json_schema())


def output_format(model: type[BaseModel]) -> dict[str, Any]:
    return {"type": "json_schema", "schema": strict_schema(model)}
