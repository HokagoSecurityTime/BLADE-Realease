"""Pure OpenAPI 3.x parsing; references never trigger file or network access."""

from collections.abc import Callable
from dataclasses import dataclass
import re
from typing import Any

import yaml


@dataclass
class Endpoint:
    method: str
    path: str
    path_params: list[str]
    query_params: list[str]
    operation_id: str | None
    tags: list[str]
    summary: str | None

    def __post_init__(self) -> None:
        # Operation details for the LoRA classifier input (prompt v3.0.1): description, security,
        # security_state, schema_fields. Not a dataclass field, so asdict(), equality, saved
        # contexts and the v2.0 prompt are unchanged. Reconstructed endpoints start empty.
        self.operation: dict[str, Any] = {}


def _schema_fields(operation: dict[str, Any], resolve: Callable[[Any], dict[str, Any]]) -> list[str]:
    """2xx response property names (nested with '.', arrays as '[]'), at most 40, as in the v3.0.1 training inputs."""
    names: list[str] = []

    def visit(node: Any, prefix: str = '', depth: int = 0) -> None:
        if len(names) >= 40 or not isinstance(node, dict) or depth > 8:  # depth bounds recursive schemas
            return
        try:
            node = resolve(node)
        except ValueError:
            return
        for name, value in (node.get('properties') or {}).items():
            if len(names) >= 40:
                return
            if prefix + name not in names:
                names.append(prefix + name)
            visit(value, prefix + name + '.', depth + 1)
        visit(node.get('items'), prefix + '[].', depth + 1)
        for branch in ('allOf', 'oneOf', 'anyOf'):
            for child in node.get(branch, []) or []:
                visit(child, prefix, depth + 1)

    for code, response in (operation.get('responses') or {}).items():
        if not str(code).startswith('2') or not isinstance(response, dict):
            continue
        try:
            response = resolve(response)
        except ValueError:
            continue
        for media in (response.get('content') or {}).values():
            if isinstance(media, dict):
                visit(media.get('schema'))
    return names[:40]


def parse_oas(document: str) -> list[Endpoint]:
    """Parse JSON or YAML text without mutating inputs or performing I/O.

    Missing optional operation metadata becomes None (or an empty tags list).
    Local JSON Pointer references are supported; external/cyclic refs fail.
    """
    root = yaml.safe_load(document)
    if not isinstance(root, dict) or not re.fullmatch(r"3\.\d+\.\d+(?:[-+].*)?", str(root.get("openapi", ""))):
        raise ValueError("Expected an OpenAPI 3.x document")

    def resolve(value: Any, seen: frozenset[str] = frozenset()) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("Expected an OpenAPI object")
        if "$ref" not in value:
            return value
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ValueError("Only document-local references are supported")
        if ref in seen:
            raise ValueError(f"Cyclic reference: {ref}")
        target = root
        try:
            for part in ref[2:].split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"Unresolved reference: {ref}") from exc
        return {**resolve(target, seen | {ref}), **{k: v for k, v in value.items() if k != "$ref"}}

    paths = root.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("paths must be an object")
    endpoints: list[Endpoint] = []
    for path, raw_item in paths.items():
        if str(path).startswith("x-"):
            continue
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Endpoint paths must start with /")
        item = resolve(raw_item)
        for method, raw_operation in item.items():
            if method not in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
                continue
            operation = resolve(raw_operation)
            params: dict[tuple[str, str], dict[str, Any]] = {}
            for source in (item, operation):
                parameters = source.get("parameters", [])
                if not isinstance(parameters, list):
                    raise ValueError("parameters must be an array")
                for raw_parameter in parameters:
                    parameter = resolve(raw_parameter)
                    name, location = parameter.get("name"), parameter.get("in")
                    if not isinstance(name, str) or location not in {"path", "query", "header", "cookie"}:
                        raise ValueError("Invalid parameter name or location")
                    params[(location, name)] = parameter
            path_params = list(dict.fromkeys(re.findall(r"\{([^{}]+)\}", path)))
            for location, name in params:
                if location == "path" and name not in path_params:
                    path_params.append(name)
            tags = operation.get("tags", [])
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                raise ValueError("tags must be an array of strings")
            for key in ("operationId", "summary"):
                if operation.get(key) is not None and not isinstance(operation[key], str):
                    raise ValueError(f"{key} must be a string")
            endpoint = Endpoint(
                method=method.upper(), path=path, path_params=path_params,
                query_params=[name for location, name in params if location == "query"],
                operation_id=operation.get("operationId"), tags=list(tags),
                summary=operation.get("summary"),
            )
            # Same security_state rule as the v3.0.1 training inputs (prepare_lora_inputs.test_record).
            if operation.get("security") == [] and "security" in root:
                security_state = "explicitly_anonymous"
            elif "security" in operation or "security" in root:
                security_state = "declared"
            else:
                security_state = "unknown"
            endpoint.operation = {
                "description": operation.get("description") if isinstance(operation.get("description"), str) else "",
                "security": operation.get("security", root.get("security", [])),
                "security_state": security_state,
                "schema_fields": _schema_fields(operation, resolve),
            }
            endpoints.append(endpoint)
    return endpoints
