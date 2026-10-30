"""OpenAPI 3 specs (YAML or JSON). ``$ref`` is not resolved."""

from pathlib import Path
from typing import Any

from pydantic import ValidationError

from llm_auditor.ingestion.base import (
    Artifact,
    FormatError,
    IngestReport,
    as_dict,
    describe,
    expect_dict,
    optional_str,
    read_structured,
)
from llm_auditor.models import ApiOperation, ApiSpec

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class OpenApiLoader:
    extensions = frozenset({".yaml", ".yml", ".json"})

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        data = read_structured(file, rel, report)
        if data is None:
            return []
        version = data.get("openapi") if isinstance(data, dict) else None
        if (
            not isinstance(data, dict)
            or not isinstance(version, str)
            or not version.startswith("3.")
        ):
            hint = (
                " (Swagger 2 is not supported)"
                if isinstance(data, dict) and "swagger" in data
                else ""
            )
            report.warn(rel, f"skipped: not an OpenAPI 3 document{hint}")
            return []
        try:
            return [_spec(data, rel, version, report)]
        except (FormatError, ValidationError) as error:
            report.warn(rel, f"skipped: {describe(error)}")
            return []


def _spec(data: dict[str, Any], rel: str, version: str, report: IngestReport) -> ApiSpec:
    info, components = as_dict(data.get("info")), as_dict(data.get("components"))
    servers = data.get("servers")
    return ApiSpec(
        path=rel,
        openapi_version=version,
        title=optional_str(info.get("title")),
        servers=tuple(
            s["url"]
            for s in (servers if isinstance(servers, list) else [])
            if isinstance(s, dict) and isinstance(s.get("url"), str)
        ),
        security_schemes=expect_dict(components.get("securitySchemes") or {}, "securitySchemes"),
        security=data.get("security") or [],
        operations=tuple(_operations(data.get("paths"), rel, report)),
    )


def _operations(paths: Any, rel: str, report: IngestReport) -> list[ApiOperation]:
    operations = []
    for path, item in (paths or {}).items() if isinstance(paths, dict) else []:
        for method in HTTP_METHODS:
            operation = item.get(method) if isinstance(item, dict) else None
            if not isinstance(operation, dict):
                continue
            try:
                operations.append(
                    ApiOperation(
                        method=method.upper(),
                        path=str(path),
                        operation_id=optional_str(operation.get("operationId")),
                        security=operation.get("security"),
                    )
                )
            except ValidationError as error:
                report.warn(rel, f"{method.upper()} {path} skipped: {describe(error)}")
    return operations
