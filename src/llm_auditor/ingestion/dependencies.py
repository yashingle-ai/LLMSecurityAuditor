"""Dependency manifests and lockfiles, for checking against known vulnerabilities (SC-02)."""

import json
import re
import tomllib
from pathlib import Path
from typing import Any, Literal

from llm_auditor.ingestion.base import Artifact, IngestReport, as_dict, read_text
from llm_auditor.models import Dependency, DependencyFile

_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_EXACT_PEP440 = re.compile(r"^===?\s*([^\s,;]+)$")
_EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class DependencyFileLoader:
    extensions = frozenset({".txt", ".in", ".toml", ".lock", ".json"})

    def load(self, file: Path, rel: str, report: IngestReport) -> list[Artifact]:
        name = file.name.lower()
        text = read_text(file, rel, report)
        if text is None:
            return []
        try:
            if re.fullmatch(r"(requirements|constraints).*\.(txt|in)", name):
                return [_file(rel, "PyPI", _requirements(text))]
            if name == "pyproject.toml":
                return [_file(rel, "PyPI", _pyproject(tomllib.loads(text)))]
            if name in ("uv.lock", "poetry.lock"):
                return [_file(rel, "PyPI", _locked(tomllib.loads(text).get("package", [])))]
            if name == "package.json":
                return [_file(rel, "npm", _package_json(json.loads(text)))]
            if name == "package-lock.json":
                return [_file(rel, "npm", _package_lock(json.loads(text)))]
        except (tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
            report.warn(rel, f"skipped: could not parse: {str(error).splitlines()[0]}")
            return []
        report.warn(rel, "skipped: not a recognized dependency file")
        return []


def parse_requirement(text: str, line: int | None = None) -> Dependency | None:
    """One PEP 508 requirement (``name[extra]==1.2; marker``), or None for options and URLs."""
    requirement = text.split("#", 1)[0].split(";", 1)[0].strip()
    if not requirement or requirement.startswith(("-", "git+", "http:", "https:", "file:")):
        return None
    match = _REQUIREMENT.match(requirement)
    if match is None:
        return None
    spec = match[2].strip()
    exact = _EXACT_PEP440.match(spec)
    return Dependency(name=match[1], version=exact[1] if exact else None, spec=spec, line=line)


def _file(
    rel: str, ecosystem: Literal["PyPI", "npm"], dependencies: list[Dependency]
) -> DependencyFile:
    return DependencyFile(path=rel, ecosystem=ecosystem, dependencies=tuple(dependencies))


def _requirements(text: str) -> list[Dependency]:
    found = (parse_requirement(line, number) for number, line in enumerate(text.splitlines(), 1))
    return [dependency for dependency in found if dependency is not None]


def _pyproject(data: dict[str, Any]) -> list[Dependency]:
    project = as_dict(data.get("project"))
    requirements = list(project.get("dependencies") or [])
    for extra in as_dict(project.get("optional-dependencies")).values():
        requirements += list(extra or [])
    found = (parse_requirement(str(r)) for r in requirements)
    return [dependency for dependency in found if dependency is not None]


def _locked(packages: Any) -> list[Dependency]:
    entries = packages if isinstance(packages, list) else []
    return [
        Dependency(name=str(p["name"]), version=str(p["version"]), spec=f"=={p['version']}")
        for p in entries
        if isinstance(p, dict) and "name" in p and "version" in p
    ]


def _package_json(data: dict[str, Any]) -> list[Dependency]:
    dependencies = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in as_dict(data.get(section)).items():
            exact = isinstance(spec, str) and _EXACT_SEMVER.match(spec)
            dependencies.append(
                Dependency(name=name, version=spec if exact else None, spec=str(spec))
            )
    return dependencies


def _package_lock(data: dict[str, Any]) -> list[Dependency]:
    dependencies = []
    for key, entry in as_dict(data.get("packages")).items():
        if key and isinstance(entry, dict) and isinstance(entry.get("version"), str):
            name = key.rsplit("node_modules/", 1)[-1]
            version = entry["version"]
            dependencies.append(Dependency(name=name, version=version, spec=version))
    return dependencies
