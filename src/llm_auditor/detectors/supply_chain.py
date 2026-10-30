"""Supply-chain checks: SC-01 (model files), SC-02 (dependencies), SC-03 (MCP installs)."""

import pickletools
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import IO, ClassVar

from llm_auditor.advisories import AdvisoryDb, builtin_db, load_db
from llm_auditor.checks import CheckUnavailable, Detection, register
from llm_auditor.detectors._text import find_line
from llm_auditor.ingestion import AuditContext
from llm_auditor.models import (
    Access,
    Boundary,
    CheckMeta,
    FindingKind,
    IngestIssue,
    InputKind,
    Location,
    McpServerConfig,
    Surface,
)

# Imports a pickle can make that run code or touch the system when it's loaded.
DANGEROUS_MODULES = frozenset(
    {"os", "posix", "nt", "subprocess", "sys", "runpy", "socket", "shutil", "pty", "commands"}
    | {"webbrowser", "importlib", "code", "ctypes", "marshal", "pickle", "_pickle", "requests"}
)
DANGEROUS_BUILTINS = frozenset(
    {"eval", "exec", "compile", "getattr", "__import__", "open", "apply"}
)
PICKLE_FORMATS = ("pickle", "pytorch")
# A STACK_GLOBAL whose module or name isn't a plain string, i.e. one built to hide.
UNRESOLVED_IMPORT = "<unresolved import>"
_MARK = object()


def pickle_imports(stream: IO[bytes]) -> list[str]:
    """Every ``module.name`` a pickle imports, read from its opcodes. Nothing is unpickled.

    STACK_GLOBAL takes its module and name off the stack, often fetched back from the
    memo, so this tracks the stack and memo (strings only; other values are None).
    """
    imports: list[str] = []
    stack: list[object] = []
    memo: dict[object, object] = {}  # PUT and GET arguments are memo keys
    for opcode, argument, _ in pickletools.genops(stream):
        name = opcode.name
        if name in ("MEMOIZE", "PUT", "BINPUT", "LONG_BINPUT"):
            memo[len(memo) if name == "MEMOIZE" else argument] = stack[-1] if stack else None
            continue
        popped = _pop(stack, opcode.stack_before)
        pushed: object = None
        if name in ("GLOBAL", "INST"):
            module, _, attribute = str(argument).partition(" ")
            imports.append(f"{module}.{attribute}")
        elif name == "STACK_GLOBAL":
            parts = popped[-2:]
            resolved = len(parts) == 2 and all(isinstance(part, str) for part in parts)
            imports.append(f"{parts[0]}.{parts[1]}" if resolved else UNRESOLVED_IMPORT)
        elif name in ("GET", "BINGET", "LONG_BINGET"):
            pushed = memo.get(argument)
        elif name == "DUP":
            pushed = popped[-1] if popped else None
        elif isinstance(argument, str):
            pushed = argument
        for item in opcode.stack_after:
            stack.append(_MARK if item is pickletools.markobject else pushed)
    return imports


def _pop(stack: list[object], wanted: list[pickletools.StackObject]) -> list[object]:
    """Pop what an opcode consumes. A mark consumes everything above the topmost MARK."""
    if pickletools.markobject not in wanted:
        start = max(len(stack) - len(wanted), 0)
    else:
        marks = [index for index, item in enumerate(stack) if item is _MARK]
        start = marks[-1] if marks else 0
        stack[start:] = [item for item in stack[start:] if item is not _MARK]
        start = max(start - wanted.index(pickletools.markobject), 0)
    popped = stack[start:]
    del stack[start:]
    return popped


def is_dangerous(qualified: str) -> bool:
    if qualified == UNRESOLVED_IMPORT:
        return True
    module, _, name = qualified.rpartition(".")
    root = module.split(".")[0]
    return root in DANGEROUS_MODULES or (
        root in ("builtins", "__builtin__") and name in DANGEROUS_BUILTINS
    )


def model_imports(path: Path) -> list[str]:
    """Imports in a pickle file, or in the pickles inside a PyTorch zip archive."""
    if zipfile.is_zipfile(path):
        imports: list[str] = []
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if member.endswith(".pkl"):
                    with archive.open(member) as stream:
                        imports += pickle_imports(stream)
        return imports
    with path.open("rb") as stream:
        return pickle_imports(stream)


@register
class UnsafeModelFile:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="SC-01",
        title="Model file can run code when it's loaded",
        surface=Surface.SUPPLY_CHAIN,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.MODEL_DIRS,),
        boundaries=(Boundary.B8,),
        maps_to=("LLM03", "ASI04"),
        base_impact=9,
        remediation=(
            "Don't load this file. Get the model in safetensors (or another format that holds "
            "only data), from a source you trust, and load pickles only with weights_only=True "
            "or not at all."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for model in context.artifacts.model_files:
            if model.format not in PICKLE_FORMATS:
                continue
            location = Location(file=model.path)
            try:
                imports = model_imports(context.scope.root / model.path)
            except (ValueError, OSError, zipfile.BadZipFile, EOFError) as error:
                issue = IngestIssue(path=model.path, message=f"could not read the pickle: {error}")
                context.issues.append(issue)
                continue
            dangerous = sorted({name for name in imports if is_dangerous(name)})
            if dangerous:
                yield Detection(
                    title=f"Model file runs code when loaded (imports {', '.join(dangerous)})",
                    location=location,
                    evidence=f"{model.format} file imports: {', '.join(dict.fromkeys(imports))}",
                    confidence=0.95,
                )
            else:
                yield Detection(
                    title="Model file uses a pickle-based format that can run code when loaded",
                    location=location,
                    evidence=f"{model.format} file, {model.size_bytes} bytes; no dangerous imports",
                    confidence=0.6,
                    kind=FindingKind.HARDENING,
                )


@register
class VulnerableDependency:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="SC-02",
        title="LLM framework dependency with known vulnerabilities",
        surface=Surface.SUPPLY_CHAIN,
        kind=FindingKind.WEAKNESS,
        min_access=Access.WHITE,
        inputs=(InputKind.DEPENDENCY_FILES,),
        boundaries=(Boundary.B8,),
        maps_to=("LLM03", "ASI04"),
        base_impact=7,
        remediation=(
            "Upgrade to a version without known vulnerabilities, pin it exactly, and refresh "
            "the advisory snapshot regularly (`llmaudit advisories update`)."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        db = _advisory_db(context)
        for file in context.artifacts.dependency_files:
            text = context.read_text(file.path) or ""
            for dependency in file.dependencies:
                if not db.watches(file.ecosystem, dependency.name):
                    continue
                location = Location(
                    file=file.path, line=dependency.line or find_line(text, f'"{dependency.name}"')
                )
                if dependency.version is None:
                    yield Detection(
                        title=f"{dependency.name} isn't pinned, so it can't be checked for "
                        "known vulnerabilities",
                        location=location,
                        evidence=f"{dependency.name} {dependency.spec or '(any version)'}",
                        confidence=0.6,
                        kind=FindingKind.HARDENING,
                    )
                    continue
                found = db.affecting(file.ecosystem, dependency.name, dependency.version)
                if found:
                    listed = "; ".join(
                        f"{a.id}{f' ({a.aliases[0]})' if a.aliases else ''}: {a.summary}"
                        for a in found[:8]
                    )
                    more = f"; and {len(found) - 8} more" if len(found) > 8 else ""
                    yield Detection(
                        title=f"{dependency.name} {dependency.version} has {len(found)} known "
                        f"vulnerabilit{'y' if len(found) == 1 else 'ies'}",
                        location=location,
                        evidence=f"{listed}{more} (OSV snapshot of {db.fetched})",
                        confidence=0.95,
                    )


def _advisory_db(context: AuditContext) -> AdvisoryDb:
    if context.scope.advisory_db is None:
        return builtin_db()
    path = context.scope.root / context.scope.advisory_db
    try:
        return load_db(path)
    except (OSError, ValueError) as error:
        raise CheckUnavailable(f"can't read the advisory database {path}: {error}") from error


PACKAGE_RUNNERS = {"npx": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "PyPI"}
VALUE_FLAGS = frozenset(
    {"-e", "--env", "-v", "--volume", "--name", "--network", "-p", "--publish", "-w"}
    | {"--workdir", "--entrypoint", "-u", "--user", "--from", "-p", "--package"}
)
NON_PUBLIC_HOST = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|[^.]+|.*\.(local|internal))$")


@register
class UnpinnedMcpServer:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="SC-03",
        title="MCP server installed unpinned or reached over plain HTTP",
        surface=Surface.SUPPLY_CHAIN,
        kind=FindingKind.WEAKNESS,
        min_access=Access.GRAY,
        inputs=(InputKind.MCP_CONFIGS,),
        boundaries=(Boundary.B7,),
        maps_to=("ASI04", "LLM03"),
        base_impact=6,
        remediation=(
            "Pin every MCP server to an exact, reviewed version (package@1.2.3, an image "
            "digest) or vendor it, don't auto-install with -y, and reach remote servers over "
            "HTTPS only."
        ),
    )

    def run(self, context: AuditContext) -> Iterator[Detection]:
        for server in context.artifacts.mcp_servers:
            for problem in mcp_problems(server):
                text = context.read_text(server.source) or ""
                yield Detection(
                    title=f"MCP server '{server.name}' {problem}",
                    location=Location(file=server.source, line=find_line(text, f'"{server.name}"')),
                    evidence=server.url or " ".join([server.command or "", *server.args]),
                    confidence=0.85,
                )


def mcp_problems(server: McpServerConfig) -> list[str]:
    if server.url is not None:
        host = re.sub(r"^https?://([^/:]+).*$", r"\1", server.url)
        if server.url.startswith("http://") and not NON_PUBLIC_HOST.match(host):
            return ["is reached over unencrypted HTTP"]
        return []
    runner = PurePosixPath(server.command or "").name
    args = list(server.args)
    if runner in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        runner, args = "npx", args[1:]
    if runner == "pipx" and args[:1] == ["run"]:
        runner, args = "uvx", args[1:]
    if runner == "docker" and "run" in args:
        image = _first_positional(args[args.index("run") + 1 :])
        if image and "@sha256:" not in image and (":" not in image or image.endswith(":latest")):
            return [f"runs a container image without a pinned tag or digest ({image})"]
        return []
    if runner not in PACKAGE_RUNNERS:
        return []  # a local command, not something downloaded at start-up
    package = _first_positional(args)
    if package is None or _pinned(package, PACKAGE_RUNNERS[runner]):
        return []
    auto = " and installs it without asking (-y)" if {"-y", "--yes"} & set(args) else ""
    return [f"downloads an unpinned package at start-up ({package}){auto}"]


def _first_positional(args: list[str]) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in VALUE_FLAGS:
            skip = True
        elif not arg.startswith("-"):
            return arg
    return None


def _pinned(package: str, ecosystem: str) -> bool:
    if ecosystem == "PyPI":
        return bool(re.search(r"==\s*\d|@\s*\d", package))
    version = (
        package[1:].partition("@")[2] if package.startswith("@") else package.partition("@")[2]
    )
    return bool(re.match(r"\d", version))
