"""runner.py - Build and execute NoPainNoScan check command lines (Agent 2).

This module is the low-level execution primitive. It is deliberately narrow:

    * build_command()   -> turns a CheckDefinition + params into an argv LIST.
    * check_tools()      -> shutil.which() pre-flight for required/optional tools.
    * validate_target()  -> best-effort sanity check on the target string.
    * spawn()            -> asyncio.create_subprocess_exec (NEVER shell=True).
    * iter_output()      -> async line-by-line reader over merged stdout+stderr.

Security note: commands are always constructed as an argv list and executed with
create_subprocess_exec (no shell), so the classic shell-injection surface is
absent by construction. validate_target() is an additional light guard; full
hardening (per-check target grammars) is planned for a later pass and is
intentionally lenient here so legitimate edge cases are not blocked.

Job lifecycle, log fan-out and DB transitions live in jobs.py; this file never
touches the store or the in-memory job registry.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from ..config import script_path
from .registry import CheckDefinition


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class TargetValidationError(ValueError):
    """Raised when a target string fails the best-effort validation."""


class MissingToolsError(RuntimeError):
    """Raised when one or more required system tools are absent."""

    def __init__(self, tools: list[str]):
        self.tools = tools
        super().__init__(
            "Missing required tool(s): " + ", ".join(tools)
            + ". Install them before running this check."
        )


# --------------------------------------------------------------------------- #
# Target validation (best-effort, non-blocking on edge cases)
# --------------------------------------------------------------------------- #
# Characters that would only make sense in a shell context. We do not use a
# shell, but rejecting them keeps obviously-malicious input out of argv and of
# any file the target string might name.
_FORBIDDEN_TARGET_CHARS = set(";|&$`\n\r<>\0")


def validate_target(target: str) -> None:
    """Best-effort validation of the target string.

    Rejects empty targets and strings carrying shell metacharacters / control
    characters. Everything else (single IP, CIDR, hostname, comma-separated
    list, path to a hosts file) is accepted without a strict grammar, matching
    the "do not block edge cases" contract.

    Raises:
        TargetValidationError: on an empty or clearly unsafe target.
    """
    if target is None or not str(target).strip():
        raise TargetValidationError("Target is required and must not be empty.")
    bad = _FORBIDDEN_TARGET_CHARS.intersection(str(target))
    if bad:
        raise TargetValidationError(
            "Target contains forbidden character(s): "
            + " ".join(sorted(repr(c) for c in bad))
        )


# --------------------------------------------------------------------------- #
# Tool pre-flight
# --------------------------------------------------------------------------- #
def check_tools(check_def: CheckDefinition) -> tuple[list[str], list[str]]:
    """Return (missing_required, missing_optional) tool names for a check.

    Uses shutil.which() to detect binaries on PATH. Callers must treat a
    non-empty missing_required as a hard failure; missing_optional is a warning
    only (the script degrades gracefully).
    """
    missing_required = [t for t in check_def.required_tools if shutil.which(t) is None]
    missing_optional = [t for t in check_def.optional_tools if shutil.which(t) is None]
    return missing_required, missing_optional


# --------------------------------------------------------------------------- #
# Command-line construction
# --------------------------------------------------------------------------- #
_TRUTHY = {"1", "true", "yes", "on", "y", "t"}


def _is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in _TRUTHY


def build_command(
    check_def: CheckDefinition,
    params: dict[str, Any],
    run_dir: Path,
) -> list[str]:
    """Build the argv LIST for one check execution.

    The command is ``["python3", <script>, <flags...>, "-o", <run_dir>]``.

    Rules, driven purely by each argument's declared ``type`` in the registry
    (never by hard-coded per-check assumptions):

        * ``bool``  -> flag appended only when the value is truthy (no value).
        * ``list``  -> flag repeated once per item (``-d a -d b``).
        * ``int`` / ``str`` -> flag followed by ``str(value)``.

    ``params`` is keyed by argument ``dest`` (e.g. ``"target"``, ``"username"``).
    The ``output`` argument is ignored here: ``-o <run_dir>`` is always injected
    from the caller-supplied per-run directory, overriding anything in params.

    Args:
        check_def: the registry entry describing the script and its arguments.
        params:    dest -> value mapping (must already contain ``target``).
        run_dir:   the per-run output directory to inject via ``-o``.

    Returns:
        The argv list, ready for asyncio.create_subprocess_exec.
    """
    cmd: list[str] = ["python3", str(script_path(check_def.script))]

    for arg in check_def.arguments:
        if arg.dest == "output":
            # Always injected explicitly below; never taken from params.
            continue
        if arg.dest not in params:
            continue
        value = params[arg.dest]
        if value is None:
            continue

        flag = arg.short or arg.name

        if arg.type == "bool":
            if _is_truthy(value):
                cmd.append(flag)
            continue

        if arg.type == "list":
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                if item is None:
                    continue
                cmd.extend([flag, str(item)])
            continue

        # str / int (and any unknown type): single flag + stringified value.
        svalue = str(value)
        if svalue == "" and not arg.required:
            # Skip empty optional strings (e.g. snmp --community default "").
            continue
        cmd.extend([flag, svalue])

    # Run non-interactively: append the script's accept-all flag when it has one
    # (every check_*.py; not discovery). Without it the script blocks on input().
    if check_def.auto_yes_flag:
        cmd.append(check_def.auto_yes_flag)

    # The per-run output directory is authoritative and always present.
    cmd.extend(["-o", str(run_dir)])
    return cmd


# --------------------------------------------------------------------------- #
# Asynchronous execution primitives
# --------------------------------------------------------------------------- #
async def spawn(cmd: list[str], cwd: Optional[Path] = None) -> asyncio.subprocess.Process:
    """Launch a command with create_subprocess_exec (no shell).

    stdout and stderr are merged onto one pipe so log ordering is preserved for
    line-by-line streaming.

    Args:
        cmd: the argv list from build_command().
        cwd: working directory for the child (defaults to the current dir).

    Returns:
        The started asyncio subprocess Process.
    """
    # Enable progress emission in the child scripts (they stay silent in a CLI run).
    env = {**os.environ, "NPNS_PROGRESS": "1"}
    return await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        # Own process group so cancel can SIGTERM the whole tree
        # (the scripts spawn nxc/masscan/nmap children).
        start_new_session=True,
    )


async def iter_output(process: asyncio.subprocess.Process) -> AsyncIterator[str]:
    """Yield decoded, newline-stripped lines from a running process.

    Reads until EOF on the merged stdout pipe. The caller is responsible for
    awaiting ``process.wait()`` afterwards to collect the exit code.
    """
    assert process.stdout is not None
    while True:
        raw = await process.stdout.readline()
        if not raw:
            break
        yield raw.decode("utf-8", errors="replace").rstrip("\n")
