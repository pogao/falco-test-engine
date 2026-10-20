"""Does the real Falco start with these rules? `falco --dry-run` answers it."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

_TAIL_LINES = 15


@dataclass(frozen=True)
class StartupPassed:
    command: str
    tail: str


@dataclass(frozen=True)
class StartupFailed:
    command: str
    reason: str
    tail: str


@dataclass(frozen=True)
class StartupSkipped:
    reason: str


type StartupResult = StartupPassed | StartupFailed | StartupSkipped


def check_startup(
    enabled: bool, falco_config: Path, rules_files: Sequence[Path], timeout: float = 300
) -> StartupResult:
    if not enabled:
        return StartupSkipped("disabled in falco-test.yaml")
    falco = shutil.which("falco")
    if falco is None:
        return StartupSkipped("no `falco` binary on PATH")
    argv = [falco, "-c", str(falco_config), "--dry-run"]
    for f in rules_files:
        argv += ["-r", str(f)]
    command = shlex.join(["falco", *argv[1:]])
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return StartupFailed(command, f"timed out after {timeout:.0f}s", "")
    tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-_TAIL_LINES:])
    if proc.returncode != 0:
        return StartupFailed(command, f"exit code {proc.returncode}", tail)
    return StartupPassed(command, tail)
