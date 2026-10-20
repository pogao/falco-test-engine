from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    rule: str | None
    message: str
    suggestion: str | None = None
