from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Policy(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    MANUAL_REVIEW = "manual_review"
    UNKNOWN = "unknown"


class AutomationMode(StrEnum):
    MANUAL = "manual"
    HYBRID = "hybrid"
    AUTO = "auto"


@dataclass(frozen=True, slots=True)
class Classification:
    domain: str
    policy: Policy
    category: str
    short: str
    details: str
    provider: str
    raw_text: str = ""


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    success: bool
    request_url: str
    elapsed_ms: int
    summary: str
    version: str = ""
