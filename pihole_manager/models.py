from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Policy(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    MANUAL_REVIEW = "manual_review"
    UNKNOWN = "unknown"


class AutomationMode(StrEnum):
    MANUAL = "manual"
    HYBRID = "hybrid"
    AUTO = "auto"


class AnalysisPoolMode(StrEnum):
    DISTRIBUTE = "distribute"
    FALLBACK = "fallback"
    COMPARE = "compare"
    VERIFY = "verify"


class ProviderLimitMode(StrEnum):
    AUTO = "auto"
    AUTO_CAP = "auto_cap"
    MANUAL = "manual"


class ServiceRole(StrEnum):
    CORE = "core"
    OPTIONAL = "optional"
    SHARED = "shared"
    UNKNOWN = "unknown"


class ReviewPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class ResearchFinding:
    domain: str
    provider: str
    kind: str
    title: str
    summary: str
    source_url: str = ""
    confidence: float = 0.0
    signal_type: str = "context"
    verdict: str = "unknown"
    decision_relevant: bool = False
    retrieved_at: int = 0
    expires_at: int = 0
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Classification:
    domain: str
    policy: Policy
    category: str
    short: str
    details: str
    provider: str
    tags: tuple[str, ...] = ()
    service: str = ""
    service_role: ServiceRole = ServiceRole.UNKNOWN
    privacy_risk: int = 0
    security_risk: int = 0
    breakage_risk: int = 50
    confidence: float = 0.0
    needs_review: bool = True
    review_reason: str = ""
    recheck_after_days: int = 30
    raw_text: str = ""


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    units: float = 0.0


@dataclass(frozen=True, slots=True)
class ProviderHealthState:
    provider_id: str
    state: str = "unknown"
    cooldown_until: float = 0.0
    consecutive_failures: int = 0
    last_error: str = ""
    last_success_at: float = 0.0
    last_failure_at: float = 0.0
    latency_ewma_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ClassificationRunContext:
    analysis_run_id: str = ""
    pool_id: str = ""
    pool_mode: str = ""
    provider_id: str = ""
    model: str = ""
    profile: str = ""
    prompt_hash: str = ""
    is_primary: bool = True
    latency_ms: int = 0
    usage: ProviderUsage = field(default_factory=ProviderUsage)


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    success: bool
    request_url: str
    elapsed_ms: int
    summary: str
    version: str = ""
    state: str = "unknown"
