from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, TypeVar, cast
from uuid import uuid4

from pihole_manager.credentials import hydrate_credentials, secure_options_payload
from pihole_manager.models import AutomationMode, Policy

T = TypeVar("T")
_CONFIG_LOCK = threading.RLock()
CURRENT_SCHEMA_VERSION = 17
log = logging.getLogger(__name__)


class UnsupportedConfigVersionError(RuntimeError):
    pass


@dataclass(slots=True)
class LoggingOptions:
    enabled: bool = True
    level: str = "INFO"
    filename: str = "pihole_manager.log"
    rotate_bytes: int = 2_000_000
    backup_count: int = 3


@dataclass(slots=True)
class NotifyOptions:
    enable_desktop: bool = False
    enable_sound: bool = False
    rate_limit_sec: int = 5
    toast_title: str = "Pi-hole Manager"


@dataclass(slots=True)
class ScanOptions:
    enabled: bool = False
    interval_sec: int = 5
    batch_size: int = 200
    initial_lookback_sec: int = 300
    queue_trigger_size: int = 20
    max_queue_wait_sec: int = 300
    history_backfill_enabled: bool = False
    history_idle_after_sec: int = 300
    history_lookback_days: int = 30
    history_batch_size: int = 500
    excluded_domain_suffixes: list[str] = field(default_factory=lambda: [".arpa"])


@dataclass(slots=True)
class PiHoleOptions:
    base_url: str = "http://pi.hole"
    password: str = ""
    verify_tls: bool = True
    timeout_sec: float = 10.0


@dataclass(slots=True)
class ProviderLimitOptions:
    mode: str = "auto"
    quota_group: str = ""
    requests_per_minute: int = 0
    requests_per_hour: int = 0
    requests_per_day: int = 0
    input_tokens_per_minute: int = 0
    output_tokens_per_minute: int = 0
    tokens_per_minute: int = 0
    tokens_per_hour: int = 0
    tokens_per_day: int = 0
    units_per_day: float = 0.0
    context_tokens: int = 0
    max_domains_per_request: int = 0
    safety_margin_percent: float = 10.0


@dataclass(slots=True)
class LLMProviderOptions:
    provider_id: str = field(default_factory=lambda: f"provider-{uuid4().hex}")
    name: str = "Custom OpenAI-compatible"
    preset_id: str = "custom"
    api_style: str = "openai_compatible"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.0
    timeout_sec: float = 30.0
    max_output_tokens: int = 4096
    max_tokens_parameter: str = "max_tokens"
    send_temperature: bool = True
    structured_output: str = "auto"
    limits: ProviderLimitOptions = field(default_factory=ProviderLimitOptions)


@dataclass(slots=True)
class ProviderPoolMembershipOptions:
    provider_id: str = ""
    enabled: bool = True
    role: str = "primary"
    priority: int = 100
    weight: int = 1


@dataclass(slots=True)
class AnalysisPoolOptions:
    pool_id: str = "background"
    name: str = "Background analysis"
    enabled: bool = True
    mode: str = "distribute"
    profile_index: int = 0
    max_parallel_requests: int = 2
    verification_sample_percent: int = 10
    verify_automatic_actions: bool = True
    verify_security_risk_at_least: int = 80
    verify_breakage_risk_at_least: int = 50
    memberships: list[ProviderPoolMembershipOptions] = field(default_factory=list)


@dataclass(slots=True)
class ProviderRegistryOptions:
    auto_update: bool = False
    refresh_interval_hours: int = 168
    last_checked_at: int = 0
    registry_url: str = (
        "https://github.com/HyperCriSiS/Pi-Hole-Manager/releases/latest/download/"
        "provider-registry.json"
    )
    signature_url: str = (
        "https://github.com/HyperCriSiS/Pi-Hole-Manager/releases/latest/download/"
        "provider-registry.json.sig"
    )


@dataclass(slots=True)
class PromptProfileOptions:
    name: str = "Balanced"
    system: str = (
        "You classify DNS domains for a Pi-hole v6 administrator. Start with the "
        "supplied domain dossier and distinguish verified facts from inference. If the "
        "selected model and API perform live web search without an additional tool request, "
        "independently verify "
        "the exact domain using official vendor documentation, GitHub code, issues and "
        "discussions, Pi-hole community reports, reputable blocklist repositories such "
        "as AdGuardTeam/HostlistsRegistry, hagezi/dns-blocklists, easylist/easylist, "
        "disconnectme/disconnect-tracking-protection, and credible user reports. "
        "Pi-hole Manager does not currently invoke provider-specific web-search tools. Never "
        "claim to have searched the web when browsing is not available. Include "
        "useful source URLs in details when known, and prefer manual "
        "review when evidence is weak or blocking may break an important service."
    )
    user_template: str = (
        "Analyse the following domain dossiers. Return only the required structured result.\n"
        "{domain_dossiers}"
    )


_DEFAULT_TAGS = [
    "advertising",
    "cross_site_tracking",
    "analytics",
    "telemetry",
    "crash_reporting",
    "authentication",
    "payments",
    "api_backend",
    "content_media",
    "cdn_shared_infrastructure",
    "software_updates",
    "notifications_messaging",
    "security_antifraud",
    "iot_cloud",
    "malware",
    "phishing",
    "command_and_control",
    "unknown",
]

_DEFAULT_TAG_POLICIES = {
    "advertising": Policy.DENY.value,
    "cross_site_tracking": Policy.DENY.value,
    "analytics": Policy.MANUAL_REVIEW.value,
    "telemetry": Policy.MANUAL_REVIEW.value,
    "crash_reporting": Policy.MANUAL_REVIEW.value,
    "authentication": Policy.MANUAL_REVIEW.value,
    "payments": Policy.MANUAL_REVIEW.value,
    "api_backend": Policy.MANUAL_REVIEW.value,
    "content_media": Policy.MANUAL_REVIEW.value,
    "cdn_shared_infrastructure": Policy.MANUAL_REVIEW.value,
    "software_updates": Policy.MANUAL_REVIEW.value,
    "notifications_messaging": Policy.MANUAL_REVIEW.value,
    "security_antifraud": Policy.MANUAL_REVIEW.value,
    "iot_cloud": Policy.MANUAL_REVIEW.value,
    "malware": Policy.DENY.value,
    "phishing": Policy.DENY.value,
    "command_and_control": Policy.DENY.value,
    "unknown": Policy.MANUAL_REVIEW.value,
}

_DEFAULT_TAG_RECHECK_DAYS = {
    "advertising": 30,
    "cross_site_tracking": 30,
    "analytics": 30,
    "telemetry": 30,
    "crash_reporting": 30,
    "authentication": 90,
    "payments": 90,
    "api_backend": 60,
    "content_media": 60,
    "cdn_shared_infrastructure": 90,
    "software_updates": 60,
    "notifications_messaging": 60,
    "security_antifraud": 60,
    "iot_cloud": 45,
    "malware": 7,
    "phishing": 7,
    "command_and_control": 7,
    "unknown": 3,
}


@dataclass(slots=True)
class LLMOptions:
    enabled: bool = False
    interval_sec: int = 10
    worker_batch_size: int = 25
    domains_per_request: int = 10
    min_request_interval_sec: float = 1.0
    max_retries: int = 2
    realtime_quota_reserve_percent: float = 20.0
    quota_wait_timeout_sec: float = 30.0
    unknown_remote_requests_per_minute: int = 2
    unknown_remote_max_domains_per_request: int = 1
    active_provider_index: int = 0
    active_profile_index: int = 0
    automation_mode: str = AutomationMode.HYBRID.value
    simulation_mode: bool = True
    default_recheck_days: int = 30
    review_confidence_threshold: float = 0.75
    auto_action_min_confidence: float = 0.95
    require_research_for_auto_action: bool = True
    tags: list[str] = field(default_factory=lambda: list(_DEFAULT_TAGS))
    tag_policies: dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_TAG_POLICIES))
    tag_recheck_days: dict[str, int] = field(
        default_factory=lambda: dict(_DEFAULT_TAG_RECHECK_DAYS)
    )

    @property
    def batch_size(self) -> int:
        return self.worker_batch_size

    @batch_size.setter
    def batch_size(self, value: int) -> None:
        self.worker_batch_size = value

    @property
    def categories(self) -> list[str]:
        return self.tags

    @categories.setter
    def categories(self, value: list[str]) -> None:
        self.tags = value

    @property
    def category_policies(self) -> dict[str, str]:
        return self.tag_policies

    @category_policies.setter
    def category_policies(self, value: dict[str, str]) -> None:
        self.tag_policies = value


@dataclass(slots=True)
class ResearchOptions:
    max_age_days: int = 30


@dataclass(slots=True)
class UpdateOptions:
    check_automatically: bool = False
    channel: str = "stable"
    check_interval_hours: int = 24
    last_check_at: int = 0


@dataclass(slots=True)
class ExternalTriggerOptions:
    enabled: bool = False
    bind_host: str = "127.0.0.1"
    port: int = 8765
    token: str = ""
    allow_remote: bool = False
    max_domains_per_request: int = 500


@dataclass(slots=True)
class ResearchProviderOptions:
    name: str = "RDAP registration data"
    kind: str = "rdap"
    enabled: bool = False
    base_url: str = ""
    api_key: str = ""
    timeout_sec: float = 15.0
    min_interval_sec: float = 1.0
    refresh_interval_hours: int = 24
    max_results: int = 5
    test_domain: str = ""


@dataclass(slots=True)
class UIOptions:
    theme: str = "system"
    show_tooltips: bool = True
    window_width: int = 1280
    window_height: int = 820
    auto_update_queries: bool = False
    query_refresh_ms: int = 2_000
    auto_scroll_queries: bool = True
    history_deduplicate_domains: bool = True
    evidence_test_skip_api_key_sources: bool = False
    evidence_test_skip_missing_api_keys: bool = True
    lists_queue_only_unreviewed: bool = True
    queries_colwidths: dict[str, int] = field(
        default_factory=lambda: {
            "selected": 38,
            "time": 90,
            "client": 170,
            "domain": 360,
            "type": 80,
            "status": 140,
        }
    )
    table_visible_columns: dict[str, list[str]] = field(
        default_factory=lambda: {
            "queries": ["selected", "time", "client", "domain", "type", "status"],
            "history": ["selected", "time", "client", "domain", "type", "status", "classified"],
            "lists": ["selected", "locked", "domain", "enabled", "tags", "details"],
            "review": [
                "selected",
                "order",
                "queued",
                "lock",
                "domain",
                "tags",
                "service",
                "role",
                "policy",
                "planned",
                "confidence",
                "breakage",
                "short",
                "status",
            ],
            "domains": [
                "domain",
                "tags",
                "service",
                "role",
                "policy",
                "planned",
                "confidence",
                "breakage",
                "queries",
                "last_seen",
                "review",
                "short",
            ],
        }
    )
    table_column_order: dict[str, list[str]] = field(
        default_factory=lambda: {
            "queries": ["selected", "time", "client", "domain", "type", "status"],
            "history": ["selected", "time", "client", "domain", "type", "status", "classified"],
            "lists": ["selected", "locked", "domain", "enabled", "comment", "tags", "details"],
            "review": [
                "selected",
                "order",
                "queued",
                "lock",
                "domain",
                "tags",
                "service",
                "role",
                "policy",
                "planned",
                "confidence",
                "privacy",
                "security",
                "breakage",
                "short",
                "status",
            ],
            "domains": [
                "domain",
                "tags",
                "service",
                "role",
                "policy",
                "planned",
                "confidence",
                "privacy",
                "security",
                "breakage",
                "queries",
                "last_seen",
                "classified",
                "recheck",
                "review",
                "lock",
                "provider",
                "short",
            ],
        }
    )
    table_column_widths: dict[str, dict[str, int]] = field(
        default_factory=lambda: {
            "queries": {
                "selected": 38,
                "time": 90,
                "client": 170,
                "domain": 360,
                "type": 80,
                "status": 140,
            },
            "history": {
                "selected": 38,
                "time": 150,
                "client": 180,
                "domain": 390,
                "type": 80,
                "status": 150,
                "classified": 90,
            },
            "lists": {
                "selected": 38,
                "locked": 58,
                "domain": 290,
                "enabled": 70,
                "comment": 260,
                "tags": 230,
                "details": 430,
            },
            "review": {
                "selected": 38,
                "order": 48,
                "queued": 115,
                "lock": 48,
                "domain": 250,
                "tags": 230,
                "service": 180,
                "role": 80,
                "policy": 105,
                "planned": 95,
                "confidence": 65,
                "privacy": 65,
                "security": 65,
                "breakage": 90,
                "short": 300,
                "status": 120,
            },
            "domains": {
                "domain": 280,
                "tags": 240,
                "service": 180,
                "role": 80,
                "policy": 105,
                "planned": 95,
                "confidence": 65,
                "privacy": 65,
                "security": 65,
                "breakage": 70,
                "queries": 80,
                "last_seen": 135,
                "classified": 135,
                "recheck": 135,
                "review": 65,
                "lock": 70,
                "provider": 150,
                "short": 340,
            },
        }
    )


@dataclass(slots=True)
class Options:
    schema_version: int = CURRENT_SCHEMA_VERSION
    logging: LoggingOptions = field(default_factory=LoggingOptions)
    notify: NotifyOptions = field(default_factory=NotifyOptions)
    scans: ScanOptions = field(default_factory=ScanOptions)
    pihole: PiHoleOptions = field(default_factory=PiHoleOptions)
    llm: LLMOptions = field(default_factory=LLMOptions)
    research: ResearchOptions = field(default_factory=ResearchOptions)
    updates: UpdateOptions = field(default_factory=UpdateOptions)
    provider_registry: ProviderRegistryOptions = field(default_factory=ProviderRegistryOptions)
    external_trigger: ExternalTriggerOptions = field(default_factory=ExternalTriggerOptions)
    llm_providers: list[LLMProviderOptions] = field(default_factory=lambda: [LLMProviderOptions()])
    analysis_pools: list[AnalysisPoolOptions] = field(default_factory=list)
    prompt_profiles: list[PromptProfileOptions] = field(
        default_factory=lambda: [PromptProfileOptions()]
    )
    research_providers: list[ResearchProviderOptions] = field(
        default_factory=lambda: [
            ResearchProviderOptions(
                name="AdGuard service catalog",
                kind="adguard_services",
                enabled=True,
                base_url=("https://adguardteam.github.io/HostlistsRegistry/assets/services.json"),
                refresh_interval_hours=24,
            ),
            ResearchProviderOptions(
                name="Local DNS records",
                kind="dns_records",
                enabled=True,
                min_interval_sec=0.0,
                refresh_interval_hours=6,
            ),
            ResearchProviderOptions(
                name="Disconnect tracker catalog",
                kind="disconnect_tracking",
                enabled=False,
                base_url=(
                    "https://raw.githubusercontent.com/disconnectme/"
                    "disconnect-tracking-protection/master/services.json"
                ),
                refresh_interval_hours=24,
            ),
            ResearchProviderOptions(
                name="RDAP registration data",
                kind="rdap",
                enabled=False,
                base_url="https://data.iana.org/rdap/dns.json",
                refresh_interval_hours=168,
            ),
            ResearchProviderOptions(
                name="RIPEstat network information",
                kind="ripestat",
                enabled=False,
                base_url="https://stat.ripe.net/data",
                refresh_interval_hours=24,
            ),
            ResearchProviderOptions(
                name="Netcraft Site Report",
                kind="netcraft",
                enabled=False,
                base_url="https://sitereport.netcraft.com/",
                min_interval_sec=10.0,
                refresh_interval_hours=168,
            ),
            ResearchProviderOptions(
                name="VirusTotal domain report",
                kind="virustotal",
                enabled=False,
                base_url="https://www.virustotal.com/api/v3",
                min_interval_sec=15.5,
                refresh_interval_hours=24,
            ),
            ResearchProviderOptions(
                name="ThreatFox IOC lookup",
                kind="threatfox",
                enabled=False,
                base_url="https://threatfox-api.abuse.ch/api/v1/",
                min_interval_sec=2.0,
                refresh_interval_hours=6,
            ),
            ResearchProviderOptions(
                name="PhishTank verified phishing database",
                kind="phishtank",
                enabled=False,
                base_url=("https://data.phishtank.com/data/{api_key}/online-valid.json.bz2"),
                refresh_interval_hours=1,
            ),
            ResearchProviderOptions(
                name="urlscan.io archived scans",
                kind="urlscan",
                enabled=False,
                base_url="https://urlscan.io/api/v1",
                min_interval_sec=2.0,
                refresh_interval_hours=12,
                max_results=3,
            ),
            ResearchProviderOptions(
                name="Cloudflare Radar domain ranking",
                kind="cloudflare_radar",
                enabled=False,
                base_url="https://api.cloudflare.com/client/v4/radar",
                min_interval_sec=1.0,
                refresh_interval_hours=168,
            ),
            ResearchProviderOptions(
                name="Curated repository blocklists",
                kind="repository_lists",
                enabled=False,
                min_interval_sec=0.0,
                refresh_interval_hours=12,
                max_results=5,
                test_domain="example.com",
            ),
        ]
    )
    ui: UIOptions = field(default_factory=UIOptions)


def app_directory() -> Path:
    override = os.environ.get("PIHOLE_MANAGER_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def options_path() -> Path:
    return app_directory() / "options.json"


def database_path() -> Path:
    return app_directory() / "pihole_manager.sqlite3"


def _coerce_dataclass(cls: type[T], raw: Any) -> T:
    instance = cls()
    if not isinstance(raw, dict):
        return instance
    valid_fields = {item.name for item in fields(cast(Any, instance))}
    for key, value in raw.items():
        if key in valid_fields:
            setattr(instance, key, value)
    return instance


def _load_list(raw: Any, cls: type[T], fallback: list[T]) -> list[T]:
    if not isinstance(raw, list):
        return fallback
    loaded = [_coerce_dataclass(cls, item) for item in raw if isinstance(item, dict)]
    return loaded or fallback


def _load_llm_providers(raw: Any) -> list[LLMProviderOptions]:
    if not isinstance(raw, list):
        return [LLMProviderOptions()]
    providers: list[LLMProviderOptions] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        provider = _coerce_dataclass(LLMProviderOptions, item)
        provider.limits = _coerce_dataclass(ProviderLimitOptions, item.get("limits"))
        providers.append(provider)
    return providers or [LLMProviderOptions()]


def _load_analysis_pools(raw: Any) -> list[AnalysisPoolOptions]:
    if not isinstance(raw, list):
        return []
    pools: list[AnalysisPoolOptions] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        pool = _coerce_dataclass(AnalysisPoolOptions, item)
        pool.memberships = _load_list(
            item.get("memberships"),
            ProviderPoolMembershipOptions,
            [],
        )
        pools.append(pool)
    return pools


def _mapping(raw: Any) -> dict[str, Any]:
    return dict(raw) if isinstance(raw, dict) else {}


def _migrated_provider_id(provider: dict[str, Any], index: int, used: set[str]) -> str:
    configured = str(provider.get("provider_id") or "").strip()
    if configured and configured not in used:
        used.add(configured)
        return configured
    identity = "\0".join(
        (
            str(index),
            str(provider.get("name") or ""),
            str(provider.get("base_url") or ""),
            str(provider.get("model") or ""),
        )
    )
    candidate = f"provider-{sha256(identity.encode('utf-8')).hexdigest()[:20]}"
    suffix = 2
    while candidate in used:
        candidate = f"{candidate}-{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _default_analysis_pool(
    pool_id: str,
    provider_id: str,
    *,
    profile_index: int = 0,
) -> dict[str, Any]:
    realtime = pool_id == "realtime"
    return {
        "pool_id": pool_id,
        "name": "Realtime analysis" if realtime else "Background analysis",
        "enabled": True,
        "mode": "fallback" if realtime else "distribute",
        "profile_index": profile_index,
        "max_parallel_requests": 2,
        "verification_sample_percent": 10,
        "verify_automatic_actions": True,
        "verify_security_risk_at_least": 80,
        "verify_breakage_risk_at_least": 50,
        "memberships": [
            {
                "provider_id": provider_id,
                "enabled": True,
                "role": "primary",
                "priority": 100,
                "weight": 1,
            }
        ],
    }


def _migrate(raw: dict[str, Any]) -> dict[str, Any]:
    data = dict(raw)
    try:
        source_version = int(data.get("schema_version") or 0)
    except (TypeError, ValueError):
        source_version = 0
    if source_version > CURRENT_SCHEMA_VERSION:
        raise UnsupportedConfigVersionError(
            "The configuration was created by a newer Pi-hole Manager version "
            f"(schema {source_version}; supported up to {CURRENT_SCHEMA_VERSION})."
        )
    data.pop("locks", None)
    pihole = _mapping(data.get("pihole"))
    pihole["base_url"] = pihole.get("base_url") or pihole.get("host") or "http://pi.hole"
    pihole["password"] = pihole.get("password") or pihole.get("app_password") or ""
    data["pihole"] = pihole

    logging_raw = _mapping(data.get("logging"))
    logging_raw["enabled"] = logging_raw.get("enabled", logging_raw.get("to_file", True))
    logging_raw["filename"] = (
        logging_raw.get("filename") or logging_raw.get("file") or "pihole_manager.log"
    )
    data["logging"] = logging_raw

    scans = _mapping(data.get("scans"))
    scans["batch_size"] = scans.get("batch_size", scans.get("batch", 200))
    data["scans"] = scans

    llm = _mapping(data.get("llm"))
    if "profile_active_index" in llm and "active_profile_index" not in llm:
        llm["active_profile_index"] = llm["profile_active_index"]
    llm["worker_batch_size"] = llm.get(
        "worker_batch_size", llm.get("batch_size", llm.get("batch", 25))
    )
    legacy_tags = llm.get("tags") or llm.get("categories")
    if legacy_tags:
        llm["tags"] = legacy_tags
    legacy_policies = llm.get("tag_policies") or llm.get("category_policies")
    if legacy_policies:
        llm["tag_policies"] = legacy_policies
    llm.setdefault("tag_recheck_days", dict(_DEFAULT_TAG_RECHECK_DAYS))
    data["llm"] = llm

    ui = _mapping(data.get("ui"))
    if "table_column_widths" not in ui and "queries_colwidths" in ui:
        ui["table_column_widths"] = {
            **UIOptions().table_column_widths,
            "queries": _mapping(ui.get("queries_colwidths")),
        }
    ui.setdefault("show_tooltips", True)
    visible_columns = _mapping(ui.get("table_visible_columns"))
    review_visible = list(visible_columns.get("review") or [])
    if review_visible:
        for column, position in (("order", 1), ("queued", 2)):
            if column not in review_visible:
                review_visible.insert(min(position, len(review_visible)), column)
        visible_columns["review"] = review_visible
        ui["table_visible_columns"] = visible_columns
    column_order = _mapping(ui.get("table_column_order"))
    review_order = list(column_order.get("review") or [])
    if review_order:
        for column, position in (("order", 1), ("queued", 2)):
            if column not in review_order:
                review_order.insert(min(position, len(review_order)), column)
        column_order["review"] = review_order
        ui["table_column_order"] = column_order
    data["ui"] = ui

    updates_raw = _mapping(data.get("updates"))
    updates_raw.setdefault("check_automatically", False)
    if "channel" not in updates_raw:
        updates_raw["channel"] = (
            "prerelease" if updates_raw.get("include_prereleases") else "stable"
        )
    updates_raw.pop("include_prereleases", None)
    updates_raw.setdefault("check_interval_hours", 24)
    updates_raw.setdefault("last_check_at", 0)
    data["updates"] = updates_raw

    registry_raw = _mapping(data.get("provider_registry"))
    registry_defaults = asdict(ProviderRegistryOptions())
    for key, value in registry_defaults.items():
        registry_raw.setdefault(key, value)
    data["provider_registry"] = registry_raw

    research_raw = _mapping(data.get("research"))
    legacy_research_enabled = research_raw.get("enabled")
    research_raw.pop("enabled", None)
    research_raw.pop("run_before_llm", None)
    data["research"] = research_raw

    profiles = []
    known_default_systems = {
        (
            "You classify DNS domains for a Pi-hole v6 administrator. "
            "Use the supplied evidence, distinguish facts from inference, and prefer "
            "manual review when evidence is weak or blocking may break an important service."
        ),
        (
            "You classify DNS domains for a Pi-hole v6 administrator. Start with the "
            "supplied domain dossier and distinguish verified facts from inference. If the "
            "selected model and API perform live web search without an additional tool request, "
            "independently verify "
            "the exact domain using official vendor documentation, GitHub code, issues and "
            "discussions, Pi-hole community reports, reputable blocklist repositories, and "
            "credible user reports. Never claim to have searched the web when browsing is not "
            "available. Include useful source URLs in details when known, and prefer manual "
            "review when evidence is weak or blocking may break an important service."
        ),
    }
    new_default_system = PromptProfileOptions().system
    for raw_profile in data.get("prompt_profiles") or []:
        if not isinstance(raw_profile, dict):
            continue
        profile = dict(raw_profile)
        if (
            str(profile.get("name") or "").strip().lower() == "balanced"
            and str(profile.get("system") or "").strip() in known_default_systems
        ):
            profile["system"] = new_default_system
        profiles.append(profile)
    if profiles:
        data["prompt_profiles"] = profiles

    research_providers = []
    supported_research_kinds = {
        "adguard_services",
        "dns_records",
        "disconnect_tracking",
        "rdap",
        "ripestat",
        "netcraft",
        "virustotal",
        "threatfox",
        "phishtank",
        "urlscan",
        "cloudflare_radar",
        "repository_lists",
    }
    for raw_provider in data.get("research_providers") or []:
        if not isinstance(raw_provider, dict):
            continue
        provider = dict(raw_provider)
        provider_kind = str(provider.get("kind") or "").strip().lower()
        if provider_kind not in supported_research_kinds:
            continue
        provider["kind"] = provider_kind
        if legacy_research_enabled is False:
            provider["enabled"] = False
        research_providers.append(provider)
    configured_kinds = {str(item.get("kind") or "") for item in research_providers}
    for default_research_provider in Options().research_providers:
        if default_research_provider.kind not in configured_kinds:
            research_providers.append(asdict(default_research_provider))
    data["research_providers"] = research_providers

    providers = []
    used_provider_ids: set[str] = set()
    for index, raw_provider in enumerate(data.get("llm_providers") or []):
        if not isinstance(raw_provider, dict):
            continue
        provider = dict(raw_provider)
        provider["provider_id"] = _migrated_provider_id(provider, index, used_provider_ids)
        provider.setdefault("preset_id", "custom")
        provider.setdefault("api_style", "openai_compatible")
        provider.setdefault("max_output_tokens", 4096)
        provider.setdefault("max_tokens_parameter", "max_tokens")
        provider.setdefault("send_temperature", True)
        limits = _mapping(provider.get("limits"))
        for key, value in asdict(ProviderLimitOptions()).items():
            limits.setdefault(key, value)
        provider["limits"] = limits
        base_url = str(provider.get("base_url") or "").strip().rstrip("/")
        if (
            base_url
            and "api_style" not in raw_provider
            and not base_url.endswith(("/v1", "/openai", "/chat/completions"))
        ):
            provider["base_url"] = base_url + "/v1"
        providers.append(provider)
    if not providers:
        default_llm_provider = asdict(LLMProviderOptions())
        default_llm_provider["provider_id"] = _migrated_provider_id(
            default_llm_provider,
            0,
            used_provider_ids,
        )
        providers.append(default_llm_provider)
    data["llm_providers"] = providers

    configured_provider_ids = {str(provider["provider_id"]) for provider in providers}
    active_provider_index = min(
        max(0, _as_int(llm.get("active_provider_index"), 0)),
        len(providers) - 1,
    )
    active_provider_id = str(providers[active_provider_index]["provider_id"])
    active_profile_index = max(0, _as_int(llm.get("active_profile_index"), 0))
    raw_pools = data.get("analysis_pools")
    pools: list[dict[str, Any]] = []
    if isinstance(raw_pools, list):
        for raw_pool in raw_pools:
            if not isinstance(raw_pool, dict):
                continue
            pool = dict(raw_pool)
            memberships = []
            for raw_membership in pool.get("memberships") or []:
                if not isinstance(raw_membership, dict):
                    continue
                membership = dict(raw_membership)
                provider_id = str(membership.get("provider_id") or "").strip()
                if provider_id in configured_provider_ids:
                    memberships.append(membership)
            pool["memberships"] = memberships
            pools.append(pool)
    configured_pool_ids = {str(pool.get("pool_id") or "").strip().lower() for pool in pools}
    for pool_id in ("realtime", "background"):
        if pool_id not in configured_pool_ids:
            pools.append(
                _default_analysis_pool(
                    pool_id,
                    active_provider_id,
                    profile_index=active_profile_index,
                )
            )
    data["analysis_pools"] = pools

    data["schema_version"] = CURRENT_SCHEMA_VERSION
    return data


def _normalize_tags(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return list(
        dict.fromkeys(
            str(value).strip().lower().replace(" ", "_") for value in values if str(value).strip()
        )
    )


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return True
        if normalized in {"false", "no", "off", "0"}:
            return False
    return default


def _validate(options: Options) -> Options:
    defaults = Options()
    options.schema_version = CURRENT_SCHEMA_VERSION
    options.logging.enabled = _as_bool(options.logging.enabled, defaults.logging.enabled)
    options.logging.level = str(options.logging.level).upper()
    if options.logging.level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        options.logging.level = "INFO"
    options.logging.filename = str(options.logging.filename or defaults.logging.filename)
    options.logging.rotate_bytes = max(
        100_000,
        _as_int(options.logging.rotate_bytes, defaults.logging.rotate_bytes),
    )
    options.logging.backup_count = max(
        1,
        _as_int(options.logging.backup_count, defaults.logging.backup_count),
    )

    options.notify.enable_desktop = _as_bool(
        options.notify.enable_desktop,
        defaults.notify.enable_desktop,
    )
    options.notify.enable_sound = _as_bool(
        options.notify.enable_sound,
        defaults.notify.enable_sound,
    )
    options.notify.rate_limit_sec = max(
        0,
        _as_int(options.notify.rate_limit_sec, defaults.notify.rate_limit_sec),
    )
    options.notify.toast_title = str(options.notify.toast_title or defaults.notify.toast_title)

    options.external_trigger.enabled = _as_bool(
        options.external_trigger.enabled,
        defaults.external_trigger.enabled,
    )
    options.external_trigger.bind_host = str(
        options.external_trigger.bind_host or defaults.external_trigger.bind_host
    ).strip()
    options.external_trigger.port = min(
        65_535,
        max(1, _as_int(options.external_trigger.port, defaults.external_trigger.port)),
    )
    options.external_trigger.token = str(options.external_trigger.token or "")
    options.external_trigger.allow_remote = _as_bool(
        options.external_trigger.allow_remote,
        defaults.external_trigger.allow_remote,
    )
    options.external_trigger.max_domains_per_request = min(
        5_000,
        max(
            1,
            _as_int(
                options.external_trigger.max_domains_per_request,
                defaults.external_trigger.max_domains_per_request,
            ),
        ),
    )

    options.scans.enabled = _as_bool(options.scans.enabled, defaults.scans.enabled)
    options.scans.interval_sec = max(
        1, _as_int(options.scans.interval_sec, defaults.scans.interval_sec)
    )
    options.scans.batch_size = max(1, _as_int(options.scans.batch_size, defaults.scans.batch_size))
    options.scans.initial_lookback_sec = max(
        1,
        _as_int(
            options.scans.initial_lookback_sec,
            defaults.scans.initial_lookback_sec,
        ),
    )
    options.scans.queue_trigger_size = max(
        1,
        _as_int(options.scans.queue_trigger_size, defaults.scans.queue_trigger_size),
    )
    options.scans.max_queue_wait_sec = max(
        1,
        _as_int(options.scans.max_queue_wait_sec, defaults.scans.max_queue_wait_sec),
    )
    options.scans.history_backfill_enabled = _as_bool(
        options.scans.history_backfill_enabled,
        defaults.scans.history_backfill_enabled,
    )
    options.scans.history_idle_after_sec = max(
        30,
        _as_int(
            options.scans.history_idle_after_sec,
            defaults.scans.history_idle_after_sec,
        ),
    )
    options.scans.history_lookback_days = max(
        1,
        _as_int(
            options.scans.history_lookback_days,
            defaults.scans.history_lookback_days,
        ),
    )
    options.scans.history_batch_size = max(
        10,
        _as_int(options.scans.history_batch_size, defaults.scans.history_batch_size),
    )

    options.pihole.base_url = str(options.pihole.base_url or defaults.pihole.base_url)
    options.pihole.password = str(options.pihole.password or "")
    options.pihole.verify_tls = _as_bool(
        options.pihole.verify_tls,
        defaults.pihole.verify_tls,
    )
    options.pihole.timeout_sec = max(
        1.0,
        _as_float(options.pihole.timeout_sec, defaults.pihole.timeout_sec),
    )

    options.llm.enabled = _as_bool(options.llm.enabled, defaults.llm.enabled)
    options.llm.interval_sec = max(1, _as_int(options.llm.interval_sec, defaults.llm.interval_sec))
    options.llm.worker_batch_size = max(
        1,
        _as_int(options.llm.worker_batch_size, defaults.llm.worker_batch_size),
    )
    options.llm.domains_per_request = min(
        options.llm.worker_batch_size,
        max(
            1,
            _as_int(
                options.llm.domains_per_request,
                defaults.llm.domains_per_request,
            ),
        ),
    )
    options.llm.min_request_interval_sec = max(
        0.0,
        _as_float(
            options.llm.min_request_interval_sec,
            defaults.llm.min_request_interval_sec,
        ),
    )
    options.llm.max_retries = max(0, _as_int(options.llm.max_retries, defaults.llm.max_retries))
    options.llm.realtime_quota_reserve_percent = min(
        90.0,
        max(
            0.0,
            _as_float(
                options.llm.realtime_quota_reserve_percent,
                defaults.llm.realtime_quota_reserve_percent,
            ),
        ),
    )
    options.llm.quota_wait_timeout_sec = max(
        0.0,
        _as_float(
            options.llm.quota_wait_timeout_sec,
            defaults.llm.quota_wait_timeout_sec,
        ),
    )
    options.llm.unknown_remote_requests_per_minute = max(
        1,
        _as_int(
            options.llm.unknown_remote_requests_per_minute,
            defaults.llm.unknown_remote_requests_per_minute,
        ),
    )
    options.llm.unknown_remote_max_domains_per_request = max(
        1,
        _as_int(
            options.llm.unknown_remote_max_domains_per_request,
            defaults.llm.unknown_remote_max_domains_per_request,
        ),
    )
    options.llm.default_recheck_days = max(
        1,
        _as_int(
            options.llm.default_recheck_days,
            defaults.llm.default_recheck_days,
        ),
    )
    options.llm.review_confidence_threshold = min(
        1.0,
        max(
            0.0,
            _as_float(
                options.llm.review_confidence_threshold,
                defaults.llm.review_confidence_threshold,
            ),
        ),
    )
    options.llm.auto_action_min_confidence = min(
        1.0,
        max(
            0.0,
            _as_float(
                options.llm.auto_action_min_confidence,
                defaults.llm.auto_action_min_confidence,
            ),
        ),
    )
    if options.llm.review_confidence_threshold > options.llm.auto_action_min_confidence:
        options.llm.review_confidence_threshold = options.llm.auto_action_min_confidence
    options.llm.simulation_mode = _as_bool(
        options.llm.simulation_mode,
        defaults.llm.simulation_mode,
    )
    options.llm.require_research_for_auto_action = _as_bool(
        options.llm.require_research_for_auto_action,
        defaults.llm.require_research_for_auto_action,
    )
    options.llm.automation_mode = str(options.llm.automation_mode)
    valid_modes = {item.value for item in AutomationMode}
    if options.llm.automation_mode not in valid_modes:
        options.llm.automation_mode = AutomationMode.HYBRID.value

    options.llm.tags = _normalize_tags(options.llm.tags) or ["unknown"]
    if not isinstance(options.llm.tag_policies, dict):
        options.llm.tag_policies = {}
    options.llm.tag_policies = {
        str(key).strip().lower().replace(" ", "_"): str(value).strip().lower()
        for key, value in options.llm.tag_policies.items()
        if str(key).strip()
    }
    for tag in options.llm.tags:
        options.llm.tag_policies.setdefault(tag, Policy.MANUAL_REVIEW.value)
    if not isinstance(options.llm.tag_recheck_days, dict):
        options.llm.tag_recheck_days = {}
    normalized_rechecks: dict[str, int] = {}
    for key, value in options.llm.tag_recheck_days.items():
        normalized_key = str(key).strip().lower().replace(" ", "_")
        if not normalized_key:
            continue
        try:
            normalized_rechecks[normalized_key] = max(1, int(value))
        except (TypeError, ValueError):
            continue
    options.llm.tag_recheck_days = normalized_rechecks
    for tag in options.llm.tags:
        options.llm.tag_recheck_days.setdefault(
            tag, _DEFAULT_TAG_RECHECK_DAYS.get(tag, options.llm.default_recheck_days)
        )

    options.research.max_age_days = max(
        1,
        _as_int(options.research.max_age_days, defaults.research.max_age_days),
    )
    options.updates.check_automatically = _as_bool(
        options.updates.check_automatically,
        defaults.updates.check_automatically,
    )
    channel = str(options.updates.channel).strip().lower()
    options.updates.channel = (
        "prerelease"
        if channel == "development"
        else channel
        if channel in {"stable", "prerelease"}
        else "stable"
    )
    options.updates.check_interval_hours = max(
        1,
        _as_int(
            options.updates.check_interval_hours,
            defaults.updates.check_interval_hours,
        ),
    )
    options.updates.last_check_at = max(
        0,
        _as_int(options.updates.last_check_at, defaults.updates.last_check_at),
    )
    options.provider_registry.auto_update = _as_bool(
        options.provider_registry.auto_update,
        defaults.provider_registry.auto_update,
    )
    options.provider_registry.refresh_interval_hours = max(
        1,
        _as_int(
            options.provider_registry.refresh_interval_hours,
            defaults.provider_registry.refresh_interval_hours,
        ),
    )
    options.provider_registry.last_checked_at = max(
        0,
        _as_int(
            options.provider_registry.last_checked_at,
            defaults.provider_registry.last_checked_at,
        ),
    )
    options.provider_registry.registry_url = str(
        options.provider_registry.registry_url or defaults.provider_registry.registry_url
    ).strip()
    options.provider_registry.signature_url = str(
        options.provider_registry.signature_url or defaults.provider_registry.signature_url
    ).strip()

    if not isinstance(options.scans.excluded_domain_suffixes, list):
        options.scans.excluded_domain_suffixes = [".arpa"]
    normalized_suffixes: list[str] = []
    for suffix_value in options.scans.excluded_domain_suffixes:
        suffix = str(suffix_value).strip().lower().rstrip(".")
        if suffix.startswith("*"):
            suffix = suffix[1:]
        if suffix and not suffix.startswith("."):
            suffix = "." + suffix
        if suffix and suffix not in normalized_suffixes:
            normalized_suffixes.append(suffix)
    options.scans.excluded_domain_suffixes = normalized_suffixes

    theme = str(options.ui.theme).strip().lower()
    options.ui.theme = theme if theme in {"system", "light", "dark"} else defaults.ui.theme
    options.ui.show_tooltips = _as_bool(
        options.ui.show_tooltips,
        defaults.ui.show_tooltips,
    )
    options.ui.evidence_test_skip_api_key_sources = _as_bool(
        options.ui.evidence_test_skip_api_key_sources,
        defaults.ui.evidence_test_skip_api_key_sources,
    )
    options.ui.evidence_test_skip_missing_api_keys = _as_bool(
        options.ui.evidence_test_skip_missing_api_keys,
        defaults.ui.evidence_test_skip_missing_api_keys,
    )
    options.ui.lists_queue_only_unreviewed = _as_bool(
        options.ui.lists_queue_only_unreviewed,
        defaults.ui.lists_queue_only_unreviewed,
    )
    options.ui.auto_update_queries = _as_bool(
        options.ui.auto_update_queries,
        defaults.ui.auto_update_queries,
    )
    options.ui.auto_scroll_queries = _as_bool(
        options.ui.auto_scroll_queries,
        defaults.ui.auto_scroll_queries,
    )
    options.ui.history_deduplicate_domains = _as_bool(
        options.ui.history_deduplicate_domains,
        defaults.ui.history_deduplicate_domains,
    )
    options.ui.query_refresh_ms = max(
        500,
        _as_int(options.ui.query_refresh_ms, defaults.ui.query_refresh_ms),
    )
    options.ui.window_width = max(
        800,
        _as_int(options.ui.window_width, defaults.ui.window_width),
    )
    options.ui.window_height = max(
        600,
        _as_int(options.ui.window_height, defaults.ui.window_height),
    )
    ui_defaults = UIOptions()
    if not isinstance(options.ui.table_visible_columns, dict):
        options.ui.table_visible_columns = {}
    if not isinstance(options.ui.table_column_widths, dict):
        options.ui.table_column_widths = {}
    for table_key, default_columns in ui_defaults.table_visible_columns.items():
        configured = options.ui.table_visible_columns.get(table_key, default_columns)
        if not isinstance(configured, list):
            configured = default_columns
        known_columns = set(ui_defaults.table_column_widths.get(table_key, {}))
        options.ui.table_visible_columns[table_key] = [
            str(column) for column in configured if str(column) in known_columns
        ] or list(default_columns)

        configured_widths = options.ui.table_column_widths.get(table_key, {})
        if not isinstance(configured_widths, dict):
            configured_widths = {}
        options.ui.table_column_widths[table_key] = {
            column: max(20, _as_int(configured_widths.get(column), width))
            for column, width in ui_defaults.table_column_widths.get(table_key, {}).items()
        }
    if not isinstance(options.ui.table_column_order, dict):
        options.ui.table_column_order = {}
    for table_key, default_order in ui_defaults.table_column_order.items():
        configured_order = options.ui.table_column_order.get(table_key, default_order)
        if not isinstance(configured_order, list):
            configured_order = default_order
        known_columns = set(default_order)
        normalized_order = list(
            dict.fromkeys(
                str(column) for column in configured_order if str(column) in known_columns
            )
        )
        options.ui.table_column_order[table_key] = [
            *normalized_order,
            *(column for column in default_order if column not in normalized_order),
        ]
    options.ui.queries_colwidths = dict(options.ui.table_column_widths["queries"])

    options.llm_providers = options.llm_providers or [LLMProviderOptions()]
    used_provider_ids: set[str] = set()
    for llm_provider in options.llm_providers:
        provider_id = str(llm_provider.provider_id or "").strip()
        if not provider_id or provider_id in used_provider_ids:
            provider_id = f"provider-{uuid4().hex}"
        llm_provider.provider_id = provider_id
        used_provider_ids.add(provider_id)
        llm_provider.name = str(llm_provider.name or "Unnamed provider")
        llm_provider.preset_id = str(llm_provider.preset_id).strip().lower() or "custom"
        llm_provider.api_style = str(llm_provider.api_style).strip().lower()
        if llm_provider.api_style not in {"openai_compatible", "anthropic_messages"}:
            llm_provider.api_style = "openai_compatible"
        llm_provider.base_url = str(llm_provider.base_url or "").strip().rstrip("/")
        llm_provider.api_key = str(llm_provider.api_key or "").strip()
        llm_provider.model = str(llm_provider.model or "").strip()
        llm_provider.temperature = _as_float(llm_provider.temperature, 0.0)
        llm_provider.timeout_sec = max(1.0, _as_float(llm_provider.timeout_sec, 30.0))
        llm_provider.max_output_tokens = max(
            1,
            _as_int(llm_provider.max_output_tokens, 4096),
        )
        llm_provider.max_tokens_parameter = str(llm_provider.max_tokens_parameter).strip().lower()
        if llm_provider.max_tokens_parameter not in {
            "max_tokens",
            "max_completion_tokens",
            "none",
        }:
            llm_provider.max_tokens_parameter = "max_tokens"
        llm_provider.send_temperature = _as_bool(llm_provider.send_temperature, True)
        llm_provider.structured_output = str(llm_provider.structured_output).strip().lower()
        if llm_provider.api_style == "anthropic_messages":
            llm_provider.structured_output = "prompt_only"
        if llm_provider.structured_output not in {
            "auto",
            "json_schema",
            "json_object",
            "prompt_only",
        }:
            llm_provider.structured_output = "auto"
        if not isinstance(llm_provider.limits, ProviderLimitOptions):
            llm_provider.limits = ProviderLimitOptions()
        limits = llm_provider.limits
        limits.mode = str(limits.mode or "").strip().lower()
        if limits.mode not in {"auto", "auto_cap", "manual"}:
            limits.mode = "auto"
        limits.quota_group = str(limits.quota_group or "").strip()
        for field_name in (
            "requests_per_minute",
            "requests_per_hour",
            "requests_per_day",
            "input_tokens_per_minute",
            "output_tokens_per_minute",
            "tokens_per_minute",
            "tokens_per_hour",
            "tokens_per_day",
            "context_tokens",
            "max_domains_per_request",
        ):
            setattr(limits, field_name, max(0, _as_int(getattr(limits, field_name), 0)))
        limits.units_per_day = max(0.0, _as_float(limits.units_per_day, 0.0))
        limits.safety_margin_percent = min(
            50.0,
            max(0.0, _as_float(limits.safety_margin_percent, 10.0)),
        )

    options.prompt_profiles = options.prompt_profiles or [PromptProfileOptions()]
    for profile in options.prompt_profiles:
        profile.name = str(profile.name or "Unnamed profile")
        profile.system = str(profile.system or "")
        profile.user_template = str(profile.user_template or "")
    supported_research_kinds = {
        "adguard_services",
        "dns_records",
        "disconnect_tracking",
        "rdap",
        "ripestat",
        "netcraft",
        "virustotal",
        "threatfox",
        "phishtank",
        "urlscan",
        "cloudflare_radar",
        "repository_lists",
    }
    options.research_providers = [
        provider
        for provider in options.research_providers
        if str(provider.kind).strip().lower() in supported_research_kinds
    ]
    configured_kinds = {
        str(provider.kind).strip().lower() for provider in options.research_providers
    }
    for default_provider in Options().research_providers:
        if default_provider.kind not in configured_kinds:
            options.research_providers.append(default_provider)
    for research_provider in options.research_providers:
        research_provider.name = str(research_provider.name or "Unnamed source")
        research_provider.kind = str(research_provider.kind).strip().lower()
        research_provider.enabled = _as_bool(research_provider.enabled, False)
        research_provider.base_url = str(research_provider.base_url or "").strip()
        research_provider.api_key = str(research_provider.api_key or "").strip()
        research_provider.test_domain = str(research_provider.test_domain or "").strip().lower()
        if research_provider.kind == "rdap" and not research_provider.base_url.strip():
            research_provider.base_url = "https://data.iana.org/rdap/dns.json"
        research_provider.timeout_sec = max(
            1.0,
            _as_float(research_provider.timeout_sec, 15.0),
        )
        research_provider.min_interval_sec = max(
            0.0,
            _as_float(research_provider.min_interval_sec, 1.0),
        )
        research_provider.refresh_interval_hours = max(
            1,
            _as_int(research_provider.refresh_interval_hours, 24),
        )
        research_provider.max_results = max(
            1,
            _as_int(research_provider.max_results, 5),
        )

    options.llm.active_provider_index = min(
        max(0, _as_int(options.llm.active_provider_index, 0)),
        len(options.llm_providers) - 1,
    )
    options.llm.active_profile_index = min(
        max(0, _as_int(options.llm.active_profile_index, 0)),
        len(options.prompt_profiles) - 1,
    )
    provider_ids = {provider.provider_id for provider in options.llm_providers}
    pools_by_id: dict[str, AnalysisPoolOptions] = {}
    for pool in options.analysis_pools:
        pool_id = str(pool.pool_id or "").strip().lower()
        if pool_id not in {"realtime", "background"} or pool_id in pools_by_id:
            continue
        pool.pool_id = pool_id
        pool.name = str(
            pool.name or ("Realtime analysis" if pool_id == "realtime" else "Background analysis")
        )
        pool.enabled = _as_bool(pool.enabled, True)
        pool.mode = str(pool.mode or "").strip().lower()
        if pool.mode not in {"distribute", "fallback", "compare", "verify"}:
            pool.mode = "fallback" if pool_id == "realtime" else "distribute"
        pool.profile_index = min(
            max(0, _as_int(pool.profile_index, options.llm.active_profile_index)),
            len(options.prompt_profiles) - 1,
        )
        pool.max_parallel_requests = min(
            16,
            max(1, _as_int(pool.max_parallel_requests, 2)),
        )
        pool.verification_sample_percent = min(
            100,
            max(0, _as_int(pool.verification_sample_percent, 10)),
        )
        pool.verify_automatic_actions = _as_bool(pool.verify_automatic_actions, True)
        pool.verify_security_risk_at_least = min(
            100,
            max(0, _as_int(pool.verify_security_risk_at_least, 80)),
        )
        pool.verify_breakage_risk_at_least = min(
            100,
            max(0, _as_int(pool.verify_breakage_risk_at_least, 50)),
        )
        memberships: list[ProviderPoolMembershipOptions] = []
        seen_memberships: set[str] = set()
        for membership in pool.memberships:
            provider_id = str(membership.provider_id or "").strip()
            if provider_id not in provider_ids or provider_id in seen_memberships:
                continue
            membership.provider_id = provider_id
            membership.enabled = _as_bool(membership.enabled, True)
            membership.role = str(membership.role or "").strip().lower()
            if membership.role not in {"primary", "fallback", "verifier"}:
                membership.role = "primary"
            membership.priority = min(
                10_000,
                max(0, _as_int(membership.priority, 100)),
            )
            membership.weight = min(100, max(1, _as_int(membership.weight, 1)))
            memberships.append(membership)
            seen_memberships.add(provider_id)
        if not memberships:
            memberships.append(
                ProviderPoolMembershipOptions(
                    provider_id=options.llm_providers[options.llm.active_provider_index].provider_id
                )
            )
        pool.memberships = memberships
        pools_by_id[pool_id] = pool
    active_provider_id = options.llm_providers[options.llm.active_provider_index].provider_id
    for pool_id in ("realtime", "background"):
        if pool_id not in pools_by_id:
            pool = _coerce_dataclass(
                AnalysisPoolOptions,
                _default_analysis_pool(
                    pool_id,
                    active_provider_id,
                    profile_index=options.llm.active_profile_index,
                ),
            )
            pool.memberships = [ProviderPoolMembershipOptions(provider_id=active_provider_id)]
            pools_by_id[pool_id] = pool
    options.analysis_pools = [
        pools_by_id["realtime"],
        pools_by_id["background"],
    ]
    return options


def load_options() -> Options:
    path = options_path()
    with _CONFIG_LOCK:
        if not path.exists():
            options = _validate(Options())
            hydrate_credentials(options)
            save_options(options)
            return options
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _validate(Options())

        if not isinstance(raw, dict):
            return _validate(Options())
        try:
            raw = _migrate(raw)
            options = Options(
                schema_version=int(raw.get("schema_version", CURRENT_SCHEMA_VERSION)),
                logging=_coerce_dataclass(LoggingOptions, raw.get("logging")),
                notify=_coerce_dataclass(NotifyOptions, raw.get("notify")),
                scans=_coerce_dataclass(ScanOptions, raw.get("scans")),
                pihole=_coerce_dataclass(PiHoleOptions, raw.get("pihole")),
                llm=_coerce_dataclass(LLMOptions, raw.get("llm")),
                research=_coerce_dataclass(ResearchOptions, raw.get("research")),
                updates=_coerce_dataclass(UpdateOptions, raw.get("updates")),
                provider_registry=_coerce_dataclass(
                    ProviderRegistryOptions,
                    raw.get("provider_registry"),
                ),
                external_trigger=_coerce_dataclass(
                    ExternalTriggerOptions,
                    raw.get("external_trigger"),
                ),
                llm_providers=_load_llm_providers(raw.get("llm_providers")),
                analysis_pools=_load_analysis_pools(raw.get("analysis_pools")),
                prompt_profiles=_load_list(
                    raw.get("prompt_profiles"),
                    PromptProfileOptions,
                    [PromptProfileOptions()],
                ),
                research_providers=_load_list(
                    raw.get("research_providers"),
                    ResearchProviderOptions,
                    Options().research_providers,
                ),
                ui=_coerce_dataclass(UIOptions, raw.get("ui")),
            )
            options = _validate(options)
            if hydrate_credentials(options):
                save_options(options)
            return options
        except UnsupportedConfigVersionError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            log.warning("Invalid configuration; using safe defaults: %s", exc)
            return _validate(Options())


def save_options(options: Options) -> None:
    if not is_dataclass(options):
        raise TypeError("options must be an Options instance")
    options = _validate(options)
    path = options_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        secure_options_payload(options),
        indent=2,
        ensure_ascii=False,
    ) + "\n"
    with _CONFIG_LOCK:
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent, delete=False
            ) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)
            os.replace(temp_path, path)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
