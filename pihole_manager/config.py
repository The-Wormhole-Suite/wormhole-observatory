from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeVar

from pihole_manager.models import AutomationMode, Policy

T = TypeVar("T")
_CONFIG_LOCK = threading.RLock()
CURRENT_SCHEMA_VERSION = 3


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


@dataclass(slots=True)
class PiHoleOptions:
    base_url: str = "http://pi.hole"
    password: str = ""
    verify_tls: bool = True
    timeout_sec: float = 10.0


@dataclass(slots=True)
class LLMProviderOptions:
    name: str = "Local or OpenAI-compatible"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.0
    timeout_sec: float = 30.0
    structured_output: str = "auto"


@dataclass(slots=True)
class PromptProfileOptions:
    name: str = "Balanced"
    system: str = (
        "You classify DNS domains for a Pi-hole v6 administrator. "
        "Use the supplied evidence, distinguish facts from inference, and prefer "
        "manual review when evidence is weak or blocking may break an important service."
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


@dataclass(slots=True)
class LLMOptions:
    enabled: bool = False
    interval_sec: int = 10
    worker_batch_size: int = 25
    domains_per_request: int = 10
    min_request_interval_sec: float = 1.0
    max_retries: int = 2
    active_provider_index: int = 0
    active_profile_index: int = 0
    automation_mode: str = AutomationMode.HYBRID.value
    default_recheck_days: int = 30
    review_confidence_threshold: float = 0.75
    auto_action_min_confidence: float = 0.95
    tags: list[str] = field(default_factory=lambda: list(_DEFAULT_TAGS))
    tag_policies: dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_TAG_POLICIES)
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
    enabled: bool = False
    run_before_llm: bool = True
    max_age_days: int = 30
    timeout_sec: float = 15.0
    max_results_per_provider: int = 5


@dataclass(slots=True)
class ResearchProviderOptions:
    name: str = "RDAP registration data"
    kind: str = "rdap"
    enabled: bool = True
    base_url: str = ""
    api_key: str = ""
    timeout_sec: float = 15.0
    min_interval_sec: float = 1.0
    max_results: int = 5


@dataclass(slots=True)
class LockOptions:
    enabled: bool = True
    reconcile_interval_sec: int = 60


@dataclass(slots=True)
class UIOptions:
    theme: str = "system"
    window_width: int = 1280
    window_height: int = 820
    auto_update_queries: bool = True
    query_refresh_ms: int = 2_000
    auto_scroll_queries: bool = True
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


@dataclass(slots=True)
class Options:
    schema_version: int = CURRENT_SCHEMA_VERSION
    logging: LoggingOptions = field(default_factory=LoggingOptions)
    notify: NotifyOptions = field(default_factory=NotifyOptions)
    scans: ScanOptions = field(default_factory=ScanOptions)
    pihole: PiHoleOptions = field(default_factory=PiHoleOptions)
    llm: LLMOptions = field(default_factory=LLMOptions)
    research: ResearchOptions = field(default_factory=ResearchOptions)
    locks: LockOptions = field(default_factory=LockOptions)
    llm_providers: list[LLMProviderOptions] = field(
        default_factory=lambda: [LLMProviderOptions()]
    )
    prompt_profiles: list[PromptProfileOptions] = field(
        default_factory=lambda: [PromptProfileOptions()]
    )
    research_providers: list[ResearchProviderOptions] = field(
        default_factory=lambda: [
            ResearchProviderOptions(),
            ResearchProviderOptions(
                name="GitHub code and list search",
                kind="github_code",
                enabled=False,
                base_url="https://api.github.com",
                min_interval_sec=6.5,
            ),
            ResearchProviderOptions(
                name="Brave web search",
                kind="brave_search",
                enabled=False,
                base_url="https://api.search.brave.com/res/v1/web/search",
            ),
            ResearchProviderOptions(
                name="VirusTotal domain report",
                kind="virustotal",
                enabled=False,
                base_url="https://www.virustotal.com/api/v3",
                min_interval_sec=15.5,
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
    valid_fields = {item.name for item in fields(instance)}
    for key, value in raw.items():
        if key in valid_fields:
            setattr(instance, key, value)
    return instance


def _load_list(raw: Any, cls: type[T], fallback: list[T]) -> list[T]:
    if not isinstance(raw, list):
        return fallback
    loaded = [_coerce_dataclass(cls, item) for item in raw if isinstance(item, dict)]
    return loaded or fallback


def _migrate(raw: dict[str, Any]) -> dict[str, Any]:
    data = dict(raw)
    pihole = dict(data.get("pihole") or {})
    pihole["base_url"] = pihole.get("base_url") or pihole.get("host") or "http://pi.hole"
    pihole["password"] = pihole.get("password") or pihole.get("app_password") or ""
    data["pihole"] = pihole

    logging_raw = dict(data.get("logging") or {})
    logging_raw["enabled"] = logging_raw.get(
        "enabled", logging_raw.get("to_file", True)
    )
    logging_raw["filename"] = (
        logging_raw.get("filename") or logging_raw.get("file") or "pihole_manager.log"
    )
    data["logging"] = logging_raw

    scans = dict(data.get("scans") or {})
    scans["batch_size"] = scans.get("batch_size", scans.get("batch", 200))
    data["scans"] = scans

    llm = dict(data.get("llm") or {})
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
    data["llm"] = llm
    data["schema_version"] = CURRENT_SCHEMA_VERSION
    return data


def _normalize_tags(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return list(
        dict.fromkeys(
            str(value).strip().lower().replace(" ", "_")
            for value in values
            if str(value).strip()
        )
    )


def _validate(options: Options) -> Options:
    options.schema_version = CURRENT_SCHEMA_VERSION
    options.logging.level = options.logging.level.upper()
    if options.logging.level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        options.logging.level = "INFO"
    options.logging.rotate_bytes = max(100_000, int(options.logging.rotate_bytes))
    options.logging.backup_count = max(1, int(options.logging.backup_count))

    options.scans.interval_sec = max(1, int(options.scans.interval_sec))
    options.scans.batch_size = max(1, int(options.scans.batch_size))
    options.scans.initial_lookback_sec = max(1, int(options.scans.initial_lookback_sec))
    options.scans.queue_trigger_size = max(1, int(options.scans.queue_trigger_size))
    options.scans.max_queue_wait_sec = max(1, int(options.scans.max_queue_wait_sec))

    options.pihole.timeout_sec = max(1.0, float(options.pihole.timeout_sec))

    options.llm.interval_sec = max(1, int(options.llm.interval_sec))
    options.llm.worker_batch_size = max(1, int(options.llm.worker_batch_size))
    options.llm.domains_per_request = min(
        options.llm.worker_batch_size, max(1, int(options.llm.domains_per_request))
    )
    options.llm.min_request_interval_sec = max(
        0.0, float(options.llm.min_request_interval_sec)
    )
    options.llm.max_retries = max(0, int(options.llm.max_retries))
    options.llm.default_recheck_days = max(1, int(options.llm.default_recheck_days))
    options.llm.review_confidence_threshold = min(
        1.0, max(0.0, float(options.llm.review_confidence_threshold))
    )
    options.llm.auto_action_min_confidence = min(
        1.0, max(0.0, float(options.llm.auto_action_min_confidence))
    )
    valid_modes = {item.value for item in AutomationMode}
    if options.llm.automation_mode not in valid_modes:
        options.llm.automation_mode = AutomationMode.HYBRID.value

    options.llm.tags = _normalize_tags(options.llm.tags) or ["unknown"]
    options.llm.tag_policies = {
        str(key).strip().lower().replace(" ", "_"): str(value).strip().lower()
        for key, value in options.llm.tag_policies.items()
        if str(key).strip()
    }
    for tag in options.llm.tags:
        options.llm.tag_policies.setdefault(tag, Policy.MANUAL_REVIEW.value)

    options.research.max_age_days = max(1, int(options.research.max_age_days))
    options.research.timeout_sec = max(1.0, float(options.research.timeout_sec))
    options.research.max_results_per_provider = max(
        1, int(options.research.max_results_per_provider)
    )
    options.locks.reconcile_interval_sec = max(
        5, int(options.locks.reconcile_interval_sec)
    )

    options.ui.query_refresh_ms = max(500, int(options.ui.query_refresh_ms))
    options.ui.window_width = max(800, int(options.ui.window_width))
    options.ui.window_height = max(600, int(options.ui.window_height))

    options.llm_providers = options.llm_providers or [LLMProviderOptions()]
    for provider in options.llm_providers:
        provider.timeout_sec = max(1.0, float(provider.timeout_sec))
        if provider.structured_output not in {
            "auto",
            "json_schema",
            "json_object",
            "prompt_only",
        }:
            provider.structured_output = "auto"

    options.prompt_profiles = options.prompt_profiles or [PromptProfileOptions()]
    options.research_providers = options.research_providers or [ResearchProviderOptions()]
    for provider in options.research_providers:
        provider.kind = provider.kind.strip().lower()
        provider.timeout_sec = max(1.0, float(provider.timeout_sec))
        provider.min_interval_sec = max(0.0, float(provider.min_interval_sec))
        provider.max_results = max(1, int(provider.max_results))

    options.llm.active_provider_index = min(
        max(0, int(options.llm.active_provider_index)), len(options.llm_providers) - 1
    )
    options.llm.active_profile_index = min(
        max(0, int(options.llm.active_profile_index)), len(options.prompt_profiles) - 1
    )
    return options


def load_options() -> Options:
    path = options_path()
    with _CONFIG_LOCK:
        if not path.exists():
            options = _validate(Options())
            save_options(options)
            return options
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return _validate(Options())

        if not isinstance(raw, dict):
            return _validate(Options())
        raw = _migrate(raw)
        options = Options(
            schema_version=int(raw.get("schema_version", CURRENT_SCHEMA_VERSION)),
            logging=_coerce_dataclass(LoggingOptions, raw.get("logging")),
            notify=_coerce_dataclass(NotifyOptions, raw.get("notify")),
            scans=_coerce_dataclass(ScanOptions, raw.get("scans")),
            pihole=_coerce_dataclass(PiHoleOptions, raw.get("pihole")),
            llm=_coerce_dataclass(LLMOptions, raw.get("llm")),
            research=_coerce_dataclass(ResearchOptions, raw.get("research")),
            locks=_coerce_dataclass(LockOptions, raw.get("locks")),
            llm_providers=_load_list(
                raw.get("llm_providers"), LLMProviderOptions, [LLMProviderOptions()]
            ),
            prompt_profiles=_load_list(
                raw.get("prompt_profiles"), PromptProfileOptions, [PromptProfileOptions()]
            ),
            research_providers=_load_list(
                raw.get("research_providers"),
                ResearchProviderOptions,
                Options().research_providers,
            ),
            ui=_coerce_dataclass(UIOptions, raw.get("ui")),
        )
        return _validate(options)


def save_options(options: Options) -> None:
    if not is_dataclass(options):
        raise TypeError("options must be an Options instance")
    options = _validate(options)
    path = options_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(asdict(options), indent=2, ensure_ascii=False) + "\n"
    with _CONFIG_LOCK:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            handle.write(payload)
            temp_name = handle.name
        os.replace(temp_name, path)
