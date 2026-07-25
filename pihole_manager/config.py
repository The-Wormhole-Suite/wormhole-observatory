from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, TypeVar

from pihole_manager.models import AutomationMode

T = TypeVar("T")
_CONFIG_LOCK = threading.RLock()


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


@dataclass(slots=True)
class PromptProfileOptions:
    name: str = "Default"
    system: str = (
        "You classify DNS domains for a Pi-hole v6 administrator. "
        "Be conservative and prefer manual review when evidence is weak."
    )
    user_template: str = "Classify the domain: {domain}"


@dataclass(slots=True)
class LLMOptions:
    enabled: bool = False
    interval_sec: int = 10
    batch_size: int = 25
    active_provider_index: int = 0
    active_profile_index: int = 0
    automation_mode: str = AutomationMode.HYBRID.value
    categories: list[str] = field(
        default_factory=lambda: [
            "ads",
            "analytics",
            "cdn",
            "content",
            "essential",
            "malicious",
            "telemetry",
            "tracker",
            "unknown",
        ]
    )
    category_policies: dict[str, str] = field(
        default_factory=lambda: {
            "ads": "deny",
            "analytics": "manual_review",
            "cdn": "allow",
            "content": "allow",
            "essential": "allow",
            "malicious": "deny",
            "telemetry": "manual_review",
            "tracker": "deny",
            "unknown": "manual_review",
        }
    )


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
    schema_version: int = 2
    logging: LoggingOptions = field(default_factory=LoggingOptions)
    notify: NotifyOptions = field(default_factory=NotifyOptions)
    scans: ScanOptions = field(default_factory=ScanOptions)
    pihole: PiHoleOptions = field(default_factory=PiHoleOptions)
    llm: LLMOptions = field(default_factory=LLMOptions)
    llm_providers: list[LLMProviderOptions] = field(
        default_factory=lambda: [LLMProviderOptions()]
    )
    prompt_profiles: list[PromptProfileOptions] = field(
        default_factory=lambda: [PromptProfileOptions()]
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


def _load_list(raw: Any, cls: type[T], fallback: T) -> list[T]:
    if not isinstance(raw, list):
        return [fallback]
    loaded = [_coerce_dataclass(cls, item) for item in raw if isinstance(item, dict)]
    return loaded or [fallback]


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
    llm["batch_size"] = llm.get("batch_size", llm.get("batch", 25))
    data["llm"] = llm
    data["schema_version"] = 2
    return data


def _validate(options: Options) -> Options:
    options.logging.level = options.logging.level.upper()
    if options.logging.level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        options.logging.level = "INFO"
    options.logging.rotate_bytes = max(100_000, int(options.logging.rotate_bytes))
    options.logging.backup_count = max(1, int(options.logging.backup_count))

    options.scans.interval_sec = max(1, int(options.scans.interval_sec))
    options.scans.batch_size = max(1, int(options.scans.batch_size))
    options.scans.initial_lookback_sec = max(1, int(options.scans.initial_lookback_sec))

    options.pihole.timeout_sec = max(1.0, float(options.pihole.timeout_sec))

    options.llm.interval_sec = max(1, int(options.llm.interval_sec))
    options.llm.batch_size = max(1, int(options.llm.batch_size))
    valid_modes = {item.value for item in AutomationMode}
    if options.llm.automation_mode not in valid_modes:
        options.llm.automation_mode = AutomationMode.HYBRID.value

    options.llm.categories = list(dict.fromkeys(
        str(category).strip().lower()
        for category in options.llm.categories
        if str(category).strip()
    ))
    if not options.llm.categories:
        options.llm.categories = ["unknown"]
    options.llm.category_policies = {
        str(key).strip().lower(): str(value).strip().lower()
        for key, value in options.llm.category_policies.items()
        if str(key).strip()
    }

    options.ui.query_refresh_ms = max(500, int(options.ui.query_refresh_ms))
    options.ui.window_width = max(800, int(options.ui.window_width))
    options.ui.window_height = max(600, int(options.ui.window_height))

    options.llm_providers = options.llm_providers or [LLMProviderOptions()]
    options.prompt_profiles = options.prompt_profiles or [PromptProfileOptions()]
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
            schema_version=int(raw.get("schema_version", 2)),
            logging=_coerce_dataclass(LoggingOptions, raw.get("logging")),
            notify=_coerce_dataclass(NotifyOptions, raw.get("notify")),
            scans=_coerce_dataclass(ScanOptions, raw.get("scans")),
            pihole=_coerce_dataclass(PiHoleOptions, raw.get("pihole")),
            llm=_coerce_dataclass(LLMOptions, raw.get("llm")),
            llm_providers=_load_list(
                raw.get("llm_providers"), LLMProviderOptions, LLMProviderOptions()
            ),
            prompt_profiles=_load_list(
                raw.get("prompt_profiles"), PromptProfileOptions, PromptProfileOptions()
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
