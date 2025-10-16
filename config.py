# Robust, minimal config.py (no tricky triple-quoted strings)
from __future__ import annotations
import json, os, threading
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "options.json")
_lock = threading.RLock()

# ---- Dataclasses -----------------------------------------------------------

@dataclass
class LLMProvider:
    name: str = "default"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.1

@dataclass
class ScanOptions:
    enabled: bool = False
    interval_seconds: int = 300
    batch_size: int = 50
    parallel: int = 3
    recheck_even_if_annotated: bool = False

@dataclass
class AutomationRules:
    auto_allow: bool = False
    auto_block: bool = False
    require_confirmation: bool = True
    dry_run: bool = True

@dataclass
class NotifyOptions:
    telegram_token: str = ""
    telegram_chat_id: str = ""
    signal_number: str = ""
    homeassistant_webhook: str = ""
    enabled_channels: List[str] = field(default_factory=lambda: [])  # ["telegram", "signal", "homeassistant"]

@dataclass
class LoggingOptions:
    enabled: bool = True
    level: str = "INFO"  # DEBUG/INFO/WARNING/ERROR
    file_path: str = os.path.join(os.path.dirname(__file__), "pihole_manager.log")
    rotate_bytes: int = 5 * 1024 * 1024
    backup_count: int = 3

@dataclass
class PiHoleOptions:
    host: str = "http://pi.hole"
    verify_tls: bool = False
    app_password: str = ""

@dataclass
class PromptProfile:
    name: str = "balanced"
    system: str = "You are a helpful security assistant. Classify domains."
    user_template: str = (
        "Classify the domain '{{domain}}' into categories: "
        "tracker, ads, analytics, cdn, content, login, mail, update, iot, malicious, phishing, spam, adult, crypto-mining, unknown.\n"
        "Return JSON with keys: category, policy(one of allow/block/manual_review), short, details."
    )

@dataclass
class Options:
    schema_version: int = 1
    pihole: PiHoleOptions = field(default_factory=PiHoleOptions)
    llm_providers: List[LLMProvider] = field(default_factory=lambda: [LLMProvider()])
    prompt_profiles: List[PromptProfile] = field(default_factory=lambda: [PromptProfile()])
    scans: ScanOptions = field(default_factory=ScanOptions)
    automation: AutomationRules = field(default_factory=AutomationRules)
    notify: NotifyOptions = field(default_factory=NotifyOptions)
    logging: LoggingOptions = field(default_factory=LoggingOptions)

# ---- Helpers ---------------------------------------------------------------

def _validate(opts: Options) -> Options:
    opts.scans.interval_seconds = max(10, int(opts.scans.interval_seconds))
    opts.scans.batch_size = max(1, int(opts.scans.batch_size))
    opts.scans.parallel = max(1, int(opts.scans.parallel))
    if opts.logging.level.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        opts.logging.level = "INFO"
    return opts

def _merge(default_obj, src: Dict[str, Any]):
    """Merge a flat dict into a dataclass instance and return a new instance."""
    data = asdict(default_obj)
    if src:
        data.update(src)
    return type(default_obj)(**data)

# ---- API ------------------------------------------------------------------

def load_options() -> Options:
    with _lock:
        if not os.path.exists(CONFIG_FILE):
            opts = Options()
            save_options(opts)
            return opts
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            raw: Dict[str, Any] = json.load(f)

        opts = Options()
        # top-level
        opts.schema_version = int(raw.get("schema_version", opts.schema_version))
        # nested objects
        opts.pihole = _merge(PiHoleOptions(), raw.get("pihole"))
        opts.scans = _merge(ScanOptions(), raw.get("scans"))
        opts.automation = _merge(AutomationRules(), raw.get("automation"))
        opts.notify = _merge(NotifyOptions(), raw.get("notify"))
        opts.logging = _merge(LoggingOptions(), raw.get("logging"))
        # lists of dataclasses
        raw_providers = raw.get("llm_providers") or []
        if raw_providers:
            opts.llm_providers = [_merge(LLMProvider(), p) for p in raw_providers]
        raw_profiles = raw.get("prompt_profiles") or []
        if raw_profiles:
            opts.prompt_profiles = [_merge(PromptProfile(), p) for p in raw_profiles]
        return _validate(opts)

def save_options(opts: Options) -> None:
    with _lock:
        opts = _validate(opts)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(opts), f, indent=2, ensure_ascii=False)
