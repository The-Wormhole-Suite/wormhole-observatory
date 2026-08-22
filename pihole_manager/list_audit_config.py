from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from pihole_manager.database import get_state, set_state

_STATE_KEY = "list_audit_options"


@dataclass(slots=True)
class ListAuditOptions:
    enabled: bool = False
    interval_sec: int = 86_400
    batch_size: int = 100
    rate_limit_sec: float = 2.0
    max_domains_per_list: int = 5_000


def normalize_list_audit_options(options: ListAuditOptions) -> ListAuditOptions:
    options.enabled = bool(options.enabled)
    options.interval_sec = max(300, int(options.interval_sec))
    options.batch_size = min(5_000, max(1, int(options.batch_size)))
    options.rate_limit_sec = min(3_600.0, max(0.0, float(options.rate_limit_sec)))
    options.max_domains_per_list = min(100_000, max(1, int(options.max_domains_per_list)))
    return options


def load_list_audit_options() -> ListAuditOptions:
    raw = get_state(_STATE_KEY, "") or ""
    if not raw:
        return ListAuditOptions()
    try:
        data = json.loads(raw)
        options = ListAuditOptions(
            enabled=bool(data.get("enabled", False)),
            interval_sec=int(data.get("interval_sec", 86_400)),
            batch_size=int(data.get("batch_size", 100)),
            rate_limit_sec=float(data.get("rate_limit_sec", 2.0)),
            max_domains_per_list=int(data.get("max_domains_per_list", 5_000)),
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        return ListAuditOptions()
    return normalize_list_audit_options(options)


def save_list_audit_options(options: ListAuditOptions) -> ListAuditOptions:
    normalized = normalize_list_audit_options(options)
    set_state(_STATE_KEY, json.dumps(asdict(normalized), sort_keys=True))
    return normalized
