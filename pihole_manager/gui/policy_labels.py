from __future__ import annotations

from pihole_manager.models import Policy

_POLICY_TO_LABEL = {
    Policy.ALLOW.value: "whitelist",
    Policy.DENY.value: "blacklist",
    Policy.MANUAL_REVIEW.value: "manual_review",
    Policy.UNKNOWN.value: "unknown",
}
_LABEL_TO_POLICY = {value: key for key, value in _POLICY_TO_LABEL.items()}


def policy_label(value: str | Policy) -> str:
    raw = value.value if isinstance(value, Policy) else str(value)
    return _POLICY_TO_LABEL.get(raw.strip().lower(), raw.strip().lower())


def policy_value(value: str) -> str:
    raw = str(value).strip().lower()
    return _LABEL_TO_POLICY.get(raw, raw)


def action_label(value: str | Policy) -> str:
    label = policy_label(value)
    if label == "whitelist":
        return "Whitelist"
    if label == "blacklist":
        return "Blacklist"
    return label.replace("_", " ").title()


def status_label(value: str) -> str:
    raw = str(value).strip()
    return raw.replace("allow", "whitelist").replace("deny", "blacklist").replace("_", " ")
