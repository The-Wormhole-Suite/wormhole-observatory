from __future__ import annotations

import ipaddress
import re

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def domain_from_list_rule(rule: str) -> str:
    value = str(rule).strip()
    if not value or value.startswith(("!", "#", "[", "@@")):
        return ""

    if value.startswith("||"):
        candidate = value[2:].split("$", 1)[0]
        candidate = candidate.split("^", 1)[0].strip("|/")
        if not candidate or any(character in candidate for character in "*[]()\\"):
            return ""
        return _validated_domain(candidate)

    fields = value.split()
    if len(fields) >= 2 and _is_ip_address(fields[0]):
        return _validated_domain(fields[1])

    if len(fields) == 1 and not any(character in value for character in "/^$|*=,;()[]\\"):
        return _validated_domain(value)

    return ""


def _validated_domain(value: str) -> str:
    normalized = str(value).strip().lower().rstrip(".")
    if not normalized or len(normalized) > 253 or "." not in normalized:
        return ""
    if _is_ip_address(normalized):
        return ""
    try:
        ascii_domain = normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = ascii_domain.split(".")
    if any(not label or len(label) > 63 or not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return ""
    return normalized


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
