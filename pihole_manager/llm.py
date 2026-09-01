from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import requests

from pihole_manager.cancellation import CancellationToken, raise_if_cancelled
from pihole_manager.config import (
    LLMOptions,
    LLMProviderOptions,
    Options,
    PromptProfileOptions,
    load_options,
)
from pihole_manager.models import Classification, Policy, ServiceRole
from pihole_manager.provider_api import (
    ProviderRequestContext,
    ProviderResponse,
    request_provider,
    request_provider_text,
)
from pihole_manager.provider_registry import ProviderLimitProfile
from pihole_manager.quota import estimate_provider_usage

log = logging.getLogger(__name__)


class LLMResponseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ClassificationBatchResult:
    classifications: tuple[Classification, ...]
    response: ProviderResponse


_RESULT_FIELDS = {
    "domain",
    "policy",
    "category",
    "tags",
    "service",
    "service_role",
    "privacy_risk",
    "security_risk",
    "breakage_risk",
    "confidence",
    "needs_review",
    "review_reason",
    "recheck_after_days",
    "short",
    "details",
}


def _active_provider(options: Options | None = None) -> LLMProviderOptions | None:
    options = options or load_options()
    if not options.llm_providers:
        return None
    return options.llm_providers[options.llm.active_provider_index]


def _active_profile(options: Options | None = None) -> PromptProfileOptions:
    options = options or load_options()
    return options.prompt_profiles[options.llm.active_profile_index]


def _chat_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    if not value:
        raise ValueError("LLM provider base URL is empty")
    if value.endswith("/chat/completions"):
        return value
    if value.endswith("/v1"):
        return f"{value}/chat/completions"
    return f"{value}/v1/chat/completions"


def classification_schema(tags: Sequence[str]) -> dict[str, Any]:
    allowed_tags = list(dict.fromkeys(str(tag).strip().lower() for tag in tags if str(tag).strip()))
    if "unknown" not in allowed_tags:
        allowed_tags.append("unknown")
    result_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "domain",
            "policy",
            "category",
            "tags",
            "service",
            "service_role",
            "privacy_risk",
            "security_risk",
            "breakage_risk",
            "confidence",
            "needs_review",
            "review_reason",
            "recheck_after_days",
            "short",
            "details",
        ],
        "properties": {
            "domain": {"type": "string"},
            "policy": {
                "type": "string",
                "enum": ["allow", "deny", "manual_review"],
            },
            "category": {"type": "string", "enum": allowed_tags},
            "tags": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string", "enum": allowed_tags},
            },
            "service": {"type": "string"},
            "service_role": {
                "type": "string",
                "enum": ["core", "optional", "shared", "unknown"],
            },
            "privacy_risk": {"type": "integer", "minimum": 0, "maximum": 100},
            "security_risk": {"type": "integer", "minimum": 0, "maximum": 100},
            "breakage_risk": {"type": "integer", "minimum": 0, "maximum": 100},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "needs_review": {"type": "boolean"},
            "review_reason": {"type": "string"},
            "recheck_after_days": {"type": "integer", "minimum": 1, "maximum": 3650},
            "short": {"type": "string"},
            "details": {"type": "string"},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "results"],
        "properties": {
            "schema_version": {"type": "integer", "enum": [1]},
            "results": {"type": "array", "minItems": 1, "items": result_schema},
        },
    }


def build_messages(
    profile: PromptProfileOptions,
    domain: str,
    dossier: Mapping[str, Any] | None = None,
) -> list[dict[str, str]]:
    selected = dict(dossier or {})
    selected.setdefault("domain", domain)
    return build_batch_messages(profile, [selected])


def build_batch_messages(
    profile: PromptProfileOptions,
    dossiers: Sequence[Mapping[str, Any]],
    *,
    llm_options: LLMOptions | None = None,
) -> list[dict[str, str]]:
    options = llm_options or load_options().llm
    tags = list(options.tags)
    policies = {tag: options.tag_policies.get(tag, Policy.MANUAL_REVIEW.value) for tag in tags}
    schema = classification_schema(tags)
    normalized_dossiers = [dict(item) for item in dossiers]
    domains = [str(item.get("domain") or "").strip().lower() for item in normalized_dossiers]
    variables = {
        "domain": domains[0] if domains else "",
        "domains": ", ".join(domains),
        "domain_dossiers": json.dumps(
            normalized_dossiers, ensure_ascii=False, indent=2, default=str
        ),
        "tags": json.dumps(tags, ensure_ascii=False),
        "policies": json.dumps(policies, ensure_ascii=False),
        "schema": json.dumps(schema, ensure_ascii=False),
    }
    try:
        user = profile.user_template.format_map(_StrictFormatMap(variables))
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Invalid user prompt template: {exc}") from exc

    policy_lines = "\n".join(f"- {tag}: {policies[tag]}" for tag in tags)
    technical = (
        "\n\nTechnical contract:\n"
        "- Return one JSON object and no prose outside it.\n"
        "- Return exactly one result for every supplied domain and no additional domains.\n"
        "- Tags describe purposes or technical roles; policy is only a recommendation.\n"
        "- Distinguish evidence from inference in details.\n"
        "- Set needs_review=true for weak evidence, shared infrastructure, high breakage risk, "
        "authentication, payments, updates, or conflicting evidence.\n"
        "- short must be suitable as a concise Pi-hole comment.\n"
        f"Allowed tags: {', '.join(tags)}.\n"
        f"Administrative default policies:\n{policy_lines}\n"
        f"Required JSON schema:\n{json.dumps(schema, ensure_ascii=False)}"
    )
    return [
        {"role": "system", "content": profile.system.strip() + technical},
        {"role": "user", "content": user},
    ]


def classify_domain(
    domain: str,
    provider: LLMProviderOptions | None = None,
    profile: PromptProfileOptions | None = None,
    dossier: Mapping[str, Any] | None = None,
    *,
    cancel_token: CancellationToken | None = None,
) -> Classification:
    return classify_domains(
        [domain],
        provider=provider,
        profile=profile,
        dossiers=[dossier or {"domain": domain}],
        cancel_token=cancel_token,
    )[0]


def classify_domains(
    domains: Sequence[str],
    *,
    provider: LLMProviderOptions | None = None,
    profile: PromptProfileOptions | None = None,
    dossiers: Sequence[Mapping[str, Any]] | None = None,
    cancel_token: CancellationToken | None = None,
) -> list[Classification]:
    raise_if_cancelled(cancel_token)
    normalized_domains = list(
        dict.fromkeys(domain.strip().lower().rstrip(".") for domain in domains if domain.strip())
    )
    if not normalized_domains:
        return []

    options = load_options()
    llm_options = options.llm
    selected_provider = provider or _active_provider(options)
    if selected_provider is None or not selected_provider.base_url.strip():
        raise RuntimeError("No LLM provider is configured")
    if not selected_provider.model.strip():
        raise RuntimeError("The active LLM provider has no model configured")
    selected_profile = profile or _active_profile(options)

    dossier_map = {
        str(item.get("domain") or "").strip().lower().rstrip("."): dict(item)
        for item in (dossiers or [])
    }
    normalized_dossiers = []
    for domain in normalized_domains:
        dossier = dossier_map.get(domain, {"domain": domain})
        dossier["domain"] = domain
        normalized_dossiers.append(dossier)

    messages = build_batch_messages(
        selected_profile,
        normalized_dossiers,
        llm_options=llm_options,
    )
    modes = (
        ["prompt_only"]
        if selected_provider.api_style == "anthropic_messages"
        else _structured_modes(selected_provider.structured_output)
    )
    last_error: Exception | None = None
    for mode in modes:
        raise_if_cancelled(cancel_token)
        response_format = _response_format(mode, llm_options.tags)
        try:
            text = request_provider_text(
                selected_provider,
                messages,
                response_format=response_format,
                cancel_token=cancel_token,
            )
            return parse_batch_classifications(
                text,
                normalized_domains,
                llm_options.tags,
                provider=selected_provider.name,
                llm_options=llm_options,
            )
        except (requests.RequestException, ValueError, LLMResponseError) as exc:
            last_error = exc
            if mode == modes[-1] or not _can_try_output_mode_fallback(exc):
                break
            log.info(
                "LLM output mode %s failed for provider %s; trying fallback: %s",
                mode,
                selected_provider.name,
                exc,
            )
    raise RuntimeError(f"LLM request failed: {last_error}") from last_error


def classify_domains_with_metadata(
    domains: Sequence[str],
    *,
    provider: LLMProviderOptions,
    profile: PromptProfileOptions,
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    pool_id: str,
    limit_profile: ProviderLimitProfile,
    cancel_token: CancellationToken | None = None,
) -> ClassificationBatchResult:
    raise_if_cancelled(cancel_token)
    normalized_domains = list(
        dict.fromkeys(domain.strip().lower().rstrip(".") for domain in domains if domain.strip())
    )
    if not normalized_domains:
        raise ValueError("At least one domain is required for provider analysis.")
    if not provider.base_url.strip():
        raise RuntimeError(f"LLM provider {provider.name} has no base URL configured")
    if not provider.model.strip():
        raise RuntimeError(f"LLM provider {provider.name} has no model configured")

    dossier_map = {
        str(item.get("domain") or "").strip().lower().rstrip("."): dict(item) for item in dossiers
    }
    normalized_dossiers: list[dict[str, Any]] = []
    for domain in normalized_domains:
        dossier = dossier_map.get(domain, {"domain": domain})
        dossier["domain"] = domain
        normalized_dossiers.append(dossier)

    messages = build_batch_messages(
        profile,
        normalized_dossiers,
        llm_options=options.llm,
    )
    estimate = estimate_provider_usage(
        messages,
        provider=provider,
        profile=limit_profile,
        domain_count=len(normalized_domains),
    )
    request_context = ProviderRequestContext(
        pool_id=pool_id,
        profile=limit_profile,
        llm_options=options.llm,
        estimate=estimate,
    )
    modes = (
        ["prompt_only"]
        if provider.api_style == "anthropic_messages"
        else _structured_modes(provider.structured_output)
    )
    last_error: Exception | None = None
    for mode in modes:
        raise_if_cancelled(cancel_token)
        try:
            response = request_provider(
                provider,
                messages,
                response_format=_response_format(mode, options.llm.tags),
                request_context=request_context,
                cancel_token=cancel_token,
            )
            classifications = parse_batch_classifications(
                response.text,
                normalized_domains,
                options.llm.tags,
                provider=provider.name,
                llm_options=options.llm,
            )
            return ClassificationBatchResult(
                classifications=tuple(classifications),
                response=response,
            )
        except (requests.RequestException, ValueError, LLMResponseError) as exc:
            last_error = exc
            if mode == modes[-1] or not _can_try_output_mode_fallback(exc):
                break
            log.info(
                "LLM output mode %s failed for provider %s; trying fallback: %s",
                mode,
                provider.name,
                exc,
            )
    raise RuntimeError(f"LLM request failed: {last_error}") from last_error


def _can_try_output_mode_fallback(exc: Exception) -> bool:
    if isinstance(exc, requests.HTTPError):
        response = exc.response
        return response is not None and response.status_code in {400, 404, 415, 422}
    if isinstance(exc, requests.RequestException):
        return False
    return isinstance(exc, (ValueError, LLMResponseError))


def prompt_fingerprint(
    profile: PromptProfileOptions | None = None,
    *,
    options: Options | None = None,
) -> str:
    selected_options = options or load_options()
    selected = profile or _active_profile(selected_options)
    payload = json.dumps(
        {
            "system": selected.system,
            "user_template": selected.user_template,
            "tags": selected_options.llm.tags,
            "policies": selected_options.llm.tag_policies,
            "schema": classification_schema(selected_options.llm.tags),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_batch_classifications(
    text: str,
    expected_domains: Sequence[str],
    tags: Sequence[str],
    *,
    provider: str = "",
    llm_options: LLMOptions | None = None,
) -> list[Classification]:
    raw = text.strip()
    if not raw:
        raise LLMResponseError("LLM returned an empty response")
    payload = _parse_json_object(raw)
    if not isinstance(payload, dict):
        raise LLMResponseError("LLM response is not valid JSON")
    _validate_batch_payload(payload, tags)
    results = payload["results"]

    expected = [domain.strip().lower().rstrip(".") for domain in expected_domains]
    expected_set = set(expected)
    selected_options = llm_options or load_options().llm
    parsed_by_domain: dict[str, Classification] = {}
    for item in results:
        if not isinstance(item, dict):
            raise LLMResponseError("A classification result is not an object")
        domain = str(item.get("domain") or "").strip().lower().rstrip(".")
        if len(expected) == 1 and not domain:
            domain = expected[0]
        if domain not in expected_set:
            raise LLMResponseError(f"Unexpected domain in LLM response: {domain or '<empty>'}")
        if domain in parsed_by_domain:
            raise LLMResponseError(f"Duplicate domain in LLM response: {domain}")
        parsed_by_domain[domain] = _classification_from_payload(
            item,
            allowed_tags=tags,
            domain=domain,
            provider=provider,
            raw_text=raw,
            llm_options=selected_options,
        )

    missing = [domain for domain in expected if domain not in parsed_by_domain]
    if missing:
        raise LLMResponseError(f"LLM response omitted domains: {', '.join(missing)}")
    return [parsed_by_domain[domain] for domain in expected]


def parse_classification(text: str, categories: list[str]) -> Classification:
    raw = text.strip()
    if not raw:
        raise ValueError("LLM returned an empty response")
    payload = _parse_json_object(raw)
    if payload is None:
        payload = _parse_labeled_lines(raw)
    if isinstance(payload.get("results"), list) and payload["results"]:
        payload = payload["results"][0]
    return _classification_from_payload(
        payload,
        allowed_tags=categories,
        domain=str(payload.get("domain") or ""),
        provider="",
        raw_text=raw,
        llm_options=load_options().llm,
    )


def _validate_batch_payload(payload: Mapping[str, Any], tags: Sequence[str]) -> None:
    top_level_fields = {"schema_version", "results"}
    missing_top = top_level_fields.difference(payload)
    extra_top = set(payload).difference(top_level_fields)
    if missing_top:
        raise LLMResponseError(
            "LLM response is missing top-level fields: " + ", ".join(sorted(missing_top))
        )
    if extra_top:
        raise LLMResponseError(
            "LLM response contains unsupported top-level fields: " + ", ".join(sorted(extra_top))
        )
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise LLMResponseError("LLM response schema_version must be the integer 1")
    results = payload.get("results")
    if not isinstance(results, list):
        raise LLMResponseError("LLM response results must be an array")

    allowed_tags = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
    allowed_tags.add("unknown")
    for index, item in enumerate(results):
        if not isinstance(item, dict):
            raise LLMResponseError(f"Result {index} must be an object")
        missing = _RESULT_FIELDS.difference(item)
        extra = set(item).difference(_RESULT_FIELDS)
        if missing:
            raise LLMResponseError(
                f"Result {index} is missing fields: " + ", ".join(sorted(missing))
            )
        if extra:
            raise LLMResponseError(
                f"Result {index} contains unsupported fields: " + ", ".join(sorted(extra))
            )
        _validate_result_types(item, index, allowed_tags)


def _validate_result_types(
    item: Mapping[str, Any],
    index: int,
    allowed_tags: set[str],
) -> None:
    string_fields = {
        "domain",
        "policy",
        "category",
        "service",
        "service_role",
        "review_reason",
        "short",
        "details",
    }
    for field in string_fields:
        if not isinstance(item.get(field), str):
            raise LLMResponseError(f"Result {index} field {field} must be a string")
    if not str(item["domain"]).strip():
        raise LLMResponseError(f"Result {index} domain must not be empty")
    if item["policy"] not in {"allow", "deny", "manual_review"}:
        raise LLMResponseError(f"Result {index} policy is invalid")
    if item["category"] not in allowed_tags:
        raise LLMResponseError(f"Result {index} category is not configured")
    if item["service_role"] not in {"core", "optional", "shared", "unknown"}:
        raise LLMResponseError(f"Result {index} service_role is invalid")

    result_tags = item.get("tags")
    if not isinstance(result_tags, list) or not result_tags:
        raise LLMResponseError(f"Result {index} tags must be a non-empty array")
    if any(not isinstance(tag, str) or tag not in allowed_tags for tag in result_tags):
        raise LLMResponseError(f"Result {index} contains an invalid tag")
    if len(set(result_tags)) != len(result_tags):
        raise LLMResponseError(f"Result {index} contains duplicate tags")
    if item["category"] not in result_tags:
        raise LLMResponseError(f"Result {index} category must also appear in tags")

    for field in ("privacy_risk", "security_risk", "breakage_risk"):
        value = item.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise LLMResponseError(f"Result {index} field {field} must be an integer from 0 to 100")
    confidence = item.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= float(confidence) <= 1
    ):
        raise LLMResponseError(f"Result {index} confidence must be a number from 0 to 1")
    if not isinstance(item.get("needs_review"), bool):
        raise LLMResponseError(f"Result {index} needs_review must be a boolean")
    recheck_days = item.get("recheck_after_days")
    if (
        isinstance(recheck_days, bool)
        or not isinstance(recheck_days, int)
        or not 1 <= recheck_days <= 3650
    ):
        raise LLMResponseError(
            f"Result {index} recheck_after_days must be an integer from 1 to 3650"
        )


def _classification_from_payload(
    payload: Mapping[str, Any],
    *,
    allowed_tags: Sequence[str],
    domain: str,
    provider: str,
    raw_text: str,
    llm_options: LLMOptions,
) -> Classification:
    allowed = list(
        dict.fromkeys(str(item).strip().lower() for item in allowed_tags if str(item).strip())
    )
    if "unknown" not in allowed:
        allowed.append("unknown")
    category = _normalize_tag(payload.get("category"), allowed)
    raw_tags = payload.get("tags")
    if isinstance(raw_tags, str):
        tag_values = raw_tags.replace(";", ",").split(",")
    elif isinstance(raw_tags, list):
        tag_values = raw_tags
    else:
        tag_values = []
    tags = list(
        dict.fromkeys(
            normalized
            for value in tag_values
            if (normalized := _normalize_tag(value, allowed)) != "unknown"
        )
    )
    if category not in tags:
        tags.insert(0, category)
    if not tags:
        tags = ["unknown"]

    details = str(payload.get("details") or "").strip()
    short = str(payload.get("short") or "").strip()[:500]
    if not short:
        short = details[:180] or raw_text[:180]
    if not details:
        details = short or raw_text
    confidence = _bounded_float(payload.get("confidence"), 0.0, 1.0)
    breakage_risk = _bounded_int(payload.get("breakage_risk"), 0, 100, 50)
    review_reason = str(payload.get("review_reason") or "").strip()
    needs_review = _as_bool(payload.get("needs_review"), default=True)
    if confidence < llm_options.review_confidence_threshold:
        needs_review = True
        review_reason = review_reason or (
            "Classification confidence is below the configured threshold."
        )

    service_role = _normalize_service_role(payload.get("service_role"))
    if service_role in {ServiceRole.CORE, ServiceRole.SHARED} and breakage_risk >= 50:
        needs_review = True
        review_reason = review_reason or "Blocking may affect a core or shared service."

    return Classification(
        domain=domain.strip().lower().rstrip("."),
        policy=_normalize_policy(str(payload.get("policy") or "")),
        category=category,
        tags=tuple(tags),
        service=str(payload.get("service") or "").strip(),
        service_role=service_role,
        privacy_risk=_bounded_int(payload.get("privacy_risk"), 0, 100, 0),
        security_risk=_bounded_int(payload.get("security_risk"), 0, 100, 0),
        breakage_risk=breakage_risk,
        confidence=confidence,
        needs_review=needs_review,
        review_reason=review_reason,
        recheck_after_days=_bounded_int(
            payload.get("recheck_after_days"),
            1,
            3650,
            llm_options.default_recheck_days,
        ),
        short=short,
        details=details,
        provider=provider,
        raw_text=raw_text,
    )


def _extract_response_text(data: Any) -> str:
    if not isinstance(data, dict):
        raise ValueError("LLM response is not a JSON object")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("LLM response contains no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ValueError("LLM response choice is invalid")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ValueError("LLM response contains no message")
    if message.get("refusal"):
        raise LLMResponseError(f"LLM refused the request: {message['refusal']}")
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [str(item.get("text") or "") for item in content if isinstance(item, dict)]
        return "\n".join(part for part in parts if part).strip()
    raise ValueError("LLM response message contains no text")


def _parse_json_object(text: str) -> dict[str, Any] | None:
    candidates = [text]
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidates.insert(0, fenced.group(1))
    first = text.find("{")
    last = text.rfind("}")
    if first >= 0 and last > first:
        candidates.append(text[first : last + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _parse_labeled_lines(text: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    current_key: str | None = None
    keys = (
        "policy|category|tags|service|service_role|privacy_risk|security_risk|"
        "breakage_risk|confidence|needs_review|review_reason|recheck_after_days|short|details"
    )
    for line in text.splitlines():
        match = re.match(rf"^\s*({keys})\s*:\s*(.*)$", line, re.I)
        if match:
            current_key = match.group(1).lower()
            output[current_key] = match.group(2).strip()
        elif current_key == "details" and line.strip():
            output["details"] = f"{output.get('details', '')}\n{line.strip()}".strip()
    if "policy" not in output:
        lowered = text.lower()
        for candidate in ("manual_review", "deny", "allow"):
            if candidate in lowered:
                output["policy"] = candidate
                break
    return output


def _structured_modes(mode: str) -> list[str]:
    normalized = mode.strip().lower()
    if normalized == "auto":
        return ["json_schema", "json_object", "prompt_only"]
    if normalized in {"json_schema", "json_object", "prompt_only"}:
        return [normalized]
    return ["prompt_only"]


def _response_format(mode: str, tags: Sequence[str]) -> dict[str, Any] | None:
    if mode == "json_schema":
        return {
            "type": "json_schema",
            "json_schema": {
                "name": "domain_classification_batch",
                "strict": True,
                "schema": classification_schema(tags),
            },
        }
    if mode == "json_object":
        return {"type": "json_object"}
    return None


def _normalize_policy(value: str) -> Policy:
    normalized = value.strip().lower().replace(" ", "_")
    if normalized in {"allow", "allowed", "permit", "permitted", "whitelist"}:
        return Policy.ALLOW
    if normalized in {"deny", "denied", "block", "blocked", "blacklist"}:
        return Policy.DENY
    if normalized in {"manual", "review", "manual_review", "needs_review"}:
        return Policy.MANUAL_REVIEW
    return Policy.UNKNOWN


def _normalize_tag(value: Any, allowed: Sequence[str]) -> str:
    normalized = str(value or "unknown").strip().lower().replace(" ", "_")
    return normalized if normalized in set(allowed) else "unknown"


def _normalize_service_role(value: Any) -> ServiceRole:
    normalized = str(value or "unknown").strip().lower()
    try:
        return ServiceRole(normalized)
    except ValueError:
        return ServiceRole.UNKNOWN


def _bounded_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        return min(maximum, max(minimum, int(float(value))))
    except (TypeError, ValueError):
        return default


def _bounded_float(value: Any, minimum: float, maximum: float) -> float:
    try:
        return min(maximum, max(minimum, float(value)))
    except (TypeError, ValueError):
        return minimum


def _as_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"true", "yes", "1", "on"}:
        return True
    if normalized in {"false", "no", "0", "off"}:
        return False
    return default


class _StrictFormatMap(dict[str, str]):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)
