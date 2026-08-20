from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from pihole_manager.models import Classification

_DEFAULT_DATASET_NAME = "golden_dataset_v1.json"
_SUPPORTED_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class GoldenCase:
    case_id: str
    domain: str
    description: str
    dossier: Mapping[str, Any]
    expected: Mapping[str, Any]
    source_expectations: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class GoldenDataset:
    dataset_id: str
    schema_version: int
    description: str
    cases: tuple[GoldenCase, ...]

    def case_for_domain(self, domain: str) -> GoldenCase | None:
        normalized = _normalize(domain)
        return next((case for case in self.cases if _normalize(case.domain) == normalized), None)

    def case_by_id(self, case_id: str) -> GoldenCase | None:
        normalized = case_id.strip().casefold()
        return next((case for case in self.cases if case.case_id.casefold() == normalized), None)


@dataclass(frozen=True, slots=True)
class GoldenScore:
    passed: int
    total: int
    failures: tuple[str, ...] = ()

    @property
    def score(self) -> float:
        return 1.0 if self.total == 0 else self.passed / self.total


@dataclass(frozen=True, slots=True)
class GoldenVariantResult:
    case_id: str
    domain: str
    variant_id: str
    classification: GoldenScore
    sources: GoldenScore

    @property
    def score(self) -> float:
        totals = self.classification.total + self.sources.total
        if totals == 0:
            return 1.0
        return (self.classification.passed + self.sources.passed) / totals


def load_golden_dataset(path: str | Path | None = None) -> GoldenDataset:
    if path is None:
        payload = json.loads(
            resources.files("pihole_manager")
            .joinpath("data", _DEFAULT_DATASET_NAME)
            .read_text(encoding="utf-8")
        )
    else:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("Golden dataset root must be a JSON object.")
    schema_version = _integer(payload.get("schema_version"), "schema_version")
    if schema_version != _SUPPORTED_SCHEMA_VERSION:
        raise ValueError(f"Unsupported golden dataset schema version: {schema_version}")
    dataset_id = str(payload.get("dataset_id") or "").strip()
    if not dataset_id:
        raise ValueError("Golden dataset requires dataset_id.")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("Golden dataset requires at least one case.")

    cases: list[GoldenCase] = []
    seen_ids: set[str] = set()
    seen_domains: set[str] = set()
    for raw_case in raw_cases:
        case = _parse_case(raw_case)
        case_key = case.case_id.casefold()
        domain_key = _normalize(case.domain)
        if case_key in seen_ids:
            raise ValueError(f"Duplicate golden case id: {case.case_id}")
        if domain_key in seen_domains:
            raise ValueError(f"Duplicate golden domain: {case.domain}")
        seen_ids.add(case_key)
        seen_domains.add(domain_key)
        cases.append(case)

    return GoldenDataset(
        dataset_id=dataset_id,
        schema_version=schema_version,
        description=str(payload.get("description") or "").strip(),
        cases=tuple(cases),
    )


def evaluate_classification(
    case: GoldenCase,
    classification: Classification | Mapping[str, Any],
) -> GoldenScore:
    actual = _classification_mapping(classification)
    expected = case.expected
    checks: list[tuple[bool, str]] = []

    policies = _string_set(expected.get("policies"))
    if policies:
        actual_policy = _enum_value(actual.get("policy"))
        checks.append((actual_policy in policies, f"policy={actual_policy!r} not in {sorted(policies)}"))

    actual_tags = _string_set(actual.get("tags"))
    category = _normalize(_enum_value(actual.get("category")))
    if category:
        actual_tags.add(category)
    for tag in sorted(_string_set(expected.get("required_tags"))):
        checks.append((tag in actual_tags, f"missing required tag {tag!r}"))
    for tag in sorted(_string_set(expected.get("forbidden_tags"))):
        checks.append((tag not in actual_tags, f"forbidden tag present: {tag!r}"))

    roles = _string_set(expected.get("service_roles"))
    if roles:
        actual_role = _enum_value(actual.get("service_role"))
        checks.append((actual_role in roles, f"service_role={actual_role!r} not in {sorted(roles)}"))

    expected_review = expected.get("needs_review")
    if isinstance(expected_review, bool):
        actual_review = bool(actual.get("needs_review"))
        checks.append(
            (
                actual_review is expected_review,
                f"needs_review={actual_review!r}, expected {expected_review!r}",
            )
        )

    risk_ranges = expected.get("risk_ranges")
    if isinstance(risk_ranges, Mapping):
        for field in ("privacy_risk", "security_risk", "breakage_risk"):
            bounds = risk_ranges.get(field)
            if bounds is None:
                continue
            minimum, maximum = _range(bounds, field)
            actual_value = _number(actual.get(field), field)
            checks.append(
                (
                    minimum <= actual_value <= maximum,
                    f"{field}={actual_value:g} outside [{minimum:g}, {maximum:g}]",
                )
            )

    return _score(checks)


def evaluate_sources(
    case: GoldenCase,
    dossier: Mapping[str, Any] | None = None,
) -> GoldenScore:
    selected = dossier or case.dossier
    findings = selected.get("findings") if isinstance(selected, Mapping) else None
    if not isinstance(findings, list):
        findings = []

    providers: set[str] = set()
    kinds: set[str] = set()
    verdicts: set[str] = set()
    decision_relevant = 0
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        provider = _normalize(finding.get("provider"))
        kind = _normalize(finding.get("kind"))
        verdict = _normalize(finding.get("verdict"))
        if provider:
            providers.add(provider)
        if kind:
            kinds.add(kind)
        if verdict:
            verdicts.add(verdict)
        if bool(finding.get("decision_relevant")):
            decision_relevant += 1

    expected = case.source_expectations
    checks: list[tuple[bool, str]] = []
    for provider in sorted(_string_set(expected.get("required_providers"))):
        checks.append((provider in providers, f"missing source provider {provider!r}"))
    for kind in sorted(_string_set(expected.get("required_kinds"))):
        checks.append((kind in kinds, f"missing source kind {kind!r}"))
    for verdict in sorted(_string_set(expected.get("required_verdicts"))):
        checks.append((verdict in verdicts, f"missing source verdict {verdict!r}"))
    for verdict in sorted(_string_set(expected.get("forbidden_verdicts"))):
        checks.append((verdict not in verdicts, f"forbidden source verdict present: {verdict!r}"))

    minimum = expected.get("minimum_decision_relevant")
    if minimum is not None:
        required = _integer(minimum, "minimum_decision_relevant")
        checks.append(
            (
                decision_relevant >= required,
                f"decision_relevant={decision_relevant}, expected at least {required}",
            )
        )
    return _score(checks)


def evaluate_variant(
    case: GoldenCase,
    variant_id: str,
    classification: Classification | Mapping[str, Any],
    *,
    dossier: Mapping[str, Any] | None = None,
) -> GoldenVariantResult:
    return GoldenVariantResult(
        case_id=case.case_id,
        domain=case.domain,
        variant_id=variant_id.strip() or "variant",
        classification=evaluate_classification(case, classification),
        sources=evaluate_sources(case, dossier),
    )


def compare_variants(
    case: GoldenCase,
    variants: Mapping[str, Classification | Mapping[str, Any]],
    *,
    dossier: Mapping[str, Any] | None = None,
) -> tuple[GoldenVariantResult, ...]:
    results = [
        evaluate_variant(case, variant_id, classification, dossier=dossier)
        for variant_id, classification in variants.items()
    ]
    return tuple(sorted(results, key=lambda item: (-item.score, item.variant_id.casefold())))


def evaluate_benchmark_run(
    dataset: GoldenDataset,
    run: Mapping[str, Any],
) -> tuple[GoldenVariantResult, ...]:
    domain = str(run.get("domain") or "")
    case = dataset.case_for_domain(domain)
    if case is None:
        raise ValueError(f"No golden case exists for benchmark domain: {domain}")
    dossier = run.get("dossier")
    selected_dossier = dossier if isinstance(dossier, Mapping) else case.dossier
    raw_results = run.get("results")
    if not isinstance(raw_results, list):
        raise ValueError("Benchmark run contains no result list.")

    results: list[GoldenVariantResult] = []
    for item in raw_results:
        if not isinstance(item, Mapping) or str(item.get("status") or "") != "completed":
            continue
        classification = item.get("classification")
        if not isinstance(classification, Mapping):
            continue
        provider = str(item.get("provider_name") or item.get("provider_id") or "provider").strip()
        model = str(item.get("model") or "model").strip()
        results.append(
            evaluate_variant(
                case,
                f"{provider} / {model}",
                classification,
                dossier=selected_dossier,
            )
        )
    return tuple(sorted(results, key=lambda item: (-item.score, item.variant_id.casefold())))


def _parse_case(raw_case: object) -> GoldenCase:
    if not isinstance(raw_case, Mapping):
        raise ValueError("Each golden case must be a JSON object.")
    case_id = str(raw_case.get("case_id") or "").strip()
    domain = str(raw_case.get("domain") or "").strip().lower().rstrip(".")
    dossier = raw_case.get("dossier")
    expected = raw_case.get("expected")
    source_expectations = raw_case.get("source_expectations", {})
    if not case_id or not domain:
        raise ValueError("Golden cases require case_id and domain.")
    if not isinstance(dossier, Mapping):
        raise ValueError(f"Golden case {case_id} requires a dossier object.")
    if _normalize(dossier.get("domain")) != _normalize(domain):
        raise ValueError(f"Golden case {case_id} dossier domain does not match case domain.")
    if not isinstance(expected, Mapping):
        raise ValueError(f"Golden case {case_id} requires expected classification criteria.")
    if not isinstance(source_expectations, Mapping):
        raise ValueError(f"Golden case {case_id} source_expectations must be an object.")
    return GoldenCase(
        case_id=case_id,
        domain=domain,
        description=str(raw_case.get("description") or "").strip(),
        dossier=dict(dossier),
        expected=dict(expected),
        source_expectations=dict(source_expectations),
    )


def _classification_mapping(
    classification: Classification | Mapping[str, Any],
) -> Mapping[str, Any]:
    if isinstance(classification, Mapping):
        return classification
    return {
        "policy": classification.policy,
        "category": classification.category,
        "tags": classification.tags,
        "service_role": classification.service_role,
        "privacy_risk": classification.privacy_risk,
        "security_risk": classification.security_risk,
        "breakage_risk": classification.breakage_risk,
        "needs_review": classification.needs_review,
    }


def _score(checks: Sequence[tuple[bool, str]]) -> GoldenScore:
    failures = tuple(message for passed, message in checks if not passed)
    return GoldenScore(passed=len(checks) - len(failures), total=len(checks), failures=failures)


def _string_set(value: object) -> set[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, Sequence):
        values = value
    else:
        return set()
    return {_normalize(item) for item in values if _normalize(item)}


def _enum_value(value: object) -> str:
    raw = getattr(value, "value", value)
    return _normalize(raw)


def _normalize(value: object) -> str:
    return str(value or "").strip().casefold()


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer.") from exc


def _number(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric.")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric.") from exc


def _range(value: object, field: str) -> tuple[float, float]:
    if not isinstance(value, Sequence) or isinstance(value, str) or len(value) != 2:
        raise ValueError(f"{field} range must contain exactly two numbers.")
    minimum = _number(value[0], field)
    maximum = _number(value[1], field)
    if minimum > maximum:
        raise ValueError(f"{field} range minimum exceeds maximum.")
    return minimum, maximum
