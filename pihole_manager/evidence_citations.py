from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from pihole_manager.models import Classification
from pihole_manager.provider_api import ProviderCitation

_CITATION_HEADER = "Evidence citations:"
_MAX_CITATIONS = 12
_MAX_LABEL_LENGTH = 180
_MAX_URL_LENGTH = 2_048


def attach_evidence_citations(
    classifications: Sequence[Classification],
    dossiers: Sequence[Mapping[str, Any]],
    *,
    provider_citations: Sequence[ProviderCitation] = (),
) -> list[Classification]:
    """Attach auditable evidence references to each generated detailed description.

    Evidence findings are domain-specific, so they are always safe to attach to the
    matching classification. Provider-native web citations are only attached when a
    request contains one domain; batch-wide annotations cannot be attributed to one
    domain reliably without provider-specific span reconstruction.
    """

    dossier_by_domain = {
        _normalize_domain(item.get("domain")): item
        for item in dossiers
        if _normalize_domain(item.get("domain"))
    }
    single_domain = len(classifications) == 1
    output: list[Classification] = []
    for classification in classifications:
        dossier = dossier_by_domain.get(_normalize_domain(classification.domain), {})
        references = _dossier_references(dossier)
        if single_domain:
            references.extend(_provider_references(provider_citations))
        references = _deduplicate_references(references)[:_MAX_CITATIONS]
        output.append(_with_citation_section(classification, references))
    return output


def _dossier_references(dossier: Mapping[str, Any]) -> list[tuple[str, str]]:
    findings = dossier.get("findings")
    if not isinstance(findings, list):
        return []
    references: list[tuple[str, str]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        provider = _single_line(finding.get("provider"))
        title = _single_line(finding.get("title"))
        kind = _single_line(finding.get("kind"))
        label_parts = [part for part in (provider, title or kind) if part]
        label = " — ".join(dict.fromkeys(label_parts)) or "Evidence finding"
        url = _source_url(finding.get("source_url"))
        references.append((label[:_MAX_LABEL_LENGTH], url))
    return references


def _provider_references(
    citations: Sequence[ProviderCitation],
) -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for citation in citations:
        url = _source_url(citation.url)
        if not url:
            continue
        title = _single_line(citation.title) or "Provider web source"
        references.append((f"Web — {title}"[:_MAX_LABEL_LENGTH], url))
    return references


def _deduplicate_references(
    references: Sequence[tuple[str, str]],
) -> list[tuple[str, str]]:
    output: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for label, url in references:
        key = (url.casefold(), label.casefold()) if url else ("", label.casefold())
        if key in seen:
            continue
        seen.add(key)
        output.append((label, url))
    return output


def _with_citation_section(
    classification: Classification,
    references: Sequence[tuple[str, str]],
) -> Classification:
    details = classification.details.strip()
    if _CITATION_HEADER in details:
        return classification

    if references:
        lines = [
            f"[E{index}] {label}{f' — {url}' if url else ''}"
            for index, (label, url) in enumerate(references, start=1)
        ]
        section = _CITATION_HEADER + "\n" + "\n".join(lines)
        return replace(classification, details=f"{details}\n\n{section}".strip())

    review_reason = classification.review_reason.strip() or (
        "No citable evidence finding was supplied for this generated description."
    )
    section = f"{_CITATION_HEADER}\n[none] No evidence finding was supplied."
    return replace(
        classification,
        details=f"{details}\n\n{section}".strip(),
        needs_review=True,
        review_reason=review_reason,
    )


def _normalize_domain(value: object) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _single_line(value: object) -> str:
    return " ".join(str(value or "").split())


def _source_url(value: object) -> str:
    url = _single_line(value)
    if not url:
        return ""
    if not url.lower().startswith(("https://", "http://")):
        return ""
    return url[:_MAX_URL_LENGTH]
