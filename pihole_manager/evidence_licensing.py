from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EvidenceLicensePolicy:
    license_id: str
    license_url: str
    commercial_use: str
    redistribution: str
    reviewed_at: str
    release_default_eligible: bool
    review_required: bool = False
    note: str = ""


_REVIEW_DATE = "2026-08-20"

_SOURCE_POLICIES: dict[str, EvidenceLicensePolicy] = {
    "adguard_services": EvidenceLicensePolicy(
        license_id="GPL-3.0",
        license_url="https://github.com/AdguardTeam/HostlistsRegistry/blob/main/LICENSE",
        commercial_use="allowed-with-license-obligations",
        redistribution="runtime-download-not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=True,
        note="HostlistsRegistry is GPL-3.0; Wormhole downloads the service catalog at runtime.",
    ),
    "dns_records": EvidenceLicensePolicy(
        license_id="local-data",
        license_url="",
        commercial_use="not-applicable",
        redistribution="not-applicable",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=True,
        note="Uses the configured DNS resolver and does not redistribute a third-party dataset.",
    ),
    "disconnect_tracking": EvidenceLicensePolicy(
        license_id="CC-BY-NC-SA-4.0",
        license_url=(
            "https://github.com/disconnectme/disconnect-tracking-protection/blob/master/LICENSE"
        ),
        commercial_use="restricted-noncommercial",
        redistribution="runtime-download-not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note=(
            "Disconnect's tracker lists are NonCommercial. Keep this source opt-in and "
            "do not enable it in distributed defaults without a separate commercial licence."
        ),
    ),
    "rdap": EvidenceLicensePolicy(
        license_id="provider-specific-rdap-terms",
        license_url="",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="RDAP queries multiple registries; their service terms are provider-specific.",
    ),
    "ripestat": EvidenceLicensePolicy(
        license_id="provider-terms",
        license_url="https://stat.ripe.net/docs/",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="Optional live lookup; no RIPEstat dataset is bundled with releases.",
    ),
    "netcraft": EvidenceLicensePolicy(
        license_id="provider-fair-use",
        license_url="https://www.netcraft.com/terms/",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="Optional live lookup subject to Netcraft access and usage terms.",
    ),
    "virustotal": EvidenceLicensePolicy(
        license_id="provider-api-terms",
        license_url="https://docs.virustotal.com/reference/terms-of-service",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="Optional API integration; releases do not bundle VirusTotal data.",
    ),
    "threatfox": EvidenceLicensePolicy(
        license_id="abuse.ch-community-api-fair-use",
        license_url="https://threatfox.abuse.ch/api/",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="Optional abuse.ch Community API integration subject to current fair-use terms.",
    ),
    "phishtank": EvidenceLicensePolicy(
        license_id="PhishTank-Data-Terms",
        license_url="https://phishtank.org/terms.php",
        commercial_use="allowed",
        redistribution="runtime-download-not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=True,
        note=(
            "PhishTank's Terms explicitly allow commercial use of defined Data without charge; "
            "the verified database is downloaded at runtime and is not bundled."
        ),
    ),
    "urlscan": EvidenceLicensePolicy(
        license_id="provider-api-terms",
        license_url="https://urlscan.io/about-api/",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="Optional archived-scan lookup; no urlscan dataset is bundled.",
    ),
    "cloudflare_radar": EvidenceLicensePolicy(
        license_id="provider-api-terms",
        license_url="https://developers.cloudflare.com/radar/",
        commercial_use="provider-terms",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note="Optional API integration; no Cloudflare Radar dataset is bundled.",
    ),
    "repository_lists": EvidenceLicensePolicy(
        license_id="per-source",
        license_url="",
        commercial_use="per-source",
        redistribution="runtime-download-not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=True,
        note="Every configured repository list is reviewed independently before use.",
    ),
    "urlhaus": EvidenceLicensePolicy(
        license_id="abuse.ch-community-api-fair-use",
        license_url="https://urlhaus.abuse.ch/api/",
        commercial_use="conditional-commercial-api",
        redistribution="not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=False,
        note=(
            "The free Community API is governed by abuse.ch fair-use principles; commercial or "
            "for-profit needs may require the enhanced paid API."
        ),
    ),
}

_REPOSITORY_LIST_POLICIES: dict[str, EvidenceLicensePolicy] = {
    "hagezi_tif_mini": EvidenceLicensePolicy(
        license_id="GPL-3.0",
        license_url="https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
        commercial_use="allowed-with-license-obligations",
        redistribution="runtime-download-not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=True,
        note="HaGeZi dns-blocklists is GPL-3.0 and permits redistribution under that licence.",
    ),
    "easyprivacy_trackingservers": EvidenceLicensePolicy(
        license_id="GPL-3.0-or-later OR CC-BY-SA-3.0-or-later",
        license_url="https://easylist.to/pages/licence.html",
        commercial_use="allowed-with-license-obligations",
        redistribution="runtime-download-not-bundled",
        reviewed_at=_REVIEW_DATE,
        release_default_eligible=True,
        note=(
            "EasyList/EasyPrivacy is dual-licensed under GPL-3.0-or-later or "
            "CC BY-SA 3.0-or-later; attribution/share-alike obligations apply as appropriate."
        ),
    ),
}


def source_license_policy(kind: str) -> EvidenceLicensePolicy | None:
    return _SOURCE_POLICIES.get(kind.strip().lower())


def repository_list_license_policy(source_id: str) -> EvidenceLicensePolicy | None:
    return _REPOSITORY_LIST_POLICIES.get(source_id.strip().lower())


def repository_list_license_policies() -> dict[str, EvidenceLicensePolicy]:
    return dict(_REPOSITORY_LIST_POLICIES)


def distribution_license_issues(enabled_provider_kinds: Iterable[str]) -> list[str]:
    issues: list[str] = []
    normalized = list(
        dict.fromkeys(
            kind.strip().lower()
            for kind in enabled_provider_kinds
            if kind
        )
    )

    for kind in normalized:
        policy = source_license_policy(kind)
        if policy is None:
            issues.append(f"{kind}: no reviewed evidence-source usage policy is registered")
            continue
        if policy.review_required:
            issues.append(f"{kind}: licensing/usage review is still required")
            continue
        if not policy.release_default_eligible:
            issues.append(
                f"{kind}: must remain opt-in for distributed builds ({policy.commercial_use})"
            )

        if kind == "repository_lists":
            for source_id, nested in _REPOSITORY_LIST_POLICIES.items():
                if nested.review_required:
                    issues.append(f"{source_id}: repository-list licensing review is required")
                elif not nested.release_default_eligible:
                    issues.append(
                        f"{source_id}: repository list is not safe for release defaults "
                        f"({nested.commercial_use})"
                    )

    return issues
