from __future__ import annotations

import ipaddress
import socket
import threading
import time
import urllib.robotparser
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlsplit

try:
    import dns.exception as dns_exception
    import dns.resolver as dns_resolver
except ModuleNotFoundError:
    dns_exception = None
    dns_resolver = None

import requests

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.models import ResearchFinding
from pihole_manager.research_common import (
    ResearchError,
    negative_finding,
    normalize_domain,
    request_headers,
    wait_for_provider,
)

_IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_CACHE: tuple[float, str, dict[str, str]] | None = None
_BOOTSTRAP_LOCK = threading.RLock()
_ROBOTS_CACHE: dict[str, tuple[float, list[str]]] = {}


def research_dns_records(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    normalized = normalize_domain(domain)
    if dns_resolver is None or dns_exception is None:
        return _research_dns_records_socket(normalized, provider)

    resolver = dns_resolver.Resolver(configure=True)
    resolver.lifetime = provider.timeout_sec
    records: dict[str, list[str]] = {}
    canonical_name = ""
    for record_type in ("CNAME", "A", "AAAA", "NS", "MX", "HTTPS", "SVCB"):
        try:
            answer = resolver.resolve(
                normalized,
                record_type,
                lifetime=provider.timeout_sec,
                search=False,
                raise_on_no_answer=False,
            )
        except (dns_exception.DNSException, OSError):
            continue
        if answer.rrset is None:
            continue
        values = [str(item).rstrip(".") for item in answer]
        if values:
            records[record_type] = values[:20]
        candidate = str(answer.canonical_name).rstrip(".")
        if candidate and candidate != normalized:
            canonical_name = candidate

    return _dns_finding(
        normalized,
        provider,
        canonical_name=canonical_name,
        records=records,
        backend="dnspython",
    )


def _research_dns_records_socket(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    records: dict[str, list[str]] = {"A": [], "AAAA": []}
    canonical_name = ""
    try:
        answers = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            flags=getattr(socket, "AI_CANONNAME", 0),
        )
    except OSError:
        answers = []

    for family, _socktype, _protocol, candidate, address in answers:
        if candidate and candidate.rstrip(".").lower() != domain:
            canonical_name = candidate.rstrip(".")
        value = str(address[0])
        if family == socket.AF_INET and value not in records["A"]:
            records["A"].append(value)
        elif family == socket.AF_INET6 and value not in records["AAAA"]:
            records["AAAA"].append(value)

    records = {key: values[:20] for key, values in records.items() if values}
    return _dns_finding(
        domain,
        provider,
        canonical_name=canonical_name,
        records=records,
        backend="socket_fallback",
    )


def _dns_finding(
    domain: str,
    provider: ResearchProviderOptions,
    *,
    canonical_name: str,
    records: dict[str, list[str]],
    backend: str,
) -> list[ResearchFinding]:
    if not records and not canonical_name:
        return [negative_finding(domain, provider, summary="No DNS records were returned.")]

    parts = []
    if canonical_name:
        parts.append(f"Canonical name: {canonical_name}")
    for record_type, values in records.items():
        parts.append(f"{record_type}: {', '.join(values[:8])}")
    now = int(time.time())
    return [
        ResearchFinding(
            domain=domain,
            provider=provider.name,
            kind="dns_records",
            title="DNS record summary",
            summary="; ".join(parts),
            confidence=0.99 if backend == "dnspython" else 0.95,
            signal_type="infrastructure",
            verdict="dns_context",
            decision_relevant=False,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data={
                "backend": backend,
                "canonical_name": canonical_name,
                "records": records,
            },
        )
    ]


def research_rdap(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    bootstrap = _rdap_bootstrap(provider)
    labels = normalize_domain(domain).split(".")
    if len(labels) < 2:
        return [negative_finding(domain, provider)]
    server = bootstrap.get(labels[-1])
    if not server:
        return [negative_finding(domain, provider)]

    response: requests.Response | None = None
    candidate = domain
    for index in range(max(0, len(labels) - 4), len(labels) - 1):
        candidate = ".".join(labels[index:])
        url = f"{server.rstrip('/')}/domain/{quote(candidate, safe='.-_')}"
        wait_for_provider(provider)
        response = requests.get(
            url,
            headers=request_headers(Accept="application/rdap+json, application/json"),
            timeout=provider.timeout_sec,
            allow_redirects=True,
        )
        if response.status_code == 404:
            continue
        response.raise_for_status()
        break
    if response is None or response.status_code == 404:
        return [negative_finding(domain, provider)]

    data = response.json()
    registrar = _rdap_registrar(data)
    statuses = [str(value) for value in data.get("status") or []]
    nameservers = [
        str(item.get("ldhName") or "")
        for item in data.get("nameservers") or []
        if isinstance(item, dict) and item.get("ldhName")
    ]
    events = {
        str(item.get("eventAction") or ""): str(item.get("eventDate") or "")
        for item in data.get("events") or []
        if isinstance(item, dict)
    }
    parts = [f"Registered domain: {data.get('ldhName') or candidate}"]
    if registrar:
        parts.append(f"Registrar: {registrar}")
    if events.get("registration"):
        parts.append(f"Registered: {events['registration']}")
    if events.get("expiration"):
        parts.append(f"Expires: {events['expiration']}")
    if statuses:
        parts.append(f"Status: {', '.join(statuses)}")
    if nameservers:
        parts.append(f"Nameservers: {', '.join(nameservers)}")
    now = int(time.time())
    return [
        ResearchFinding(
            domain=normalize_domain(domain),
            provider=provider.name,
            kind="registration",
            title=f"RDAP registration for {candidate}",
            summary="; ".join(parts),
            source_url=response.url,
            confidence=0.98,
            signal_type="identity",
            verdict="registration_context",
            decision_relevant=False,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data=data,
        )
    ]


def research_ripestat(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    addresses = _public_addresses(domain)
    if not addresses:
        return [negative_finding(domain, provider, summary="No public IP address was resolved.")]
    base_url = (provider.base_url or "https://stat.ripe.net/data").rstrip("/")
    findings: list[ResearchFinding] = []
    holders: dict[str, str] = {}
    for address in addresses[: provider.max_results]:
        wait_for_provider(provider)
        response = requests.get(
            f"{base_url}/network-info/data.json",
            params={"resource": address, "sourceapp": "pi-hole-manager"},
            headers=request_headers(),
            timeout=provider.timeout_sec,
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") or {}
        asns = [str(value) for value in data.get("asns") or []]
        for asn in asns:
            if asn not in holders:
                holders[asn] = _ripestat_as_holder(base_url, asn, provider)
        holder_text = ", ".join(f"AS{asn} {holders.get(asn, '')}".strip() for asn in asns)
        summary = f"IP {address}; prefix {data.get('prefix') or 'unknown'}"
        if holder_text:
            summary += f"; origin {holder_text}"
        now = int(time.time())
        findings.append(
            ResearchFinding(
                domain=normalize_domain(domain),
                provider=provider.name,
                kind="network_routing",
                title=f"RIPEstat network information for {address}",
                summary=summary,
                source_url=(f"https://stat.ripe.net/app/launchpad/{quote(address, safe=':.')}"),
                confidence=0.98,
                signal_type="infrastructure",
                verdict="network_context",
                decision_relevant=False,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data={"address": address, "network_info": data, "holders": holders},
            )
        )
    return findings or [negative_finding(domain, provider)]


def research_netcraft(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    endpoint = provider.base_url or "https://sitereport.netcraft.com/"
    query_value = f"http://{normalize_domain(domain)}"
    report_url = f"{endpoint.rstrip('/?')}/?{urlencode({'url': query_value})}"
    site_root = f"{urlsplit(endpoint).scheme}://{urlsplit(endpoint).netloc}"
    if not _robots_allows(site_root, report_url, provider):
        raise ResearchError("Netcraft robots.txt does not permit this Site Report request")
    wait_for_provider(provider)
    response = requests.get(
        report_url,
        headers=request_headers(Accept="text/html,application/xhtml+xml"),
        timeout=provider.timeout_sec,
        allow_redirects=True,
    )
    response.raise_for_status()
    parser = _NetcraftTableParser()
    parser.feed(response.text)
    fields = parser.fields
    useful = _select_netcraft_fields(fields)
    if not useful:
        return [negative_finding(domain, provider)]

    summary = "; ".join(f"{key}: {value}" for key, value in useful.items())
    now = int(time.time())
    return [
        ResearchFinding(
            domain=normalize_domain(domain),
            provider=provider.name,
            kind="site_infrastructure",
            title="Netcraft Site Report",
            summary=summary[:2500],
            source_url=response.url,
            confidence=0.8,
            signal_type="infrastructure",
            verdict="site_context",
            decision_relevant=False,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data={"selected_fields": useful, "all_fields": fields},
        )
    ]


def research_virustotal(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        raise ResearchError("VirusTotal requires an API key")
    base_url = (provider.base_url or "https://www.virustotal.com/api/v3").rstrip("/")
    wait_for_provider(provider)
    response = requests.get(
        f"{base_url}/domains/{quote(normalize_domain(domain), safe='.-_')}",
        headers=request_headers(**{"x-apikey": provider.api_key}),
        timeout=provider.timeout_sec,
    )
    if response.status_code == 404:
        return [negative_finding(domain, provider)]
    response.raise_for_status()
    data = response.json()
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    categories = attributes.get("categories") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious >= 3:
        verdict = "malicious"
    elif malicious or suspicious:
        verdict = "suspicious"
    else:
        verdict = "no_detection"
    summary = (
        f"VirusTotal analysis: malicious={malicious}, suspicious={suspicious}, "
        f"harmless={stats.get('harmless', 0)}, undetected={stats.get('undetected', 0)}; "
        f"reputation={attributes.get('reputation', 0)}."
    )
    if categories:
        summary += " Categories: " + ", ".join(
            f"{key}={value}" for key, value in list(categories.items())[:10]
        )
    now = int(time.time())
    return [
        ResearchFinding(
            domain=normalize_domain(domain),
            provider=provider.name,
            kind="threat_intelligence",
            title="VirusTotal domain report",
            summary=summary,
            source_url=f"https://www.virustotal.com/gui/domain/{normalize_domain(domain)}",
            confidence=0.9 if malicious >= 3 else 0.7 if malicious or suspicious else 0.6,
            signal_type="security",
            verdict=verdict,
            decision_relevant=malicious >= 3,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data=data,
        )
    ]


def research_threatfox(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        raise ResearchError("ThreatFox requires an Auth-Key")
    url = provider.base_url or "https://threatfox-api.abuse.ch/api/v1/"
    wait_for_provider(provider)
    response = requests.post(
        url,
        json={
            "query": "search_ioc",
            "search_term": normalize_domain(domain),
            "exact_match": True,
        },
        headers=request_headers(**{"Auth-Key": provider.api_key}),
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    payload = response.json()
    entries = payload.get("data") if payload.get("query_status") == "ok" else []
    if not isinstance(entries, list) or not entries:
        return [negative_finding(domain, provider)]

    now = int(time.time())
    findings = []
    for item in entries[: provider.max_results]:
        if not isinstance(item, dict):
            continue
        threat_type = str(item.get("threat_type") or "unknown")
        malware = str(item.get("malware_printable") or item.get("malware") or "unknown")
        confidence = _safe_confidence(item.get("confidence_level"), 0.75)
        findings.append(
            ResearchFinding(
                domain=normalize_domain(domain),
                provider=provider.name,
                kind="ioc_database",
                title=f"ThreatFox IOC: {threat_type}",
                summary=(
                    f"Exact active IOC match. Threat type: {threat_type}; malware: {malware}; "
                    f"first seen: {item.get('first_seen') or 'unknown'}; "
                    f"last seen: {item.get('last_seen') or 'unknown'}."
                ),
                source_url=(
                    f"https://threatfox.abuse.ch/ioc/{item.get('id')}/"
                    if item.get("id")
                    else "https://threatfox.abuse.ch/"
                ),
                confidence=confidence,
                signal_type="security",
                verdict=_threatfox_verdict(threat_type),
                decision_relevant=True,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data=item,
            )
        )
    return findings or [negative_finding(domain, provider)]


def research_urlscan(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    base_url = (provider.base_url or "https://urlscan.io/api/v1").rstrip("/")
    headers = request_headers()
    if provider.api_key.strip():
        headers["api-key"] = provider.api_key.strip()
    wait_for_provider(provider)
    response = requests.get(
        f"{base_url}/search/",
        params={
            "q": f"domain:{normalize_domain(domain)} AND date:>now-90d",
            "size": provider.max_results,
        },
        headers=headers,
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    payload = response.json()
    results = payload.get("results") or []
    if not isinstance(results, list) or not results:
        return [negative_finding(domain, provider)]

    now = int(time.time())
    findings = []
    for item in results[: provider.max_results]:
        if not isinstance(item, dict):
            continue
        page = item.get("page") if isinstance(item.get("page"), dict) else {}
        stats = item.get("stats") if isinstance(item.get("stats"), dict) else {}
        task = item.get("task") if isinstance(item.get("task"), dict) else {}
        verdicts = item.get("verdicts") if isinstance(item.get("verdicts"), dict) else {}
        overall = verdicts.get("overall") if isinstance(verdicts, dict) else {}
        malicious = bool(isinstance(overall, dict) and overall.get("malicious"))
        score = int(overall.get("score") or 0) if isinstance(overall, dict) else 0
        findings.append(
            ResearchFinding(
                domain=normalize_domain(domain),
                provider=provider.name,
                kind="archived_web_scan",
                title=(
                    f"urlscan.io archived scan: {page.get('title') or page.get('domain') or domain}"
                ),
                summary=(
                    f"Archived scan from {task.get('time') or 'unknown time'}; "
                    f"page status={page.get('status') or 'unknown'}; "
                    f"IP={page.get('ip') or 'unknown'}; "
                    f"ASN={page.get('asn') or 'unknown'}; "
                    f"unique domains={stats.get('uniqDomains', 0)}; "
                    f"malicious verdict={malicious}; score={score}."
                ),
                source_url=str(item.get("result") or ""),
                confidence=0.9 if malicious else 0.65,
                signal_type="behavior",
                verdict="malicious_scan" if malicious else "scan_context",
                decision_relevant=False,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data=item,
            )
        )
    return findings


def research_cloudflare_radar(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        raise ResearchError("Cloudflare Radar requires an API token")
    base_url = (provider.base_url or "https://api.cloudflare.com/client/v4/radar").rstrip("/")
    wait_for_provider(provider)
    response = requests.get(
        f"{base_url}/ranking/domain/{quote(normalize_domain(domain), safe='.-_')}",
        headers=request_headers(Authorization=f"Bearer {provider.api_key.strip()}"),
        timeout=provider.timeout_sec,
    )
    if response.status_code == 404:
        return [negative_finding(domain, provider)]
    response.raise_for_status()
    payload = response.json()
    result = payload.get("result") or {}
    details = result.get("details_0") or result.get("details") or {}
    categories = details.get("categories") or []
    category_names = [
        str(item.get("name") or "")
        for item in categories
        if isinstance(item, dict) and item.get("name")
    ]
    bucket = str(details.get("bucket") or "unranked")
    rank = details.get("rank")
    summary = f"Popularity bucket: {bucket}"
    if rank is not None:
        summary += f"; rank: {rank}"
    if category_names:
        summary += f"; categories: {', '.join(category_names)}"
    now = int(time.time())
    return [
        ResearchFinding(
            domain=normalize_domain(domain),
            provider=provider.name,
            kind="domain_popularity",
            title="Cloudflare Radar domain ranking",
            summary=summary,
            source_url=f"https://radar.cloudflare.com/domains/domain/{normalize_domain(domain)}",
            confidence=0.9,
            signal_type="popularity",
            verdict="popular" if bucket != "unranked" else "unranked",
            decision_relevant=False,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data=payload,
        )
    ]


def _rdap_bootstrap(provider: ResearchProviderOptions) -> dict[str, str]:
    global _BOOTSTRAP_CACHE
    selected_url = provider.base_url.strip() or _IANA_BOOTSTRAP_URL
    with _BOOTSTRAP_LOCK:
        if (
            _BOOTSTRAP_CACHE
            and _BOOTSTRAP_CACHE[1] == selected_url
            and time.time() - _BOOTSTRAP_CACHE[0] < 86400
        ):
            return dict(_BOOTSTRAP_CACHE[2])
        wait_for_provider(provider)
        response = requests.get(
            selected_url,
            headers=request_headers(),
            timeout=provider.timeout_sec,
        )
        response.raise_for_status()
        data = response.json()
        mapping: dict[str, str] = {}
        for service in data.get("services") or []:
            if not isinstance(service, list) or len(service) != 2:
                continue
            tlds, urls = service
            if not urls:
                continue
            for tld in tlds:
                mapping[str(tld).lower()] = str(urls[0])
        _BOOTSTRAP_CACHE = (time.time(), selected_url, mapping)
        return dict(mapping)


def _rdap_registrar(data: dict[str, Any]) -> str:
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) != 2:
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
                return str(item[3])
    return ""


def _public_addresses(domain: str) -> list[str]:
    output: list[str] = []
    try:
        records = socket.getaddrinfo(normalize_domain(domain), None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    for record in records:
        address = str(record[4][0])
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not parsed.is_global or address in output:
            continue
        output.append(address)
    return output


def _ripestat_as_holder(
    base_url: str,
    asn: str,
    provider: ResearchProviderOptions,
) -> str:
    wait_for_provider(provider)
    response = requests.get(
        f"{base_url}/as-overview/data.json",
        params={"resource": f"AS{asn}", "sourceapp": "pi-hole-manager"},
        headers=request_headers(),
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    return str((response.json().get("data") or {}).get("holder") or "")


def _robots_allows(
    base_url: str,
    target_url: str,
    provider: ResearchProviderOptions,
) -> bool:
    robots_url = urljoin(base_url, "/robots.txt")
    cached = _ROBOTS_CACHE.get(robots_url)
    if cached and time.time() - cached[0] < 86400:
        lines = cached[1]
    else:
        wait_for_provider(provider)
        response = requests.get(
            robots_url,
            headers=request_headers(Accept="text/plain"),
            timeout=provider.timeout_sec,
        )
        if response.status_code >= 400:
            return False
        lines = response.text.splitlines()
        _ROBOTS_CACHE[robots_url] = (time.time(), lines)
    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(lines)
    return parser.can_fetch("Pi-Hole-Manager", target_url)


class _NetcraftTableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}
        self._in_cell = False
        self._cell_parts: list[str] = []
        self._row: list[str] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        if tag in {"th", "td"}:
            self._in_cell = True
            self._cell_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_cell and data.strip():
            self._cell_parts.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag in {"th", "td"} and self._in_cell:
            value = " ".join(self._cell_parts).strip()
            self._row.append(value)
            self._in_cell = False
            self._cell_parts = []
        elif tag == "tr":
            values = [value for value in self._row if value]
            if len(values) >= 2:
                key = values[0].rstrip(":")
                value = " | ".join(values[1:])
                if key and value:
                    self.fields[key] = value
            self._row = []


def _select_netcraft_fields(fields: dict[str, str]) -> dict[str, str]:
    wanted = (
        "Site title",
        "Site rank",
        "Description",
        "Date first seen",
        "Netblock Owner",
        "Hosting company",
        "Hosting country",
        "IPv4 address",
        "IPv4 autonomous systems",
        "IPv6 address",
        "IPv6 autonomous systems",
        "Reverse DNS",
        "Domain",
        "Nameserver",
        "Domain registrar",
        "Nameserver organisation",
        "Organisation",
        "DNS Security Extensions",
        "Web Server",
        "SSL Certificate",
    )
    return {key: fields[key][:500] for key in wanted if fields.get(key)}


def _safe_confidence(value: Any, fallback: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return fallback
    if numeric > 1:
        numeric /= 100.0
    return max(0.0, min(1.0, numeric))


def _threatfox_verdict(threat_type: str) -> str:
    mapping = {
        "botnet_cc": "command_and_control",
        "cc_skimming": "security_antifraud",
        "payload_delivery": "malware",
    }
    return mapping.get(threat_type.strip().lower(), "malware")
