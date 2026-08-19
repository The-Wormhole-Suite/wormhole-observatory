# Evidence-source licensing and release policy

This document records the technical licensing/usage review for evidence sources that
Wormhole Observatory can download, index, or query. It is a release-safety policy,
not legal advice.

Review date: 2026-08-20.

## Release rule

A distributed build may contain an evidence adapter without bundling its upstream
data. However, an evidence source may be enabled in the shipped default configuration
only when its policy is reviewed and marked `release_default_eligible`.

The release builder enforces this rule. Unknown sources fail closed. Sources with
NonCommercial restrictions or provider-specific commercial terms remain opt-in.

Downloaded catalog data stays in the runtime evidence cache and is not packaged into
release archives.

## Reviewed datasets and catalogs

| Source | Upstream terms | Commercial-use assessment | Release default |
| --- | --- | --- | --- |
| AdGuard HostlistsRegistry service catalog | GPL-3.0 | Allowed subject to GPL obligations | Eligible |
| Disconnect tracking-protection lists | CC BY-NC-SA 4.0 | NonCommercial restriction; separate commercial licence offered by Disconnect | Opt-in only |
| PhishTank defined Data / verified database | PhishTank Terms of Use | Terms explicitly permit commercial use of defined Data without charge | Eligible |
| HaGeZi TIF Mini | GPL-3.0 | Allowed subject to GPL obligations | Eligible |
| EasyPrivacy tracking servers | GPL-3.0-or-later OR CC BY-SA 3.0-or-later | Commercial use permitted subject to the selected licence obligations | Eligible |

### Primary sources

- AdGuard HostlistsRegistry licence:
  https://github.com/AdguardTeam/HostlistsRegistry/blob/main/LICENSE
- Disconnect licence:
  https://github.com/disconnectme/disconnect-tracking-protection/blob/master/LICENSE
- PhishTank Terms of Use:
  https://phishtank.org/terms.php
- PhishTank developer/database documentation:
  https://phishtank.org/developer_info.php
- HaGeZi dns-blocklists licence:
  https://github.com/hagezi/dns-blocklists/blob/main/LICENSE
- EasyList/EasyPrivacy licence:
  https://easylist.to/pages/licence.html

## API and live-lookup sources

API integrations do not cause their upstream datasets to be bundled into Wormhole
Observatory releases. For sources governed by provider-specific API or fair-use
terms, the conservative release policy is therefore `opt-in only` unless a later
review explicitly clears default enablement.

This applies to RDAP providers, RIPEstat, Netcraft, VirusTotal, ThreatFox, urlscan.io,
Cloudflare Radar, and URLhaus.

URLhaus deserves an explicit note: its free Community API is available under abuse.ch
fair-use principles, while commercial or for-profit needs may require the enhanced
commercial API. Wormhole therefore keeps URLhaus disabled by default and requires the
user's own Auth-Key.

Primary URLhaus API documentation:
https://urlhaus.abuse.ch/api/

## Repository-list provenance

Every locally indexed repository-list finding records:

- source repository and ref
- list path and download URL
- matched rule and source line
- licence identifier and licence URL
- commercial-use classification
- redistribution classification
- review date and review-required state
- release-default eligibility

Repository list entries without a registered reviewed policy are skipped instead of
being silently consumed.

## Maintenance

Whenever an evidence source, dataset, upstream licence, API terms, or distribution
model changes:

1. update `pihole_manager/evidence_licensing.py`;
2. update this document with the current primary source;
3. adjust provenance metadata when needed;
4. run the evidence-licensing tests;
5. do not override the release gate merely to make a build pass.

The review date is intentionally stored in code so stale policy decisions are visible
and can later be checked automatically.
