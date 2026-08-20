# Protected services and compatibility profiles

Wormhole Observatory uses a small, versioned compatibility registry to keep high-breakage
service endpoints from being blocked automatically by a mistaken model classification or an
aggressive tag policy.

## Safety model

A compatibility profile is not a whitelist and does not declare a domain privacy-safe. It adds
local, deterministic service-dependency evidence and a minimum breakage-risk floor. Profiles in
`deny_requires_review` mode also convert a model-generated deny recommendation into manual review.

Protection is enforced twice:

1. before automatic policy resolution, where the classification is enriched with the profile's
   service role and breakage-risk floor; and
2. at the Pi-hole write boundary, where a deny write for a protected domain is rejected unless an
   explicit `compatibility_override=True` is supplied.

The normal GUI supplies that override only after an explicit warning for a manual deny action.
Background/automatic actions never supply it.

## Evidence integration

When evidence is collected for a matching domain, Wormhole Observatory stores a local
`compatibility_profile` finding. The finding is decision-relevant and contains the profile ID,
match type, service role, protection mode, and matched domain pattern. Because it is persisted like
other findings, the existing evidence-citation layer can include the compatibility source in the
generated domain description.

The local profile does not replace threat-intelligence, tracking, or ownership evidence. A
protected endpoint can still be malicious or privacy-invasive; the protection only means that an
automated block has enough compatibility risk to require review.

## Bundled profiles

The first bundled profile set is intentionally conservative and contains only well-documented core
endpoints:

- Microsoft Entra identity authorization/token hosts;
- Google OAuth authorization/token hosts;
- Sign in with Apple authorization;
- Mozilla account sign-in used for Firefox Sync setup; and
- Windows NCSI connectivity probes.

The registry uses exact matching by default. Suffix matching is used only where vendor guidance
explicitly covers a domain family, such as the Windows NCSI probe domains. Suffix matching is DNS
label-aware, so `evilmsftconnecttest.com` does not match `msftconnecttest.com`.

## Registry format

`pihole_manager/data/compatibility_profiles_v1.json` is versioned with `schema_version`. Each
profile contains:

- a stable `profile_id` and display name;
- a service role (`core`, `shared`, or `optional`);
- a minimum breakage-risk score;
- a protection mode;
- exact and/or suffix domains;
- an operator-facing reason; and
- a primary-source URL documenting the service dependency.

`load_compatibility_profiles(path)` can also validate and load another registry file for tests or
future user-managed profile support. Incompatible schema changes require a new schema version.
