# Security Policy

## Supported versions

Wormhole Observatory is currently in pre-1.0 development. Security fixes are applied to the current development line and the latest published release. Older development snapshots are not maintained as security-support branches.

## Reporting a vulnerability

Please do not disclose security vulnerabilities in a public issue, discussion, pull request, or other public channel.

Use GitHub's private vulnerability reporting for this repository when the **Report a vulnerability** option is available under the repository's **Security** tab. Include enough information to reproduce and assess the issue, such as the affected component, version or commit, prerequisites, impact, and a minimal proof of concept when appropriate.

If private vulnerability reporting is temporarily unavailable, open a public issue containing no vulnerability details and ask the maintainers for a private reporting channel. Do not include exploit steps, credentials, tokens, private URLs, or sensitive logs in that issue.

## Scope

Reports are especially useful for issues involving:

- authentication or authorization bypasses in the local review API or PWA;
- credential, token, or secret exposure;
- unsafe Pi-hole rule changes or privilege-boundary violations;
- update, release-signing, provenance, or registry verification bypasses;
- container or Home Assistant isolation problems;
- request forgery, injection, path traversal, or unsafe external-data handling;
- dependency vulnerabilities that are exploitable in Wormhole Observatory.

## Disclosure

Please allow reasonable time for investigation and remediation before public disclosure. Once a fix is available, the project may publish a GitHub Security Advisory and release notes describing the affected versions, impact, and remediation without exposing unrelated sensitive information.
