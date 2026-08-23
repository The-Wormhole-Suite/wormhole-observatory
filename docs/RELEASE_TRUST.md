# Release signing and provenance

Wormhole Observatory release archives use two linked trust records after the reproducible build check has passed:

1. **Sigstore keyless signing** signs each Windows and Linux release ZIP with the GitHub Actions OIDC identity of the release workflow.
2. A **portable in-toto/SLSA-v1 provenance statement** records the ZIP digest, source commit, Git ref, workflow identity, workflow run, and runner platform. That provenance file is separately signed and verified with the same Sigstore workflow identity.

No long-lived private signing key is stored in the repository or in GitHub Secrets. The workflow receives a short-lived OIDC identity only for the running job.

For public repositories, the workflow additionally publishes a GitHub Artifact Attestation. GitHub's hosted attestation storage is not available to this private repository under its current organization plan, so release trust does not depend on that plan-specific service.

## Order of operations

The release pipeline intentionally keeps reproducibility and signing separate:

1. Build the Onedir package twice in clean environments.
2. Verify that both release ZIPs are byte-for-byte identical.
3. Generate an in-toto/SLSA-v1 provenance statement for the verified ZIP.
4. Sign the ZIP with Sigstore and verify its workflow identity immediately.
5. Sign the provenance statement with Sigstore and verify its workflow identity immediately.
6. Upload the ZIP, SHA-256 sidecar, provenance statement, and Sigstore bundles as release artifacts.

The generated files are stored next to the archive:

- `<archive>.sigstore.json` - Sigstore signature bundle for the ZIP.
- `<archive>.intoto.json` - portable provenance statement.
- `<archive>.intoto.json.sigstore.json` - Sigstore signature bundle for the provenance.

## Verify a stable release archive

Install the current Sigstore Python CLI and verify the downloaded ZIP against the expected release-workflow identity. Replace the example version and archive name with the release being checked.

```bash
sigstore verify identity \
  --bundle Pi-Hole-Manager-linux-x64.zip.sigstore.json \
  --cert-identity "https://github.com/The-Wormhole-Suite/wormhole-observatory/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  Pi-Hole-Manager-linux-x64.zip
```

For a Windows release, use the corresponding Windows ZIP and bundle. Development builds are signed by `.github/workflows/dev-release.yml@refs/heads/dev` instead.

## Verify the portable provenance

First verify the provenance file itself with Sigstore:

```bash
sigstore verify identity \
  --bundle Pi-Hole-Manager-linux-x64.zip.intoto.json.sigstore.json \
  --cert-identity "https://github.com/The-Wormhole-Suite/wormhole-observatory/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  Pi-Hole-Manager-linux-x64.zip.intoto.json
```

Then inspect the statement and compare `subject[0].digest.sha256` with the SHA-256 digest of the downloaded ZIP. The statement also records the source commit, Git ref, workflow identity, workflow run, runner operating system, and runner architecture.

If the repository becomes public in the future, GitHub's additional attestation can be checked with:

```bash
gh attestation verify Pi-Hole-Manager-linux-x64.zip \
  -R The-Wormhole-Suite/wormhole-observatory
```

## What each mechanism proves

- The SHA-256 sidecar is a convenient integrity checksum, but by itself does not identify who produced the file.
- The ZIP Sigstore signature binds the archive digest to the GitHub Actions workflow identity.
- The signed provenance independently records which source revision and workflow run produced that archive digest.
- Reproducibility confirms that the controlled build process produced the same unsigned archive bytes twice before either trust layer was applied.

These mechanisms complement each other; none of them is a claim that the software itself is vulnerability-free.

## Transparency and private repositories

Sigstore's public-good service uses public certificate/transparency infrastructure. Signing therefore makes the GitHub workflow identity, including the repository name, observable in public transparency records. Release contents and repository source are not published by this mechanism, but the repository/workflow identity is not confidential once keyless public Sigstore signing is used.

## Windows Authenticode

The Windows executable is not Authenticode-signed by this cross-platform release-signing layer. Authenticode/SmartScreen reputation requires a platform-native trusted code-signing certificate or managed signing service and therefore external account/certificate material that is not currently part of the project.

If native Windows signing is added later, it must run **after** the reproducibility check. The reproducible unsigned build remains the deterministic source artifact, while the platform-specific signature is an additional distribution layer.
