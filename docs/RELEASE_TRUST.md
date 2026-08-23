# Release signing and provenance

Wormhole Observatory release archives use two independent trust mechanisms after the reproducible build check has passed:

1. **Sigstore keyless signing** signs each Windows and Linux release ZIP with the GitHub Actions OIDC identity of the release workflow.
2. **GitHub Artifact Attestations** record signed build provenance for the same ZIP digest.

No long-lived private signing key is stored in the repository or in GitHub Secrets. The workflow receives a short-lived OIDC identity only for the running job.

## Order of operations

The release pipeline intentionally keeps reproducibility and signing separate:

1. Build the Onedir package twice in clean environments.
2. Verify that both release ZIPs are byte-for-byte identical.
3. Sign the verified ZIP with Sigstore.
4. Verify the new Sigstore signature immediately inside the workflow.
5. Generate a GitHub artifact attestation for the ZIP digest.
6. Upload the ZIP, SHA-256 sidecar, and Sigstore bundle as release artifacts.

The Sigstore bundle is stored next to the archive as `<archive>.sigstore.json`. It contains the information required to validate the signature and its transparency-log proof.

## Verify a stable release with Sigstore

Install the Sigstore Python CLI and verify the downloaded ZIP against the expected release-workflow identity. Replace the example version and archive name with the release being checked.

```bash
sigstore verify identity \
  --bundle Pi-Hole-Manager-linux-x86_64.zip.sigstore.json \
  --cert-identity "https://github.com/The-Wormhole-Suite/wormhole-observatory/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  Pi-Hole-Manager-linux-x86_64.zip
```

For a Windows release, use the corresponding Windows ZIP and bundle. Development builds are signed by `.github/workflows/dev-release.yml@refs/heads/dev` instead.

## Verify GitHub build provenance

With a current GitHub CLI installation:

```bash
gh attestation verify Pi-Hole-Manager-linux-x86_64.zip \
  -R The-Wormhole-Suite/wormhole-observatory
```

GitHub verifies the signed attestation and shows the repository, workflow, commit, event, and other provenance claims associated with the artifact digest.

## What each mechanism proves

- The SHA-256 sidecar is a convenient integrity checksum, but by itself does not identify who produced the file.
- The Sigstore signature binds the archive digest to the GitHub Actions workflow identity and records the signing event in Sigstore's transparency infrastructure.
- The GitHub artifact attestation independently binds the archive digest to GitHub's build provenance, including repository and workflow context.
- Reproducibility confirms that the controlled build process produced the same unsigned archive bytes twice before either trust layer was applied.

These mechanisms complement each other; none of them is a claim that the software itself is vulnerability-free.

## Windows Authenticode

The Windows executable is not Authenticode-signed by this keyless cross-platform release-signing layer. Authenticode/SmartScreen reputation requires a platform-native trusted code-signing certificate or managed signing service and therefore external account/certificate material that is not currently part of the project.

If native Windows signing is added later, it must run **after** the reproducibility check. The reproducible unsigned build remains the deterministic source artifact, while the platform-specific signature is an additional distribution layer.
