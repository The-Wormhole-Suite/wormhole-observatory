# Reproducible Onedir releases

Windows and Linux Onedir artifacts are built with a controlled toolchain and are verified byte-for-byte before publication.

## Reproducibility controls

The release build uses the following controls:

- CPython is pinned to `3.11.15` in GitHub Actions.
- Runtime and PyInstaller build dependencies are pinned in `requirements-build.lock`.
- Each build uses a newly created virtual environment; an old local `.venv` cannot leak packages into a release.
- `PYTHONHASHSEED=1` removes randomized Python hash ordering from PyInstaller's build inputs.
- `SOURCE_DATE_EPOCH` is derived from the Git commit timestamp and is supplied to PyInstaller, including its Windows PE timestamp handling.
- The ZIP writer sorts every archive entry and assigns the same source-controlled timestamp rather than filesystem mtimes.
- File permissions are serialized explicitly into the ZIP metadata.
- SHA-256 sidecar files are emitted for every release ZIP.
- Windows and Linux CI each build the same commit twice and fail unless the two ZIP archives are byte-for-byte identical.

PyInstaller documents `PYTHONHASHSEED` and `SOURCE_DATE_EPOCH` as the controls required for reproducible bundles. The second CI build is the enforcement layer: if a future toolchain or dependency reintroduces nondeterminism, publishing is blocked.

## Build locally

The build scripts use the source commit timestamp automatically when `SOURCE_DATE_EPOCH` is not already defined:

### Windows

```powershell
./build_windows.ps1
```

### Linux

```bash
./build_linux.sh
```

Artifacts are written to `release/` by default. A different output directory can be selected with `PIHOLE_MANAGER_RELEASE_DIR`.

For example:

```bash
PIHOLE_MANAGER_RELEASE_DIR=release-pass1 ./build_linux.sh
PIHOLE_MANAGER_RELEASE_DIR=release-pass2 ./build_linux.sh
python scripts/verify_reproducible_release.py release-pass1 release-pass2
```

## Updating the build lock

`requirements-build.lock` is part of the release input. Dependency updates must be deliberate:

1. Update the pinned versions.
2. Run the normal Python and Pi-hole test matrix.
3. Run the reproducible Windows/Linux release jobs.
4. Merge only when both independent build passes match on each platform.

The regular application dependency ranges remain in `pyproject.toml`; the lock is intentionally stricter because release binaries must be reproducible.

## Scope of this guarantee

Reproducibility means two builds of the same source revision, on the controlled platform/Python/dependency inputs used by CI, must produce identical release ZIP bytes. The workflow records the commit SHA through the application's existing build metadata.

Operating-system code signing and release provenance are intentionally handled by the next distribution roadmap item. Signing a binary necessarily changes its bytes, so reproducibility is verified on the unsigned deterministic artifact before the signing/provenance stage is applied.
