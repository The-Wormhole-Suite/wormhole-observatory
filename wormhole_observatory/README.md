# Wormhole Observatory

Home Assistant App metadata for the headless Wormhole Observatory container.

The app provides the authenticated review API, PWA and the same scanner, list-audit and
classification workers used by the desktop application. It runs without the Tk desktop UI and uses
the existing multi-architecture OCI image for `amd64` and `aarch64` systems.

See `DOCS.md` for installation, configuration and registry requirements.
