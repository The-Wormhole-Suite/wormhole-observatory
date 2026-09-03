# Changelog

## 0.3.7

- Fix the desktop Settings startup crash caused by shadowing Tkinter's internal `_options()` method.
- Add source and packaged GUI startup smoke coverage to prevent publishing a non-starting desktop build.
- Keep the server/container runtime unchanged while documenting the dual-frontend architecture.

## 0.3.6

- Initial Home Assistant App repository metadata.
- Reuse the Wormhole Observatory amd64/aarch64 OCI image.
- Map Supervisor options into the existing authenticated headless runtime.
- Keep Wormhole state under `/data/wormhole` and use cold backups for SQLite consistency.
