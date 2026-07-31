import json
import os
import platform
import re
from pathlib import Path

project_root = Path(SPECPATH)
build_root = project_root / "build"
build_root.mkdir(parents=True, exist_ok=True)
version_text = (project_root / "pihole_manager" / "__init__.py").read_text(encoding="utf-8")
version_match = re.search(r'__version__\s*=\s*"([^"]+)"', version_text)
version = version_match.group(1) if version_match else "0.0.0"
machine = platform.machine().lower()
architecture = "arm64" if machine in {"arm64", "aarch64"} else "x64"
platform_id = "windows" if os.name == "nt" else "linux"
entrypoint = "Pi-Hole-Manager.exe" if os.name == "nt" else "Pi-Hole-Manager"
manifest_path = build_root / "install_manifest.json"
manifest_path.write_text(
    json.dumps(
        {
            "schema_version": 1,
            "application": "pi-hole-manager",
            "version": version,
            "channel": os.environ.get("PIHOLE_MANAGER_BUILD_CHANNEL", "local"),
            "platform": platform_id,
            "architecture": architecture,
            "entrypoint": entrypoint,
            "build_id": os.environ.get("PIHOLE_MANAGER_BUILD_ID", "local"),
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)

analysis = Analysis(
    [str(project_root / "app.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[(str(manifest_path), ".")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="Pi-Hole-Manager",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)
collection = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="Pi-Hole-Manager",
)
