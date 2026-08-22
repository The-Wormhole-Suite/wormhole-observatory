$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$PipVersion = "26.2.1"
$ReleaseDir = if ($env:PIHOLE_MANAGER_RELEASE_DIR) { $env:PIHOLE_MANAGER_RELEASE_DIR } else { "release" }

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not $env:PYTHONHASHSEED) {
    $env:PYTHONHASHSEED = "1"
}
if (-not $env:SOURCE_DATE_EPOCH) {
    $env:SOURCE_DATE_EPOCH = (& git show -s --format=%ct HEAD).Trim()
}

& $Python -m pip install --upgrade "pip==$PipVersion"
& $Python -m pip install -r requirements-build.lock
& $Python -m pip install --no-deps --no-build-isolation -e .
Remove-Item -Recurse -Force "build", "dist", $ReleaseDir -ErrorAction SilentlyContinue
& $Python -m PyInstaller --clean --noconfirm "Pi-Hole-Manager.spec"
& $Python "build_release.py" --platform windows --output-dir $ReleaseDir

Write-Host "Onedir build created at dist\Pi-Hole-Manager"
Write-Host "Deterministic update archive created in $ReleaseDir\"
