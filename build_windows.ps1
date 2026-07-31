$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -e ".[build]"
Remove-Item -Recurse -Force "build", "dist", "release" -ErrorAction SilentlyContinue
& $Python -m PyInstaller --clean --noconfirm "Pi-Hole-Manager.spec"
& $Python "build_release.py" --platform windows

Write-Host "Onedir build created at dist\Pi-Hole-Manager"
Write-Host "Update archive created in release\"
