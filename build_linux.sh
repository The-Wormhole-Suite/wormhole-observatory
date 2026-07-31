#!/bin/sh
set -eu
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi

PYTHON="$(pwd)/.venv/bin/python"
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -e ".[build]"
rm -rf build dist release
"$PYTHON" -m PyInstaller --clean --noconfirm Pi-Hole-Manager.spec
"$PYTHON" build_release.py --platform linux

printf '%s\n' "Onedir build created at dist/Pi-Hole-Manager"
printf '%s\n' "Update archive created in release/"
