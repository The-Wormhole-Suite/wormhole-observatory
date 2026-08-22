#!/bin/sh
set -eu
cd "$(dirname "$0")"

PIP_VERSION="26.2.1"
RELEASE_DIR="${PIHOLE_MANAGER_RELEASE_DIR:-release}"

rm -rf .venv
python -m venv .venv
PYTHON="$(pwd)/.venv/bin/python"
export PYTHONHASHSEED="${PYTHONHASHSEED:-1}"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
    export SOURCE_DATE_EPOCH
fi

"$PYTHON" -m pip install --upgrade "pip==${PIP_VERSION}"
"$PYTHON" -m pip install -r requirements-build.lock
"$PYTHON" -m pip install --no-deps --no-build-isolation -e .
rm -rf build dist "$RELEASE_DIR"
"$PYTHON" -m PyInstaller --clean --noconfirm Pi-Hole-Manager.spec
"$PYTHON" build_release.py --platform linux --output-dir "$RELEASE_DIR"

printf '%s\n' "Onedir build created at dist/Pi-Hole-Manager"
printf '%s\n' "Deterministic update archive created in ${RELEASE_DIR}/"
