from __future__ import annotations

import argparse
import base64
import json
import os
import stat
import sys
from datetime import UTC, date, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pihole_manager.provider_registry import (
    ProviderRegistryError,
    parse_provider_registry,
    verify_registry_signature,
)

_PUBLIC_KEY_PLACEHOLDER = (
    "# Remote registry updates remain disabled until a reviewed Ed25519 public key is installed."
)


def _registry_data(path: Path) -> dict:
    payload = path.read_bytes()
    parse_provider_registry(payload)
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderRegistryError("Registry is not valid UTF-8 JSON.") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ProviderRegistryError("Registry schema_version must be 1.")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ProviderRegistryError("Registry entries must be an array.")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ProviderRegistryError("Every registry entry must be an object.")
        entry_id = str(entry.get("entry_id") or "").strip()
        if not entry_id or entry_id in seen:
            raise ProviderRegistryError("Registry entry IDs must be present and unique.")
        seen.add(entry_id)
        verified_at = str(entry.get("verified_at") or "")
        try:
            date.fromisoformat(verified_at)
        except ValueError as exc:
            raise ProviderRegistryError(
                f"Registry entry {entry_id} has an invalid verified_at date."
            ) from exc
        source_url = str(entry.get("source_url") or "")
        if not source_url.startswith("https://"):
            raise ProviderRegistryError(
                f"Registry entry {entry_id} must reference an HTTPS source."
            )
    return data


def _validate(path: Path) -> int:
    data = _registry_data(path)
    print(f"Valid registry {data.get('registry_version')} with {len(data['entries'])} entries.")
    return 0


def _stale(path: Path, maximum_age_days: int) -> int:
    data = _registry_data(path)
    today = datetime.now(UTC).date()
    stale = []
    for entry in data["entries"]:
        verified_at = date.fromisoformat(str(entry["verified_at"]))
        age = (today - verified_at).days
        if age > maximum_age_days:
            stale.append((str(entry["entry_id"]), age, str(entry["source_url"])))
    if not stale:
        print(f"All provider registry entries are at most {maximum_age_days} days old.")
        return 0
    print(f"Provider registry review required ({len(stale)} stale entries):")
    for entry_id, age, source_url in stale:
        print(f"- {entry_id}: {age} days old — {source_url}")
    return 2


def _private_key(value: str) -> Ed25519PrivateKey:
    payload = value.replace("\\n", "\n").encode("utf-8")
    key = serialization.load_pem_private_key(payload, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Signing key is not Ed25519.")
    return key


def _sign(registry_path: Path, signature_path: Path, private_key_value: str) -> int:
    _registry_data(registry_path)
    payload = registry_path.read_bytes()
    signature = _private_key(private_key_value).sign(payload)
    envelope = {
        "algorithm": "ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    signature_path.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(signature_path)
    return 0


def _verify(registry_path: Path, signature_path: Path, public_key_path: Path) -> int:
    _registry_data(registry_path)
    verify_registry_signature(
        registry_path.read_bytes(),
        signature_path.read_bytes(),
        public_key_path.read_bytes(),
    )
    print("Registry signature is valid.")
    return 0


def _generate_key(private_path: Path, public_path: Path) -> int:
    if private_path.exists():
        raise FileExistsError("Refusing to overwrite an existing registry key.")
    if public_path.exists():
        try:
            existing_public_key = public_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise FileExistsError("Refusing to overwrite an existing registry key.") from exc
        if existing_public_key != _PUBLIC_KEY_PLACEHOLDER:
            raise FileExistsError("Refusing to overwrite an existing registry key.")
    private_key = Ed25519PrivateKey.generate()
    private_payload = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_payload = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_payload)
    private_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    public_path.write_bytes(public_payload)
    print(f"Private key: {private_path}")
    print(f"Public key: {public_path}")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the signed provider registry")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("registry", type=Path)

    stale = subparsers.add_parser("stale")
    stale.add_argument("registry", type=Path)
    stale.add_argument("--max-age-days", type=int, default=35)

    sign = subparsers.add_parser("sign")
    sign.add_argument("registry", type=Path)
    sign.add_argument("signature", type=Path)
    sign.add_argument(
        "--private-key-env",
        default="PROVIDER_REGISTRY_ED25519_PRIVATE_KEY",
    )

    verify = subparsers.add_parser("verify")
    verify.add_argument("registry", type=Path)
    verify.add_argument("signature", type=Path)
    verify.add_argument("public_key", type=Path)

    generate = subparsers.add_parser("generate-key")
    generate.add_argument("private_key", type=Path)
    generate.add_argument("public_key", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "validate":
        return _validate(args.registry)
    if args.command == "stale":
        return _stale(args.registry, max(1, args.max_age_days))
    if args.command == "sign":
        private_key_value = os.environ.get(args.private_key_env, "")
        if not private_key_value:
            raise RuntimeError(f"Missing signing key environment variable: {args.private_key_env}")
        return _sign(args.registry, args.signature, private_key_value)
    if args.command == "verify":
        return _verify(args.registry, args.signature, args.public_key)
    if args.command == "generate-key":
        return _generate_key(args.private_key, args.public_key)
    raise RuntimeError(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"provider-registry: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
