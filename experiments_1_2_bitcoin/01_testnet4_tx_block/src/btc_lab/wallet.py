from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .encoding import encode_segwit_address, hash160, p2wpkh_script


def _new_key() -> dict[str, str]:
    from coincurve import PrivateKey

    private_key = PrivateKey()
    public_key = private_key.public_key.format(compressed=True)
    program = hash160(public_key)
    return {
        "private_key_hex": private_key.secret.hex(),
        "public_key_hex": public_key.hex(),
        "address": encode_segwit_address("tb", 0, program),
        "script_pubkey": p2wpkh_script(public_key).hex(),
    }


def create_wallet(secret_path: Path, public_path: Path) -> dict[str, Any]:
    if secret_path.exists():
        return load_wallet(secret_path)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    wallet: dict[str, Any] = {
        "network": "testnet4",
        "address_hrp": "tb",
        "sender": _new_key(),
        "receiver": _new_key(),
    }
    secret_path.write_text(json.dumps(wallet, indent=2) + "\n", encoding="utf-8")
    os.chmod(secret_path, 0o600)
    public = public_wallet(wallet)
    public_path.write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8")
    return wallet


def load_wallet(secret_path: Path) -> dict[str, Any]:
    if not secret_path.exists():
        raise FileNotFoundError("wallet not initialized; run `btc-lab wallet-init`")
    return json.loads(secret_path.read_text(encoding="utf-8"))


def public_wallet(wallet: dict[str, Any]) -> dict[str, Any]:
    return {
        "network": wallet["network"],
        "address_hrp": wallet["address_hrp"],
        "sender": {key: value for key, value in wallet["sender"].items() if key != "private_key_hex"},
        "receiver": {key: value for key, value in wallet["receiver"].items() if key != "private_key_hex"},
    }

