#!/usr/bin/env python3
"""Reproduce ECDSA existential forgery when the verifier trusts a supplied digest.

The attacker-facing part of the demonstration uses only a public key P and two
chosen non-zero scalars u and v.  No private key is present in this file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# Public key from Task 1.  Its private key is deliberately absent.
PUBLIC_KEY_COMPRESSED = (
    "021c2a98e839fb46a75c19528a8e7466c41ffa4639ac3db717963c8355d3a7dec8"
)
FIXED_MESSAGE = b"course project fixed message"


Point = tuple[int, int] | None


def inverse(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * inverse(2 * y1, P_FIELD) % P_FIELD
    else:
        slope = (y2 - y1) * inverse(x2 - x1, P_FIELD) % P_FIELD
    x3 = (slope * slope - x1 - x2) % P_FIELD
    y3 = (slope * (x1 - x3) - y1) % P_FIELD
    return x3, y3


def scalar_multiply(scalar: int, point: Point) -> Point:
    result: Point = None
    addend = point
    scalar %= N_ORDER
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def decompress_public_key(encoded_hex: str) -> tuple[int, int]:
    encoded = bytes.fromhex(encoded_hex)
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("expected a compressed secp256k1 public key")
    x = int.from_bytes(encoded[1:], "big")
    y = pow((pow(x, 3, P_FIELD) + 7) % P_FIELD, (P_FIELD + 1) // 4, P_FIELD)
    if y & 1 != encoded[0] & 1:
        y = P_FIELD - y
    if (y * y - x * x * x - 7) % P_FIELD:
        raise ValueError("public key is not on secp256k1")
    return x, y


def verify_digest(public_key: Point, digest: int, r: int, s: int) -> bool:
    if public_key is None or not (1 <= r < N_ORDER and 1 <= s < N_ORDER):
        return False
    w = inverse(s, N_ORDER)
    candidate = point_add(
        scalar_multiply(digest * w, G),
        scalar_multiply(r * w, public_key),
    )
    return candidate is not None and candidate[0] % N_ORDER == r


def main() -> None:
    public_key = decompress_public_key(PUBLIC_KEY_COMPRESSED)
    u = 0x12345
    v = 0x6789A
    candidate = point_add(scalar_multiply(u, G), scalar_multiply(v, public_key))
    if candidate is None:
        raise RuntimeError("chosen u and v unexpectedly produced the point at infinity")
    r_forged = candidate[0] % N_ORDER
    s_forged = r_forged * inverse(v, N_ORDER) % N_ORDER
    e_chosen = r_forged * u * inverse(v, N_ORDER) % N_ORDER
    fixed_digest = int.from_bytes(hashlib.sha256(FIXED_MESSAGE).digest(), "big") % N_ORDER

    result = {
        "public_key_compressed": PUBLIC_KEY_COMPRESSED,
        "attacker_inputs": {"u_hex": hex(u), "v_hex": hex(v)},
        "forged_signature": {"r_hex": f"{r_forged:064x}", "s_hex": f"{s_forged:064x}"},
        "attacker_chosen_digest_hex": f"{e_chosen:064x}",
        "chosen_digest_verifies": verify_digest(public_key, e_chosen, r_forged, s_forged),
        "fixed_message_utf8": FIXED_MESSAGE.decode(),
        "fixed_message_sha256_hex": f"{fixed_digest:064x}",
        "fixed_message_verifies": verify_digest(public_key, fixed_digest, r_forged, s_forged),
        "private_key_used_by_attack": False,
    }
    output_path = Path(__file__).resolve().parents[1] / "results" / "forgery_demo.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
