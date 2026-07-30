from __future__ import annotations

import math
from typing import Any

from .encoding import (
    encode_compact_size,
    hash160,
    p2pkh_script,
    p2wpkh_script,
    read_compact_size,
    sha256d,
)
from .models import ByteReader, ParseError, assert_complete_coverage
from .script import classify_script, disassemble_script


SIGHASH_ALL = 1
RBF_SEQUENCE = 0xFFFFFFFD


def serialize_transaction(tx: dict[str, Any], *, include_witness: bool = True) -> bytes:
    result = bytearray()
    result.extend(int(tx["version"]).to_bytes(4, "little", signed=True))
    has_witness = bool(tx.get("has_witness")) and include_witness
    if has_witness:
        result.extend(b"\x00\x01")
    result.extend(encode_compact_size(len(tx["inputs"])))
    for txin in tx["inputs"]:
        result.extend(bytes.fromhex(txin["prev_txid"])[::-1])
        result.extend(int(txin["prev_vout"]).to_bytes(4, "little"))
        script_sig = bytes.fromhex(txin.get("script_sig", ""))
        result.extend(encode_compact_size(len(script_sig)))
        result.extend(script_sig)
        result.extend(int(txin["sequence"]).to_bytes(4, "little"))
    result.extend(encode_compact_size(len(tx["outputs"])))
    for txout in tx["outputs"]:
        result.extend(int(txout["value_sats"]).to_bytes(8, "little"))
        script_pubkey = bytes.fromhex(txout["script_pubkey"])
        result.extend(encode_compact_size(len(script_pubkey)))
        result.extend(script_pubkey)
    if has_witness:
        witnesses = tx.get("witnesses", [[] for _ in tx["inputs"]])
        if len(witnesses) != len(tx["inputs"]):
            raise ValueError("one witness stack is required per input")
        for stack in witnesses:
            result.extend(encode_compact_size(len(stack)))
            for item_hex in stack:
                item = bytes.fromhex(item_hex)
                result.extend(encode_compact_size(len(item)))
                result.extend(item)
    result.extend(int(tx["locktime"]).to_bytes(4, "little"))
    return bytes(result)


def _parse_transaction(reader: ByteReader, prefix: str = "tx") -> dict[str, Any]:
    start = reader.pos
    version = reader.read_uint(4, f"{prefix}.version", signed=True, notes="transaction version")
    has_witness = reader.remaining() >= 2 and reader.peek(2)[0] == 0 and reader.peek(2)[1] != 0
    if has_witness:
        reader.read(1, f"{prefix}.marker", decoded_value=0, notes="SegWit marker")
        flag = reader.peek(1)[0]
        reader.read(1, f"{prefix}.flag", decoded_value=flag, notes="SegWit serialization flag")
    input_count = read_compact_size(reader, f"{prefix}.input_count")
    inputs: list[dict[str, Any]] = []
    for index in range(input_count):
        base = f"{prefix}.inputs[{index}]"
        prev_internal = reader.peek(32)
        reader.read(
            32,
            f"{base}.prev_txid",
            decoded_value=prev_internal[::-1].hex(),
            endian="internal little-endian hash order",
        )
        prev_vout = reader.read_uint(4, f"{base}.prev_vout")
        script_length = read_compact_size(reader, f"{base}.script_sig_length")
        script_sig = reader.peek(script_length)
        reader.read(script_length, f"{base}.script_sig", decoded_value=script_sig.hex(), notes="unlocking script")
        sequence = reader.read_uint(4, f"{base}.sequence")
        inputs.append(
            {
                "prev_txid": prev_internal[::-1].hex(),
                "prev_vout": prev_vout,
                "script_sig": script_sig.hex(),
                "script_sig_asm": disassemble_script(script_sig),
                "sequence": sequence,
            }
        )
    output_count = read_compact_size(reader, f"{prefix}.output_count")
    outputs: list[dict[str, Any]] = []
    for index in range(output_count):
        base = f"{prefix}.outputs[{index}]"
        value_sats = reader.read_uint(8, f"{base}.value_sats", notes="amount in satoshis")
        script_length = read_compact_size(reader, f"{base}.script_pubkey_length")
        script_pubkey = reader.peek(script_length)
        reader.read(
            script_length,
            f"{base}.script_pubkey",
            decoded_value=script_pubkey.hex(),
            notes="locking script",
        )
        outputs.append(
            {
                "value_sats": value_sats,
                "script_pubkey": script_pubkey.hex(),
                "script_type": classify_script(script_pubkey),
                "script_pubkey_asm": disassemble_script(script_pubkey),
            }
        )
    witnesses: list[list[str]] = []
    if has_witness:
        for input_index in range(input_count):
            stack_count = read_compact_size(reader, f"{prefix}.witnesses[{input_index}].item_count")
            stack: list[str] = []
            for item_index in range(stack_count):
                item_length = read_compact_size(
                    reader, f"{prefix}.witnesses[{input_index}].items[{item_index}].length"
                )
                item = reader.peek(item_length)
                reader.read(
                    item_length,
                    f"{prefix}.witnesses[{input_index}].items[{item_index}].data",
                    decoded_value=item.hex(),
                    notes="witness stack element; not Script bytecode by itself",
                )
                stack.append(item.hex())
            witnesses.append(stack)
    locktime = reader.read_uint(4, f"{prefix}.locktime")
    end = reader.pos
    parsed: dict[str, Any] = {
        "version": version,
        "has_witness": has_witness,
        "inputs": inputs,
        "outputs": outputs,
        "witnesses": witnesses,
        "locktime": locktime,
        "start_offset": start,
        "end_offset": end,
    }
    full = serialize_transaction(parsed, include_witness=True)
    stripped = serialize_transaction(parsed, include_witness=False)
    parsed.update(
        {
            "raw_hex": full.hex(),
            "stripped_hex": stripped.hex(),
            "txid": sha256d(stripped)[::-1].hex(),
            "wtxid": sha256d(full)[::-1].hex(),
            "size": len(full),
            "base_size": len(stripped),
            "witness_size": len(full) - len(stripped),
            "weight": len(stripped) * 4 + (len(full) - len(stripped)),
        }
    )
    parsed["vsize"] = math.ceil(parsed["weight"] / 4)
    return parsed


def parse_transaction(raw: bytes, *, require_all: bool = True) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reader = ByteReader(raw)
    parsed = _parse_transaction(reader)
    if require_all and reader.remaining() != 0:
        raise ParseError(f"{reader.remaining()} trailing bytes after transaction")
    coverage = assert_complete_coverage(reader.records, 0, reader.pos)
    parsed["byte_coverage"] = coverage
    return parsed, [record.to_dict() for record in reader.records]


def bip143_sighash(tx: dict[str, Any], input_index: int, script_code: bytes, input_value: int) -> bytes:
    if not 0 <= input_index < len(tx["inputs"]):
        raise IndexError("input index out of range")
    prevouts = b"".join(
        bytes.fromhex(txin["prev_txid"])[::-1] + int(txin["prev_vout"]).to_bytes(4, "little")
        for txin in tx["inputs"]
    )
    sequences = b"".join(int(txin["sequence"]).to_bytes(4, "little") for txin in tx["inputs"])
    serialized_outputs = bytearray()
    for output in tx["outputs"]:
        script = bytes.fromhex(output["script_pubkey"])
        serialized_outputs.extend(int(output["value_sats"]).to_bytes(8, "little"))
        serialized_outputs.extend(encode_compact_size(len(script)))
        serialized_outputs.extend(script)
    current = tx["inputs"][input_index]
    preimage = bytearray()
    preimage.extend(int(tx["version"]).to_bytes(4, "little", signed=True))
    preimage.extend(sha256d(prevouts))
    preimage.extend(sha256d(sequences))
    preimage.extend(bytes.fromhex(current["prev_txid"])[::-1])
    preimage.extend(int(current["prev_vout"]).to_bytes(4, "little"))
    preimage.extend(encode_compact_size(len(script_code)))
    preimage.extend(script_code)
    preimage.extend(int(input_value).to_bytes(8, "little"))
    preimage.extend(int(current["sequence"]).to_bytes(4, "little"))
    preimage.extend(sha256d(bytes(serialized_outputs)))
    preimage.extend(int(tx["locktime"]).to_bytes(4, "little"))
    preimage.extend(SIGHASH_ALL.to_bytes(4, "little"))
    return sha256d(bytes(preimage))


def build_and_sign_p2wpkh(
    *,
    private_key: bytes,
    public_key: bytes,
    utxo: dict[str, Any],
    receiver_script: bytes,
    change_script: bytes,
    payment_sats: int = 1000,
    fee_rate: float = 2.0,
) -> dict[str, Any]:
    from coincurve import PrivateKey

    if payment_sats < 294:
        raise ValueError("payment output is below the conservative P2WPKH dust threshold")
    input_value = int(utxo["value"])
    estimated_vsize = 141
    fee_sats = math.ceil(estimated_vsize * fee_rate)
    change_sats = input_value - payment_sats - fee_sats
    if change_sats < 294:
        raise ValueError(
            f"insufficient UTXO: need payment {payment_sats} + fee {fee_sats} + change >= 294, got {input_value}"
        )
    tx: dict[str, Any] = {
        "version": 2,
        "has_witness": True,
        "inputs": [
            {
                "prev_txid": utxo["txid"],
                "prev_vout": int(utxo["vout"]),
                "script_sig": "",
                "sequence": RBF_SEQUENCE,
            }
        ],
        "outputs": [
            {"value_sats": payment_sats, "script_pubkey": receiver_script.hex()},
            {"value_sats": change_sats, "script_pubkey": change_script.hex()},
        ],
        "witnesses": [[]],
        "locktime": 0,
    }
    pubkey_hash = hash160(public_key)
    if change_script != p2wpkh_script(public_key):
        raise ValueError("change script does not match sender public key")
    digest = bip143_sighash(tx, 0, p2pkh_script(pubkey_hash), input_value)
    signature_der = PrivateKey(private_key).sign(digest, hasher=None)
    signature_with_type = signature_der + bytes([SIGHASH_ALL])
    tx["witnesses"] = [[signature_with_type.hex(), public_key.hex()]]
    full = serialize_transaction(tx, include_witness=True)
    stripped = serialize_transaction(tx, include_witness=False)
    weight = len(stripped) * 4 + len(full) - len(stripped)
    vsize = math.ceil(weight / 4)
    return {
        "network": "testnet4",
        "transaction": tx,
        "raw_hex": full.hex(),
        "stripped_hex": stripped.hex(),
        "txid": sha256d(stripped)[::-1].hex(),
        "wtxid": sha256d(full)[::-1].hex(),
        "input_value_sats": input_value,
        "payment_sats": payment_sats,
        "change_sats": change_sats,
        "fee_sats": fee_sats,
        "fee_rate_sat_vb": fee_sats / vsize,
        "size": len(full),
        "base_size": len(stripped),
        "weight": weight,
        "vsize": vsize,
        "sighash": digest.hex(),
        "previous_output_script": p2wpkh_script(public_key).hex(),
    }


def verify_p2wpkh_draft(draft: dict[str, Any]) -> dict[str, Any]:
    from coincurve import PublicKey

    tx = draft["transaction"]
    if len(tx["inputs"]) != 1 or len(tx.get("witnesses", [])) != 1:
        raise ValueError("verification routine expects the lab's one-input transaction")
    signature_with_type = bytes.fromhex(tx["witnesses"][0][0])
    public_key = bytes.fromhex(tx["witnesses"][0][1])
    if not signature_with_type or signature_with_type[-1] != SIGHASH_ALL:
        raise ValueError("unexpected sighash type")
    previous_script = bytes.fromhex(draft["previous_output_script"])
    expected_previous_script = p2wpkh_script(public_key)
    if previous_script != expected_previous_script:
        raise ValueError("witness public key does not match previous output")
    digest = bip143_sighash(tx, 0, p2pkh_script(hash160(public_key)), int(draft["input_value_sats"]))
    signature_valid = PublicKey(public_key).verify(signature_with_type[:-1], digest, hasher=None)
    raw = serialize_transaction(tx, include_witness=True)
    parsed, _ = parse_transaction(raw)
    return {
        "signature_valid": signature_valid,
        "sighash_matches": digest.hex() == draft["sighash"],
        "txid_matches": parsed["txid"] == draft["txid"],
        "wtxid_matches": parsed["wtxid"] == draft["wtxid"],
        "amount_conservation": int(draft["input_value_sats"])
        == sum(int(output["value_sats"]) for output in tx["outputs"]) + int(draft["fee_sats"]),
        "calculated_sighash": digest.hex(),
    }

