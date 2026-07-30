from __future__ import annotations

from typing import Any


OPCODE_NAMES = {
    0x00: "OP_0",
    0x4C: "OP_PUSHDATA1",
    0x4D: "OP_PUSHDATA2",
    0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE",
    **{value: f"OP_{value - 0x50}" for value in range(0x51, 0x61)},
    0x63: "OP_IF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6A: "OP_RETURN",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0xA9: "OP_HASH160",
    0xAA: "OP_HASH256",
    0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
}


def classify_script(script: bytes) -> dict[str, Any]:
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return {"type": "p2pkh", "payload": script[3:23].hex()}
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
        return {"type": "p2sh", "payload": script[2:22].hex()}
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return {"type": "p2wpkh", "witness_version": 0, "payload": script[2:].hex()}
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return {"type": "p2wsh", "witness_version": 0, "payload": script[2:].hex()}
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return {"type": "p2tr", "witness_version": 1, "payload": script[2:].hex()}
    if script[:1] == b"\x6a":
        return {"type": "op_return", "payload": script[1:].hex()}
    return {"type": "nonstandard", "payload": script.hex()}


def disassemble_script(script: bytes) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    offset = 0
    while offset < len(script):
        start = offset
        opcode = script[offset]
        offset += 1
        item: dict[str, Any] = {
            "offset": start,
            "opcode": f"0x{opcode:02x}",
            "name": OPCODE_NAMES.get(opcode, f"OP_UNKNOWN_{opcode:02X}"),
        }
        length: int | None = None
        if 1 <= opcode <= 75:
            length = opcode
            item["name"] = f"PUSH_{length}"
        elif opcode == 0x4C:
            if offset >= len(script):
                item["error"] = "truncated OP_PUSHDATA1 length"
                result.append(item)
                break
            length = script[offset]
            offset += 1
            item["length_bytes"] = 1
        elif opcode == 0x4D:
            if offset + 2 > len(script):
                item["error"] = "truncated OP_PUSHDATA2 length"
                result.append(item)
                break
            length = int.from_bytes(script[offset : offset + 2], "little")
            offset += 2
            item["length_bytes"] = 2
        elif opcode == 0x4E:
            if offset + 4 > len(script):
                item["error"] = "truncated OP_PUSHDATA4 length"
                result.append(item)
                break
            length = int.from_bytes(script[offset : offset + 4], "little")
            offset += 4
            item["length_bytes"] = 4
        if length is not None:
            available = min(length, len(script) - offset)
            item["push_length"] = length
            item["data"] = script[offset : offset + available].hex()
            if available != length:
                item["error"] = f"truncated push: expected {length}, got {available}"
            offset += available
        item["end_offset"] = offset
        result.append(item)
    return result

