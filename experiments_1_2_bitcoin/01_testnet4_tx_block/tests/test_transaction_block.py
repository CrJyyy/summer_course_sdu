from btc_lab.block import merkle_root_from_txids, parse_block
from btc_lab.encoding import encode_compact_size, sha256d
from btc_lab.models import ParseError
from btc_lab.transaction import parse_transaction


def legacy_fixture() -> bytes:
    return bytes.fromhex(
        "01000000"
        "01"
        + "00" * 32
        + "ffffffff"
        "01"
        "00"
        "ffffffff"
        "01"
        "e803000000000000"
        "01"
        "51"
        "00000000"
    )


def segwit_fixture() -> bytes:
    return bytes.fromhex(
        "02000000"
        "0001"
        "01"
        + "11" * 32
        + "00000000"
        "00"
        "fdffffff"
        "01"
        "e803000000000000"
        "16"
        "0014"
        + "22" * 20
        + "02"
        "01"
        "00"
        "21"
        "02"
        + "33" * 32
        + "00000000"
    )


def test_parse_legacy_transaction_and_byte_coverage():
    raw = legacy_fixture()
    parsed, records = parse_transaction(raw)
    assert parsed["has_witness"] is False
    assert parsed["inputs"][0]["prev_vout"] == 0xFFFFFFFF
    assert parsed["outputs"][0]["value_sats"] == 1000
    assert parsed["outputs"][0]["script_pubkey_asm"][0]["name"] == "OP_1"
    assert len(records) == len(raw)
    assert [record["offset_start"] for record in records] == list(range(len(raw)))


def test_parse_segwit_transaction_distinguishes_txid_and_wtxid():
    raw = segwit_fixture()
    parsed, records = parse_transaction(raw)
    assert parsed["has_witness"] is True
    assert parsed["inputs"][0]["script_sig"] == ""
    assert len(parsed["witnesses"][0]) == 2
    assert parsed["txid"] != parsed["wtxid"]
    assert parsed["weight"] == parsed["base_size"] * 4 + parsed["witness_size"]
    assert len(records) == len(raw)


def test_reject_truncated_and_trailing_transaction():
    raw = legacy_fixture()
    try:
        parse_transaction(raw[:-1])
        assert False, "expected ParseError"
    except ParseError:
        pass
    try:
        parse_transaction(raw + b"\x00")
        assert False, "expected ParseError"
    except ParseError:
        pass


def test_parse_synthetic_single_transaction_block():
    tx = legacy_fixture()
    internal_txid = sha256d(tx)
    header = (
        (1).to_bytes(4, "little", signed=True)
        + b"\x00" * 32
        + internal_txid
        + (0).to_bytes(4, "little")
        + bytes.fromhex("ffff001d")
        + (0).to_bytes(4, "little")
    )
    block = header + encode_compact_size(1) + tx
    parsed, records = parse_block(block)
    assert parsed["transaction_count"] == 1
    assert parsed["merkle_root_valid"] is True
    assert parsed["calculated_merkle_root"] == merkle_root_from_txids([parsed["transactions"][0]["txid"]])
    assert len(records) == len(block)

