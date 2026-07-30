import pytest

from btc_lab.encoding import encode_compact_size, encode_segwit_address, read_compact_size
from btc_lab.models import ByteReader, ParseError


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "00"),
        (252, "fc"),
        (253, "fdfd00"),
        (65535, "fdffff"),
        (65536, "fe00000100"),
        (0xFFFFFFFF, "feffffffff"),
        (0x100000000, "ff0000000001000000"),
    ],
)
def test_compact_size_boundaries(value, expected):
    encoded = encode_compact_size(value)
    assert encoded.hex() == expected
    reader = ByteReader(encoded)
    assert read_compact_size(reader, "value") == value
    assert reader.pos == len(encoded)


def test_reject_noncanonical_compact_size():
    with pytest.raises(ParseError):
        read_compact_size(ByteReader(bytes.fromhex("fdfc00")), "value")


def test_bip173_known_witness_address():
    program = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    assert encode_segwit_address("bc", 0, program) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
