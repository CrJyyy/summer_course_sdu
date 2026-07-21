from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


class ParseError(ValueError):
    """Raised when serialized Bitcoin data is malformed or truncated."""


@dataclass(frozen=True)
class ByteRecord:
    offset_start: int
    offset_end: int
    raw_hex: str
    bits: str
    field_path: str
    decoded_value: str
    endian: str
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ByteReader:
    """Cursor reader that assigns every consumed byte to exactly one field."""

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.pos = offset
        self.records: list[ByteRecord] = []

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def peek(self, n: int = 1) -> bytes:
        if self.pos + n > len(self.data):
            raise ParseError(f"need {n} bytes at offset {self.pos}, only {self.remaining()} remain")
        return self.data[self.pos : self.pos + n]

    def read(
        self,
        n: int,
        field_path: str,
        *,
        decoded_value: Any = "",
        endian: str = "",
        notes: str = "",
    ) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ParseError(f"need {n} bytes for {field_path} at offset {self.pos}, only {self.remaining()} remain")
        start = self.pos
        chunk = self.data[start : start + n]
        decoded = str(decoded_value)
        for i, value in enumerate(chunk):
            self.records.append(
                ByteRecord(
                    offset_start=start + i,
                    offset_end=start + i + 1,
                    raw_hex=f"{value:02x}",
                    bits=f"{value:08b}",
                    field_path=field_path,
                    decoded_value=decoded,
                    endian=endian,
                    notes=notes,
                )
            )
        self.pos += n
        return chunk

    def read_uint(self, n: int, field_path: str, *, signed: bool = False, notes: str = "") -> int:
        preview = self.peek(n)
        value = int.from_bytes(preview, "little", signed=signed)
        self.read(n, field_path, decoded_value=value, endian="little", notes=notes)
        return value


def assert_complete_coverage(records: list[ByteRecord], start: int, end: int) -> dict[str, int | bool]:
    offsets = [record.offset_start for record in records if start <= record.offset_start < end]
    expected = list(range(start, end))
    if offsets != expected:
        missing = sorted(set(expected) - set(offsets))[:10]
        duplicate_count = len(offsets) - len(set(offsets))
        raise ParseError(f"byte coverage failed: missing={missing}, duplicates={duplicate_count}")
    return {
        "start": start,
        "end": end,
        "byte_count": end - start,
        "record_count": len(offsets),
        "complete": True,
    }

