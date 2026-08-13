from __future__ import annotations

import os
import struct
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Final

from pydump.errors import PydumpError
from pydump.model import ContentKind, HeapObject, HeapThread

MAGIC: Final = 123_000_321
FORMAT_VERSION: Final = 1
FLAG_WITH_STR_REPR: Final = 1
MAX_STRING_SIZE: Final = 0xFFFF
MAX_UINT32: Final = 0xFFFF_FFFF

WELL_KNOWN_TYPE_NAMES: Final = (
    "list",
    "tuple",
    "dict",
    "set",
    "str",
    "bytes",
    "bytearray",
    "int",
    "bool",
    "float",
    "object",
    "type",
    "NoneType",
)

_BOOL = struct.Struct("!?")
_SIGNED_SHORT = struct.Struct("!h")
_UNSIGNED_INT = struct.Struct("!I")
_UNSIGNED_LONG = struct.Struct("!Q")


class HeapWriter:
    """Streaming writer for the public PyHeap v1 artifact format."""

    def __init__(self, file: BinaryIO, *, with_str_repr: bool, sync: bool = True) -> None:
        self._file = file
        self._with_str_repr = with_str_repr
        self._sync = sync
        self._object_count_offset: int | None = None
        self._object_count = 0

    def write_header(
        self, well_known_types: dict[str, int], *, created_at: str | None = None
    ) -> None:
        missing = set(WELL_KNOWN_TYPE_NAMES) - well_known_types.keys()
        if missing:
            raise PydumpError(f"agent omitted well-known types: {', '.join(sorted(missing))}")

        self._write_u64(MAGIC)
        self._write_u32(FORMAT_VERSION)
        self._write_long_string(created_at or datetime.now().astimezone().isoformat())
        self._write_u64(FLAG_WITH_STR_REPR if self._with_str_repr else 0)
        self._write_u32(len(WELL_KNOWN_TYPE_NAMES))
        for name in WELL_KNOWN_TYPE_NAMES:
            self._write_long_string(name)
            self._write_u64(well_known_types[name])

    def write_threads(self, threads: list[HeapThread]) -> None:
        self._write_u32(len(threads))
        for thread in threads:
            self._write_long_string(thread.name)
            self._file.write(_BOOL.pack(thread.is_alive))
            self._file.write(_BOOL.pack(thread.is_daemon))
            self._write_u32(len(thread.frames))
            for frame in thread.frames:
                self._write_long_string(frame.filename)
                self._write_u32(frame.lineno)
                self._write_long_string(frame.function)
                self._write_u32(len(frame.locals))
                for name, address in frame.locals:
                    self._write_long_string(name)
                    self._write_u64(address)

    def begin_objects(self) -> None:
        # Empty compression tables retain the v1 contract without requiring a target-side pre-scan.
        self._write_u32(0)  # frequent attributes
        self._write_u32(0)  # common types
        self._object_count_offset = self._file.tell()
        self._write_u32(0)

    def write_object(self, obj: HeapObject, well_known_types: dict[str, int]) -> None:
        if self._object_count_offset is None:
            raise PydumpError("object section was not started")
        self._write_u64(obj.address)
        self._write_u64(obj.type_address)
        self._write_u32(min(max(obj.shallow_size, 0), MAX_UINT32))

        container_addresses: set[int] = set()
        if obj.content_kind is ContentKind.DICT:
            entries = _dict_content(obj)
            self._write_u32(len(entries))
            for key, value in entries:
                self._write_u64(key)
                self._write_u64(value)
                container_addresses.update((key, value))
        elif obj.content_kind in (ContentKind.LIST, ContentKind.SET, ContentKind.TUPLE):
            content = _sequence_content(obj)
            self._write_u32(len(content))
            for address in content:
                self._write_u64(address)
            container_addresses.update(content)

        remaining_referents = obj.referents - container_addresses
        self._write_u32(len(remaining_referents))
        for address in sorted(remaining_referents):
            self._write_u64(address)

        self._write_u32(len(obj.attributes))
        for attribute in obj.attributes:
            self._write_short_string(attribute.name)
            self._write_u64(attribute.address)

        is_container = obj.type_address in {
            well_known_types["dict"],
            well_known_types["list"],
            well_known_types["set"],
            well_known_types["tuple"],
        }
        if self._with_str_repr and not is_container:
            self._write_long_string(obj.str_repr)
        self._object_count += 1

    def finish(self, types: dict[int, str]) -> None:
        if self._object_count_offset is None:
            raise PydumpError("object section was not started")
        end_offset = self._file.tell()
        self._file.seek(self._object_count_offset)
        self._write_u32(self._object_count)
        self._file.seek(end_offset)

        self._write_u32(len(types))
        for address, name in sorted(types.items()):
            self._write_u64(address)
            self._write_long_string(name)
        self._write_u64(MAGIC)
        self._file.flush()
        if self._sync:
            os.fsync(self._file.fileno())

    def _write_short_string(self, value: str) -> None:
        encoded = _encode_string(value)
        if len(encoded) > 0x7FFF:
            encoded = encoded[:0x7FFF]
        self._file.write(_SIGNED_SHORT.pack(len(encoded)))
        self._file.write(encoded)

    def _write_long_string(self, value: str) -> None:
        encoded = _encode_string(value)
        if len(encoded) > MAX_STRING_SIZE:
            encoded = encoded[:MAX_STRING_SIZE]
        self._file.write(struct.pack("!H", len(encoded)))
        self._file.write(encoded)

    def _write_u32(self, value: int) -> None:
        if not 0 <= value <= MAX_UINT32:
            raise PydumpError(f"value {value} does not fit in a v1 unsigned int")
        self._file.write(_UNSIGNED_INT.pack(value))

    def _write_u64(self, value: int) -> None:
        self._file.write(_UNSIGNED_LONG.pack(value))


def validate_artifact(path: Path) -> None:
    if path.stat().st_size < _UNSIGNED_LONG.size * 2:
        raise PydumpError(f"artifact {path} is too short")
    with path.open("rb") as file:
        start = _UNSIGNED_LONG.unpack(file.read(_UNSIGNED_LONG.size))[0]
        file.seek(-_UNSIGNED_LONG.size, os.SEEK_END)
        end = _UNSIGNED_LONG.unpack(file.read(_UNSIGNED_LONG.size))[0]
    if start != MAGIC or end != MAGIC:
        raise PydumpError(f"artifact {path} has an invalid magic value")


def _encode_string(value: str) -> bytes:
    return value.encode("utf-8", "backslashreplace")


def _dict_content(obj: HeapObject) -> list[tuple[int, int]]:
    return obj.dict_content


def _sequence_content(obj: HeapObject) -> list[int]:
    return obj.sequence_content
