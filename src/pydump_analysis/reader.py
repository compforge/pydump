# Copyright 2022 Ivan Yurchenko
# Copyright 2026 CompForge
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Derived from PyHeap's HeapReader and rewritten as an explicit, dependency-free
# PyHeap v1 reader for Pydump's headless analyzer.
from __future__ import annotations

import mmap
import struct
from pathlib import Path
from typing import cast

from pydump_analysis.model import (
    Address,
    Heap,
    HeapFlags,
    HeapHeader,
    HeapObject,
    HeapThread,
    HeapThreadFrame,
    ObjectContent,
)

MAGIC = 123_000_321
FORMAT_VERSION = 1
FLAG_WITH_STR_REPR = 1

_BOOL = struct.Struct("!?")
_SIGNED_SHORT = struct.Struct("!h")
_UNSIGNED_SHORT = struct.Struct("!H")
_UNSIGNED_INT = struct.Struct("!I")
_UNSIGNED_LONG = struct.Struct("!Q")


class HeapFormatError(ValueError):
    """Raised when a heap artifact cannot be decoded as PyHeap v1."""


class HeapReader:
    def __init__(self, source: bytes | mmap.mmap) -> None:
        self._source = source
        self._offset = 0

    def read(self) -> Heap:
        if self._read_u64() != MAGIC:
            raise HeapFormatError("invalid PyHeap magic value")

        version = self._read_u32()
        if version != FORMAT_VERSION:
            raise HeapFormatError(f"unsupported PyHeap format version: {version}")
        created_at = self._read_long_string()
        flags = HeapFlags(with_str_repr=bool(self._read_u64() & FLAG_WITH_STR_REPR))
        well_known_types = self._read_string_address_map()
        header = HeapHeader(version, created_at, flags, well_known_types)

        threads = self._read_threads()
        frequent_attributes = self._read_string_list()
        common_types = self._read_common_types(frequent_attributes)
        objects = self._read_objects(header, frequent_attributes, common_types)
        types = self._read_address_string_map()

        if self._read_u64() != MAGIC:
            raise HeapFormatError("invalid PyHeap footer magic value")
        if self._offset != len(self._source):
            raise HeapFormatError("unexpected data after PyHeap footer")
        return Heap(header, threads, objects, types, self._source)

    def _read_threads(self) -> list[HeapThread]:
        threads = []
        for _ in range(self._read_u32()):
            name = self._read_long_string()
            is_alive = self._read_bool()
            is_daemon = self._read_bool()
            frames = []
            for _ in range(self._read_u32()):
                file_name = self._read_long_string()
                line_number = self._read_u32()
                function_name = self._read_long_string()
                local_variables = {
                    self._read_long_string(): self._read_u64() for _ in range(self._read_u32())
                }
                frames.append(
                    HeapThreadFrame(file_name, line_number, function_name, local_variables)
                )
            threads.append(HeapThread(name, is_alive, is_daemon, frames))
        return threads

    def _read_common_types(self, frequent_attributes: list[str]) -> set[Address]:
        common_types = set()
        for _ in range(self._read_u32()):
            common_types.add(self._read_u64())
            for _ in range(self._read_u32()):
                self._read_attribute_name(frequent_attributes)
                self._read_u64()
        return common_types

    def _read_objects(
        self,
        header: HeapHeader,
        frequent_attributes: list[str],
        common_types: set[Address],
    ) -> dict[Address, HeapObject]:
        result = {}
        known = header.well_known_types
        container_types = {known["dict"], known["list"], known["set"], known["tuple"]}

        for _ in range(self._read_u32()):
            address = self._read_u64()
            type_address = self._read_u64()
            size = self._read_u32()
            content, content_referents = self._read_content(type_address, known)
            referents = self._read_address_set()
            referents.update(content_referents)

            if type_address not in common_types:
                for _ in range(self._read_u32()):
                    self._read_attribute_name(frequent_attributes)
                    self._read_u64()

            string_offset = None
            if header.flags.with_str_repr and type_address not in container_types:
                string_offset = self._offset
                self._skip_long_string()
            result[address] = HeapObject(
                address,
                type_address,
                size,
                referents,
                content,
                string_offset,
            )
        return result

    def _read_content(
        self, type_address: Address, known: dict[str, Address]
    ) -> tuple[ObjectContent, set[Address]]:
        referents: set[Address] = set()
        if type_address == known["dict"]:
            content = {}
            for _ in range(self._read_u32()):
                key, value = self._read_u64(), self._read_u64()
                content[key] = value
                referents.update((key, value))
            return content, referents
        if type_address in {known["list"], known["tuple"], known["set"]}:
            values = [self._read_u64() for _ in range(self._read_u32())]
            referents.update(values)
            if type_address == known["tuple"]:
                return tuple(values), referents
            if type_address == known["set"]:
                return set(values), referents
            return values, referents
        return None, referents

    def _read_address_string_map(self) -> dict[Address, str]:
        return {self._read_u64(): self._read_long_string() for _ in range(self._read_u32())}

    def _read_string_address_map(self) -> dict[str, Address]:
        return {self._read_long_string(): self._read_u64() for _ in range(self._read_u32())}

    def _read_string_list(self) -> list[str]:
        return [self._read_long_string() for _ in range(self._read_u32())]

    def _read_address_set(self) -> set[Address]:
        return {self._read_u64() for _ in range(self._read_u32())}

    def _read_attribute_name(self, frequent_attributes: list[str]) -> str:
        length_or_index = self._read_i16()
        if length_or_index >= 0:
            return self._read_string(length_or_index)
        index = -(length_or_index + 1)
        try:
            return frequent_attributes[index]
        except IndexError as error:
            raise HeapFormatError(f"invalid frequent attribute index: {index}") from error

    def _read_long_string(self) -> str:
        return self._read_string(self._read_u16())

    def _skip_long_string(self) -> None:
        self._take(self._read_u16())

    def _read_string(self, length: int) -> str:
        return bytes(self._take(length)).decode("utf-8", "backslashreplace")

    def _read_bool(self) -> bool:
        return bool(self._unpack(_BOOL))

    def _read_i16(self) -> int:
        return int(self._unpack(_SIGNED_SHORT))

    def _read_u16(self) -> int:
        return int(self._unpack(_UNSIGNED_SHORT))

    def _read_u32(self) -> int:
        return int(self._unpack(_UNSIGNED_INT))

    def _read_u64(self) -> int:
        return int(self._unpack(_UNSIGNED_LONG))

    def _unpack(self, value_struct: struct.Struct) -> int | bool:
        try:
            value = value_struct.unpack_from(self._source, self._offset)[0]
        except struct.error as error:
            raise HeapFormatError(f"truncated PyHeap data at offset {self._offset}") from error
        self._offset += value_struct.size
        return cast(int | bool, value)

    def _take(self, length: int) -> bytes | mmap.mmap:
        end = self._offset + length
        if end > len(self._source):
            raise HeapFormatError(f"truncated PyHeap data at offset {self._offset}")
        value = self._source[self._offset : end]
        self._offset = end
        return value


def load_heap(path: Path) -> Heap:
    file = path.open("rb")
    try:
        source = mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ)
    finally:
        file.close()
    try:
        return HeapReader(source).read()
    except BaseException:
        source.close()
        raise
