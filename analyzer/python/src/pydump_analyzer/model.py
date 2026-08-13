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
# Derived from PyHeap's heap model and modified for Pydump's headless analyzer.
from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass, field

Address = int
ObjectContent = dict[Address, Address] | list[Address] | set[Address] | tuple[Address, ...] | None


@dataclass(frozen=True, slots=True)
class HeapFlags:
    with_str_repr: bool


@dataclass(frozen=True, slots=True)
class HeapHeader:
    version: int
    created_at: str
    flags: HeapFlags
    well_known_types: dict[str, Address]


@dataclass(frozen=True, slots=True)
class HeapThreadFrame:
    file_name: str
    line_number: int
    function_name: str
    locals: dict[str, Address]


@dataclass(frozen=True, slots=True)
class HeapThread:
    name: str
    is_alive: bool
    is_daemon: bool
    stack_trace: list[HeapThreadFrame]

    @property
    def locals(self) -> set[Address]:
        result: set[Address] = set()
        for frame in self.stack_trace:
            result.update(frame.locals.values())
        return result


@dataclass(slots=True)
class HeapObject:
    address: Address
    type_address: Address
    size: int
    referents: set[Address]
    content: ObjectContent = None
    string_representation_offset: int | None = None


@dataclass(slots=True)
class Heap:
    header: HeapHeader
    threads: list[HeapThread]
    objects: dict[Address, HeapObject]
    types: dict[Address, str]
    _source: bytes | mmap.mmap | None = field(default=None, repr=False, compare=False)

    def close(self) -> None:
        if isinstance(self._source, mmap.mmap):
            self._source.close()
        self._source = None

    def string_representation(self, obj: HeapObject) -> str | None:
        if not self.header.flags.with_str_repr:
            return None
        return self._string_representation(obj.address, set())

    def _string_representation(self, address: Address, seen: set[Address]) -> str:
        obj = self.objects.get(address)
        if obj is None:
            return "(unknown)"

        containers = {
            self.header.well_known_types["dict"],
            self.header.well_known_types["list"],
            self.header.well_known_types["set"],
            self.header.well_known_types["tuple"],
        }
        if obj.type_address not in containers:
            return self._read_string_representation(obj)

        left, right = self._container_brackets(obj.type_address)
        if address in seen:
            return f"{left}...{right}"
        nested_seen = seen | {address}

        if isinstance(obj.content, dict):
            inner = ", ".join(
                f"{self._string_representation(key, nested_seen)}: "
                f"{self._string_representation(value, nested_seen)}"
                for key, value in obj.content.items()
            )
        elif isinstance(obj.content, set):
            inner = ", ".join(
                self._string_representation(item, nested_seen) for item in sorted(obj.content)
            )
        elif obj.content is not None:
            inner = ", ".join(
                self._string_representation(item, nested_seen) for item in obj.content
            )
        else:
            inner = ""
        return f"{left}{inner}{right}"

    def _read_string_representation(self, obj: HeapObject) -> str:
        if self._source is None or obj.string_representation_offset is None:
            return ""
        offset = obj.string_representation_offset
        length = struct.unpack_from("!H", self._source, offset)[0]
        start = offset + 2
        return bytes(self._source[start : start + length]).decode("utf-8", "backslashreplace")

    def _container_brackets(self, type_address: Address) -> tuple[str, str]:
        known = self.header.well_known_types
        if type_address == known["list"]:
            return "[", "]"
        if type_address == known["tuple"]:
            return "(", ")"
        return "{", "}"
