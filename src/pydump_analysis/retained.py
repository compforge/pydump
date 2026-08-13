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
# Derived from PyHeap's retained-heap implementation and modified to remove UI
# and progress-bar dependencies while preserving its graph semantics.
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydump_analysis.model import Address, Heap


@dataclass(frozen=True, slots=True)
class RetainedHeap:
    objects: dict[Address, int]
    threads: dict[str, int]

    def get_for_object(self, address: Address) -> int | None:
        return self.objects.get(address)

    def get_for_thread(self, thread_name: str) -> int:
        return self.threads[thread_name]

    def dump(self) -> dict[str, object]:
        return {"objects": self.objects, "threads": self.threads}

    @classmethod
    def load(cls, value: dict[str, Any]) -> RetainedHeap:
        return cls(
            objects={int(address): int(size) for address, size in value["objects"].items()},
            threads={str(name): int(size) for name, size in value["threads"].items()},
        )


class InboundReferences:
    def __init__(self, heap: Heap) -> None:
        inbound: dict[Address, set[Address]] = {}
        for address, obj in heap.objects.items():
            inbound.setdefault(address, set())
            for referent in obj.referents:
                inbound.setdefault(referent, set()).add(address)
        self._inbound = inbound

    def __getitem__(self, address: Address) -> set[Address]:
        return self._inbound[address]


class RetainedHeapCalculator:
    """Calculate the bytes made unreachable by deleting each object or thread root."""

    def __init__(self, heap: Heap, inbound: InboundReferences) -> None:
        self._heap = heap
        self._inbound = inbound
        self._subtree_roots: set[Address] = set()
        self._object_retained: dict[Address, int] = {}
        self._thread_retained: dict[str, int] = {}
        self._calculated = False

    def calculate(self) -> RetainedHeap:
        if self._calculated:
            raise ValueError("retained heap is already calculated")
        self._find_strict_subtrees()
        for address in self._heap.objects:
            self._object_retained[address] = self._retained_heap_for_object(address)
        self._calculate_threads()
        self._calculated = True
        return RetainedHeap(self._object_retained, self._thread_retained)

    def _find_strict_subtrees(self) -> None:
        front: set[Address] = set()
        for address, obj in self._heap.objects.items():
            if not obj.referents and len(self._inbound[address]) < 2:
                self._subtree_roots.add(address)
                self._object_retained[address] = obj.size
                front.update(self._inbound[address])

        while True:
            next_front: set[Address] = set()
            for address in front:
                obj = self._heap.objects[address]
                if len(self._inbound[address]) > 1:
                    continue
                if obj.referents - self._subtree_roots:
                    next_front.add(address)
                    continue
                self._subtree_roots.add(address)
                self._object_retained[address] = obj.size + sum(
                    self._object_retained[referent] for referent in obj.referents
                )
                next_front.update(self._inbound[address])
            if next_front == front:
                return
            front = next_front

    def _calculate_threads(self) -> None:
        for removed_thread in self._heap.threads:
            inbound_view: dict[Address, int] = {}
            for address in removed_thread.locals:
                inbound_view[address] = len(self._inbound[address])
                inbound_view[address] += sum(
                    address in thread.locals
                    for thread in self._heap.threads
                    if thread != removed_thread
                )
            self._thread_retained[removed_thread.name] = self._retained_heap(
                inbound_view, list(removed_thread.locals), use_subtrees=False
            )

    def _retained_heap_for_object(self, address: Address) -> int:
        return self._retained_heap({address: 0}, [address], use_subtrees=True)

    def _retained_heap(
        self,
        inbound_view: dict[Address, int],
        front: list[Address],
        *,
        use_subtrees: bool,
    ) -> int:
        retained = 0
        deleted: set[Address] = set()
        while True:
            front.sort(key=inbound_view.__getitem__, reverse=True)
            iteration_retained, deletion_happened = self._delete_unreferenced(
                front, inbound_view, deleted, use_subtrees=use_subtrees
            )
            if not deletion_happened:
                return retained
            retained += iteration_retained

    def _delete_unreferenced(
        self,
        front: list[Address],
        inbound_view: dict[Address, int],
        deleted: set[Address],
        *,
        use_subtrees: bool,
    ) -> tuple[int, bool]:
        retained = 0
        deletion_happened = False
        for index in range(len(front) - 1, -1, -1):
            current = front[index]
            if inbound_view[current] > 0:
                break
            if current in deleted:
                continue
            front.pop(index)
            deleted.add(current)
            deletion_happened = True

            if use_subtrees and current in self._subtree_roots:
                retained += self._object_retained[current]
                continue
            obj = self._heap.objects.get(current)
            if obj is None:
                continue
            retained += obj.size
            new_front = obj.referents - deleted
            self._decrement_inbound(new_front, inbound_view)
            front.extend(new_front)
        return retained, deletion_happened

    def _decrement_inbound(self, addresses: set[Address], inbound_view: dict[Address, int]) -> None:
        for address in addresses:
            if address in inbound_view:
                inbound_view[address] -= 1
            else:
                inbound_view[address] = len(self._inbound[address]) - 1


class RetainedHeapCache:
    VERSION = 1

    def __init__(self, heap_file: Path, cache_dir: Path | None = None) -> None:
        self._heap_file = heap_file
        self._cache_dir = cache_dir

    def load(self) -> RetainedHeap | None:
        try:
            with self.path.open(encoding="utf-8") as file:
                value = json.load(file)
        except FileNotFoundError:
            return None
        if not isinstance(value, dict):
            raise ValueError(f"invalid retained heap cache: {self.path}")
        return RetainedHeap.load(value)

    def store(self, retained: RetainedHeap) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as file:
            json.dump(retained.dump(), file)

    @property
    def path(self) -> Path:
        digest = hashlib.sha1()
        with self._heap_file.open("rb") as file:
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)
        suffix = f".{digest.hexdigest()}.{self.VERSION}.retained_heap"
        if self._cache_dir is None:
            return Path(f"{self._heap_file}{suffix}")
        return self._cache_dir / f"{self._heap_file.name}{suffix}"


def retained_heap_with_cache(heap_file: Path, heap: Heap) -> RetainedHeap:
    cache_dir_value = os.getenv("PYHEAP_CACHE_DIR")
    cache = RetainedHeapCache(
        heap_file,
        Path(cache_dir_value) if cache_dir_value is not None else None,
    )
    retained = cache.load()
    if retained is not None:
        return retained
    retained = RetainedHeapCalculator(heap, InboundReferences(heap)).calculate()
    cache.store(retained)
    return retained


def objects_sorted_by_retained_heap(
    heap: Heap, retained: RetainedHeap
) -> list[tuple[Address, int]]:
    result = [(address, retained.get_for_object(address) or 0) for address in heap.objects]
    result.sort(key=lambda item: item[1], reverse=True)
    return result


def total_heap_size(heap: Heap) -> int:
    return sum(obj.size for obj in heap.objects.values())
