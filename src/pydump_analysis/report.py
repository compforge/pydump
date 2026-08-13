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
# Derived from PyHeap's stable headless analysis output and maintained here as
# Pydump's consumer-neutral JSON contract.
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from pydump_analysis.model import Address, Heap, HeapObject, HeapThread
from pydump_analysis.retained import (
    RetainedHeap,
    objects_sorted_by_retained_heap,
    total_heap_size,
)

ANALYSIS_SCHEMA = "pyheap.analysis/v1"


def _address(value: Address) -> str:
    return f"0x{value:x}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _type_summaries(heap: Heap) -> list[dict[str, Any]]:
    counts: dict[Address, int] = {}
    shallow_sizes: dict[Address, int] = {}
    for obj in heap.objects.values():
        counts[obj.type_address] = counts.get(obj.type_address, 0) + 1
        shallow_sizes[obj.type_address] = shallow_sizes.get(obj.type_address, 0) + obj.size
    addresses = sorted(
        counts,
        key=lambda address: (
            -shallow_sizes[address],
            -counts[address],
            heap.types[address],
            address,
        ),
    )
    return [
        {
            "type_address": _address(address),
            "type_name": heap.types[address],
            "object_count": counts[address],
            "shallow_size_bytes": shallow_sizes[address],
        }
        for address in addresses
    ]


def _object_type_name(heap: Heap, address: Address) -> str | None:
    obj = heap.objects.get(address)
    return None if obj is None else heap.types.get(obj.type_address)


def _thread_summary(
    heap: Heap, thread: HeapThread, retained: RetainedHeap | None
) -> dict[str, Any]:
    frames = []
    for frame in thread.stack_trace:
        local_variables = [
            {
                "name": name,
                "object_address": _address(address),
                "type_name": _object_type_name(heap, address),
            }
            for name, address in sorted(frame.locals.items())
        ]
        frames.append(
            {
                "file_name": frame.file_name,
                "line_number": frame.line_number,
                "function_name": frame.function_name,
                "local_variables": local_variables,
            }
        )
    return {
        "name": thread.name,
        "is_alive": thread.is_alive,
        "is_daemon": thread.is_daemon,
        "retained_size_bytes": (
            retained.get_for_thread(thread.name) if retained is not None else None
        ),
        "frames": frames,
    }


def _object_string(heap: Heap, obj: HeapObject) -> str | None:
    return heap.string_representation(obj) if heap.header.flags.with_str_repr else None


def _retained_summary(heap: Heap, retained: RetainedHeap | None, top_n: int) -> dict[str, Any]:
    if retained is None:
        return {"status": "not_computed", "top_n": top_n, "top_objects": []}
    top_objects = []
    for address, retained_size in objects_sorted_by_retained_heap(heap, retained)[:top_n]:
        obj = heap.objects[address]
        top_objects.append(
            {
                "object_address": _address(address),
                "type_name": heap.types[obj.type_address],
                "shallow_size_bytes": obj.size,
                "retained_size_bytes": retained_size,
                "string_representation": _object_string(heap, obj),
            }
        )
    return {"status": "complete", "top_n": top_n, "top_objects": top_objects}


def build_heap_analysis(
    *,
    heap_file: Path,
    heap: Heap,
    retained: RetainedHeap | None = None,
    top_n: int = 100,
) -> dict[str, Any]:
    """Build the stable, consumer-neutral JSON representation of a heap analysis."""
    return {
        "schema": ANALYSIS_SCHEMA,
        "source": {
            "sha256": _sha256(heap_file),
            "size_bytes": heap_file.stat().st_size,
            "heap_format_version": heap.header.version,
            "created_at": heap.header.created_at,
            "with_string_representations": heap.header.flags.with_str_repr,
        },
        "heap": {
            "object_count": len(heap.objects),
            "type_count": len(heap.types),
            "thread_count": len(heap.threads),
            "referent_count": sum(len(obj.referents) for obj in heap.objects.values()),
            "shallow_size_bytes": total_heap_size(heap),
        },
        "types": _type_summaries(heap),
        "threads": [_thread_summary(heap, thread, retained) for thread in heap.threads],
        "retained_heap": _retained_summary(heap, retained, top_n),
    }
