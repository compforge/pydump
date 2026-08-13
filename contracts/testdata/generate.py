from __future__ import annotations

import json
from pathlib import Path

from pydump.heap_writer import WELL_KNOWN_TYPE_NAMES, HeapWriter
from pydump.model import ContentKind, HeapObject, HeapThread, ThreadFrame
from pydump_analyzer.reader import load_heap
from pydump_analyzer.report import build_heap_analysis
from pydump_analyzer.retained import InboundReferences, RetainedHeapCalculator

ROOT = Path(__file__).parent
HEAP = ROOT / "heap-v1.pyheap"
EXPECTED = ROOT / "analysis-v1.expected.json"


def main() -> None:
    known = {name: 0x1000 + index for index, name in enumerate(WELL_KNOWN_TYPE_NAMES)}
    with HEAP.open("w+b") as file:
        writer = HeapWriter(file, with_str_repr=True)
        writer.write_header(known, created_at="2026-08-13T12:00:00+00:00")
        writer.write_threads(
            [
                HeapThread(
                    name="MainThread",
                    is_alive=True,
                    is_daemon=False,
                    frames=(
                        ThreadFrame(
                            filename="/app/main.py",
                            lineno=42,
                            function="run",
                            locals=(("payload", 0x2000),),
                        ),
                    ),
                )
            ]
        )
        writer.begin_objects()
        writer.write_object(
            HeapObject(
                address=0x2000,
                type_address=known["list"],
                type_name="list",
                shallow_size=64,
                content_kind=ContentKind.LIST,
                sequence_content=[0x3000, 0x4000],
                referents={0x3000, 0x4000},
            ),
            known,
        )
        writer.write_object(
            _object(0x3000, known["object"], 16, "<object at 0x3000>"),
            known,
        )
        writer.write_object(
            _object(0x4000, known["object"], 32, "<object at 0x4000>", {0x3000}),
            known,
        )
        writer.write_object(
            _object(0x5000, known["object"], 8, "<object at 0x5000>", {0x3000}),
            known,
        )
        writer.write_object(
            HeapObject(
                address=0x6000,
                type_address=known["set"],
                type_name="set",
                shallow_size=48,
                content_kind=ContentKind.SET,
                sequence_content=[0x4000, 0x3000],
                referents={0x3000, 0x4000},
            ),
            known,
        )
        writer.write_object(
            HeapObject(
                address=0x7000,
                type_address=known["tuple"],
                type_name="tuple",
                shallow_size=40,
                content_kind=ContentKind.TUPLE,
                sequence_content=[0x3000],
                referents={0x3000},
            ),
            known,
        )
        writer.write_object(
            HeapObject(
                address=0x8000,
                type_address=known["dict"],
                type_name="dict",
                shallow_size=80,
                content_kind=ContentKind.DICT,
                dict_content=[(0x3000, 0x4000)],
                referents={0x3000, 0x4000},
            ),
            known,
        )
        writer.finish(
            {
                known["dict"]: "dict",
                known["list"]: "list",
                known["set"]: "set",
                known["tuple"]: "tuple",
                known["object"]: "object",
            }
        )

    heap = load_heap(HEAP)
    try:
        retained = RetainedHeapCalculator(heap, InboundReferences(heap)).calculate()
        report = build_heap_analysis(
            heap_file=HEAP,
            heap=heap,
            retained=retained,
            top_n=8,
        )
    finally:
        heap.close()
    EXPECTED.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _object(
    address: int,
    type_address: int,
    size: int,
    representation: str,
    referents: set[int] | None = None,
) -> HeapObject:
    return HeapObject(
        address=address,
        type_address=type_address,
        type_name="object",
        shallow_size=size,
        content_kind=ContentKind.NONE,
        referents=referents or set(),
        str_repr=representation,
    )


if __name__ == "__main__":
    main()
