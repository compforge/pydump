from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydump.heap_writer import WELL_KNOWN_TYPE_NAMES, HeapWriter
from pydump.model import ContentKind
from pydump.model import HeapObject as CapturedObject
from pydump_analyzer.cli import build_parser, main
from pydump_analyzer.model import (
    Heap,
    HeapFlags,
    HeapHeader,
    HeapObject,
    HeapThread,
    HeapThreadFrame,
)
from pydump_analyzer.reader import load_heap
from pydump_analyzer.report import ANALYSIS_SCHEMA, build_heap_analysis
from pydump_analyzer.retained import InboundReferences, RetainedHeapCalculator


def _well_known_types() -> dict[str, int]:
    return {name: 0x1000 + index for index, name in enumerate(WELL_KNOWN_TYPE_NAMES)}


def _write_heap(path: Path, *, with_str_repr: bool = True) -> None:
    known = _well_known_types()
    with path.open("w+b") as file:
        writer = HeapWriter(file, with_str_repr=with_str_repr)
        writer.write_header(known)
        writer.write_threads([])
        writer.begin_objects()
        writer.write_object(
            CapturedObject(
                address=0x2000,
                type_address=known["list"],
                type_name="list",
                shallow_size=64,
                content_kind=ContentKind.LIST,
                sequence_content=[0x3000],
                referents={0x3000},
            ),
            known,
        )
        writer.write_object(
            CapturedObject(
                address=0x3000,
                type_address=known["object"],
                type_name="object",
                shallow_size=16,
                content_kind=ContentKind.NONE,
                str_repr="<object at 0x3000>",
            ),
            known,
        )
        writer.finish({known["list"]: "list", known["object"]: "object"})


def _analysis_heap() -> Heap:
    return Heap(
        header=HeapHeader(
            version=1,
            created_at="2026-08-13T12:00:00+00:00",
            flags=HeapFlags(with_str_repr=False),
            well_known_types=_well_known_types(),
        ),
        threads=[
            HeapThread(
                name="MainThread",
                is_alive=True,
                is_daemon=False,
                stack_trace=[
                    HeapThreadFrame(
                        file_name="/app/main.py",
                        line_number=42,
                        function_name="run",
                        locals={"payload": 0x101, "missing": 0x999},
                    )
                ],
            )
        ],
        objects={
            0x100: HeapObject(0x100, 0x10, 80, {0x101}),
            0x101: HeapObject(0x101, 0x20, 100, set()),
            0x102: HeapObject(0x102, 0x10, 40, set()),
        },
        types={0x10: "dict", 0x20: "str"},
    )


def test_reader_loads_pydump_artifact_and_lazy_string_representations(tmp_path: Path) -> None:
    heap_file = tmp_path / "heap.pyheap"
    _write_heap(heap_file)

    heap = load_heap(heap_file)
    try:
        assert heap.header.version == 1
        assert heap.objects[0x2000].referents == {0x3000}
        assert heap.string_representation(heap.objects[0x3000]) == "<object at 0x3000>"
        assert heap.string_representation(heap.objects[0x2000]) == "[<object at 0x3000>]"
    finally:
        heap.close()


def test_string_representation_orders_set_content_by_address() -> None:
    known = _well_known_types()
    heap = Heap(
        header=HeapHeader(1, "", HeapFlags(True), known),
        threads=[],
        objects={
            1: HeapObject(1, known["set"], 16, {2, 3}, {3, 2}),
            2: HeapObject(2, known["object"], 16, set(), string_representation_offset=0),
            3: HeapObject(3, known["object"], 16, set(), string_representation_offset=3),
        },
        types={known["set"]: "set", known["object"]: "object"},
        _source=b"\x00\x01a\x00\x01b",
    )

    assert heap.string_representation(heap.objects[1]) == "{a, b}"


def test_summary_matches_stable_pyheap_analysis_contract(tmp_path: Path) -> None:
    heap_file = tmp_path / "heap.pyheap"
    heap_file.write_bytes(b"heap contents")

    result = build_heap_analysis(heap_file=heap_file, heap=_analysis_heap(), top_n=5)

    assert result["schema"] == "pydump.analysis/v1"
    assert result["source"] == {
        "sha256": hashlib.sha256(b"heap contents").hexdigest(),
        "size_bytes": 13,
        "heap_format_version": 1,
        "created_at": "2026-08-13T12:00:00+00:00",
        "with_string_representations": False,
    }
    assert result["heap"] == {
        "object_count": 3,
        "type_count": 2,
        "thread_count": 1,
        "referent_count": 1,
        "shallow_size_bytes": 220,
    }
    assert result["types"] == [
        {
            "type_address": "0x10",
            "type_name": "dict",
            "object_count": 2,
            "shallow_size_bytes": 120,
        },
        {
            "type_address": "0x20",
            "type_name": "str",
            "object_count": 1,
            "shallow_size_bytes": 100,
        },
    ]
    assert result["threads"][0]["frames"][0]["local_variables"] == [
        {"name": "missing", "object_address": "0x999", "type_name": None},
        {"name": "payload", "object_address": "0x101", "type_name": "str"},
    ]
    assert result["retained_heap"] == {
        "status": "not_computed",
        "top_n": 5,
        "top_objects": [],
    }


def test_retained_heap_preserves_shared_referents() -> None:
    heap = Heap(
        header=_analysis_heap().header,
        threads=[],
        objects={
            1: HeapObject(1, 10, 10, {2}),
            2: HeapObject(2, 10, 20, set()),
            3: HeapObject(3, 10, 30, {2}),
        },
        types={10: "object"},
    )

    retained = RetainedHeapCalculator(heap, InboundReferences(heap)).calculate()

    assert retained.objects == {1: 10, 2: 20, 3: 30}


def test_retained_heap_handles_chains_and_cycles() -> None:
    chain = Heap(
        header=_analysis_heap().header,
        threads=[],
        objects={
            1: HeapObject(1, 10, 10, {2}),
            2: HeapObject(2, 10, 20, {3}),
            3: HeapObject(3, 10, 30, set()),
        },
        types={10: "object"},
    )
    cycle = Heap(
        header=_analysis_heap().header,
        threads=[],
        objects={
            1: HeapObject(1, 10, 10, {2}),
            2: HeapObject(2, 10, 20, {1}),
        },
        types={10: "object"},
    )

    chain_retained = RetainedHeapCalculator(chain, InboundReferences(chain)).calculate()
    cycle_retained = RetainedHeapCalculator(cycle, InboundReferences(cycle)).calculate()

    assert chain_retained.objects == {1: 60, 2: 50, 3: 30}
    assert cycle_retained.objects == {1: 30, 2: 30}


def test_retained_heap_treats_other_threads_as_roots() -> None:
    frame = HeapThreadFrame("/app/main.py", 1, "run", {"root": 1})
    heap = Heap(
        header=_analysis_heap().header,
        threads=[
            HeapThread("one", True, False, [frame]),
            HeapThread("two", True, False, [frame]),
        ],
        objects={
            1: HeapObject(1, 10, 10, {2}),
            2: HeapObject(2, 10, 20, set()),
        },
        types={10: "object"},
    )

    retained = RetainedHeapCalculator(heap, InboundReferences(heap)).calculate()

    assert retained.threads == {"one": 0, "two": 0}


def test_cli_summary_writes_only_json(tmp_path: Path, capsys) -> None:
    heap_file = tmp_path / "heap.pyheap"
    _write_heap(heap_file, with_str_repr=False)

    assert main(["summary", "--file", str(heap_file)]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == ANALYSIS_SCHEMA
    assert result["heap"]["object_count"] == 2


def test_cli_rejects_negative_top_n() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["retained-heap", "--file", "heap.pyheap", "--top-n", "-1"])


def test_shared_contract_fixture_matches_python_reference() -> None:
    root = Path(__file__).parents[3]
    heap_file = root / "contracts/testdata/heap-v1.pyheap"
    expected = json.loads(
        (root / "contracts/testdata/analysis-v1.expected.json").read_text(encoding="utf-8")
    )
    heap = load_heap(heap_file)
    try:
        retained = RetainedHeapCalculator(heap, InboundReferences(heap)).calculate()
        actual = build_heap_analysis(
            heap_file=heap_file,
            heap=heap,
            retained=retained,
            top_n=8,
        )
    finally:
        heap.close()

    assert actual == expected
