from __future__ import annotations

import io
import struct
from pathlib import Path

from pydump.heap_writer import MAGIC, WELL_KNOWN_TYPE_NAMES, HeapWriter, validate_artifact
from pydump.model import ContentKind, HeapObject


def _well_known() -> dict[str, int]:
    return {name: 0x1000 + index for index, name in enumerate(WELL_KNOWN_TYPE_NAMES)}


def test_writes_pyheap_v1_container_and_footer(tmp_path: Path) -> None:
    output = tmp_path / "sample.pyheap"
    known = _well_known()
    with output.open("w+b") as file:
        writer = HeapWriter(file, with_str_repr=False)
        writer.write_header(known)
        writer.write_threads([])
        writer.begin_objects()
        writer.write_object(
            HeapObject(
                address=0x2000,
                type_address=known["list"],
                type_name="list",
                shallow_size=64,
                content_kind=ContentKind.LIST,
                sequence_content=[0x3000],
                referents={0x3000, 0x4000},
            ),
            known,
        )
        writer.finish({known["list"]: "list"})

    validate_artifact(output)
    raw = output.read_bytes()
    assert struct.unpack_from("!Q", raw)[0] == MAGIC
    assert struct.unpack_from("!Q", raw, len(raw) - 8)[0] == MAGIC


def test_writer_requires_all_well_known_types() -> None:
    writer = HeapWriter(io.BytesIO(), with_str_repr=False)
    known = _well_known()
    del known["dict"]
    try:
        writer.write_header(known)
    except Exception as error:
        assert "dict" in str(error)
    else:
        raise AssertionError("missing well-known type was accepted")


def test_writer_can_measure_an_in_memory_sink_without_fsync() -> None:
    output = io.BytesIO()
    known = _well_known()
    writer = HeapWriter(output, with_str_repr=False, sync=False)
    writer.write_header(known)
    writer.write_threads([])
    writer.begin_objects()
    writer.finish({})

    assert struct.unpack_from("!Q", output.getvalue(), len(output.getvalue()) - 8)[0] == MAGIC


def test_upstream_pyheap_reader_accepts_artifact(tmp_path: Path) -> None:
    """The external contract is a real upstream reader, not our own footer check."""
    try:
        from pyheap_ui.heap_reader import HeapReader
    except ImportError:
        return

    output = tmp_path / "compatible.pyheap"
    known = _well_known()
    with output.open("w+b") as file:
        writer = HeapWriter(file, with_str_repr=True)
        writer.write_header(known)
        writer.write_threads([])
        writer.begin_objects()
        writer.write_object(
            HeapObject(
                address=0x2000,
                type_address=known["object"],
                type_name="object",
                shallow_size=16,
                content_kind=ContentKind.NONE,
                str_repr="<object at 0x2000>",
            ),
            known,
        )
        writer.finish({known["object"]: "object"})

    heap = HeapReader(output.read_bytes()).read()
    assert heap.header.version == 1
    assert heap.objects[0x2000].str_repr == "<object at 0x2000>"
