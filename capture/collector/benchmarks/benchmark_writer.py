from __future__ import annotations

import argparse
import io
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from pydump.heap_writer import WELL_KNOWN_TYPE_NAMES, HeapWriter
from pydump.model import ContentKind, HeapObject


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Measure PyHeap artifact encoding and sink cost.")
    result.add_argument("--objects", type=int, default=250_000)
    result.add_argument("--referents", type=int, default=4)
    return result


def write_heap(
    file: BinaryIO,
    *,
    objects: int,
    referents: int,
    sync: bool,
) -> tuple[float, int]:
    known = {name: 0x1000 + index for index, name in enumerate(WELL_KNOWN_TYPE_NAMES)}
    writer = HeapWriter(file, with_str_repr=False, sync=sync)
    started = time.perf_counter()
    writer.write_header(known)
    writer.write_threads([])
    writer.begin_objects()
    for index in range(objects):
        address = 0x100_000 + index * 16
        edges = {address + (offset + 1) * 16 for offset in range(referents)}
        writer.write_object(
            HeapObject(
                address=address,
                type_address=known["object"],
                type_name="object",
                shallow_size=16,
                content_kind=ContentKind.NONE,
                referents=edges,
            ),
            known,
        )
    writer.finish({known["object"]: "object"})
    elapsed = time.perf_counter() - started
    return elapsed, file.tell()


def benchmark(
    name: str,
    factory: Callable[[], BinaryIO],
    *,
    objects: int,
    referents: int,
    sync: bool,
) -> None:
    file = factory()
    try:
        elapsed, size = write_heap(
            file,
            objects=objects,
            referents=referents,
            sync=sync,
        )
    finally:
        file.close()
    print(
        f"{name:12s}: {objects / elapsed:10,.0f} objects/s, "
        f"{size / elapsed / (1 << 20):7.1f} MiB/s, {elapsed:.3f}s"
    )


def main() -> None:
    arguments = parser().parse_args()
    with tempfile.TemporaryDirectory(prefix="pydump-writer-") as directory:
        output = Path(directory) / "heap.pyheap"
        benchmark(
            "memory",
            io.BytesIO,
            objects=arguments.objects,
            referents=arguments.referents,
            sync=False,
        )
        benchmark(
            "file",
            lambda: output.open("w+b"),
            objects=arguments.objects,
            referents=arguments.referents,
            sync=False,
        )
        benchmark(
            "file+fsync",
            lambda: output.open("w+b"),
            objects=arguments.objects,
            referents=arguments.referents,
            sync=True,
        )


if __name__ == "__main__":
    main()
