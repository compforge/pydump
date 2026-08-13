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
# The command surface follows PyHeap's headless analyzer; implementation and
# packaging are independent from the legacy Flask UI.
from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from pydump_analysis.model import Heap
from pydump_analysis.reader import load_heap
from pydump_analysis.report import build_heap_analysis
from pydump_analysis.retained import (
    RetainedHeap,
    objects_sorted_by_retained_heap,
    retained_heap_with_cache,
    total_heap_size,
)


def _print_json(value: object) -> None:
    json.dump(value, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _summary(heap_file: Path) -> None:
    heap = load_heap(heap_file)
    try:
        _print_json(build_heap_analysis(heap_file=heap_file, heap=heap))
    finally:
        heap.close()


def _retained_heap(heap_file: Path, *, output_format: str, top_n: int) -> None:
    heap = load_heap(heap_file)
    try:
        retained = retained_heap_with_cache(heap_file, heap)
        if output_format == "json":
            _print_json(
                build_heap_analysis(
                    heap_file=heap_file,
                    heap=heap,
                    retained=retained,
                    top_n=top_n,
                )
            )
        else:
            _print_retained_text(heap, retained, top_n)
    finally:
        heap.close()


def _print_retained_text(heap: Heap, retained: RetainedHeap, top_n: int) -> None:
    terminal_columns = shutil.get_terminal_size().columns
    prefix = "{:<15} | {:<15} | {:>18} | "
    representation_width = max(0, terminal_columns - len(prefix.format("", "", "")))
    row_format = prefix + "{:<" + str(representation_width) + "}"
    print("Retained heap for objects:")
    print(
        row_format.format("Address", "Object type", "Retained heap size", "String representation")
    )
    print("-" * terminal_columns)
    for address, retained_size in objects_sorted_by_retained_heap(heap, retained)[:top_n]:
        obj = heap.objects[address]
        representation = heap.string_representation(obj) or ""
        print(
            row_format.format(
                address,
                heap.types[obj.type_address],
                retained_size,
                representation[:representation_width],
            )
        )

    print("\nRetained heap for threads:")
    print("{:<50} | {:>18}".format("Thread", "Retained heap size"))
    print("-" * 71)
    threads = sorted(retained.threads.items(), key=lambda item: item[1], reverse=True)
    for thread_name, retained_size in threads:
        print(f"{thread_name:<50} | {retained_size:>18}")
    print(f"\nTotal heap size: {total_heap_size(heap)} bytes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze PyHeap v1 heap files.", allow_abbrev=False
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    summary = subparsers.add_parser(
        "summary", help="show heap summary using the stable JSON protocol"
    )
    summary.add_argument("--file", "-f", type=Path, required=True, help="heap file name")

    retained = subparsers.add_parser("retained-heap", help="show retained heap statistics")
    retained.add_argument("--file", "-f", type=Path, required=True, help="heap file name")
    retained.add_argument(
        "--top-n", "-n", type=int, default=100, help="number of top objects to show"
    )
    retained.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    heap_file: Path = args.file
    if args.command == "summary":
        _summary(heap_file)
    else:
        _retained_heap(heap_file, output_format=args.format, top_n=args.top_n)
    return 0
