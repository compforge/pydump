from __future__ import annotations

import pytest
from pydump.cli import parser


def test_pyheap_compatible_defaults() -> None:
    args = parser().parse_args(["--pid", "12", "--file", "heap.pyheap"])
    assert args.pid == 12
    assert args.str_repr_len == 1000
    assert args.no_attribute is False


def test_targets_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(
            ["--pid", "12", "--docker-container", "target", "--file", "heap.pyheap"]
        )


def test_negative_preview_below_disabled_value_is_rejected() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(["--pid", "12", "--file", "heap.pyheap", "--str-repr-len", "-2"])
