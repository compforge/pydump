from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class ContentKind(IntEnum):
    NONE = 0
    DICT = 1
    LIST = 2
    SET = 3
    TUPLE = 4


@dataclass(frozen=True)
class HeapAttribute:
    name: str
    address: int


@dataclass
class HeapObject:
    address: int
    type_address: int
    type_name: str
    shallow_size: int
    content_kind: ContentKind
    sequence_content: list[int] = field(default_factory=list)
    dict_content: list[tuple[int, int]] = field(default_factory=list)
    referents: set[int] = field(default_factory=set)
    attributes: list[HeapAttribute] = field(default_factory=list)
    str_repr: str = ""


@dataclass(frozen=True)
class ThreadFrame:
    filename: str
    lineno: int
    function: str
    locals: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class HeapThread:
    name: str
    is_alive: bool
    is_daemon: bool
    frames: tuple[ThreadFrame, ...]
