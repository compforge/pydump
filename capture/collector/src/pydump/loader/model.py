from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from pydump.target import Target


class LoaderKind(str, Enum):
    AUTO = "auto"
    GDB = "gdb"
    PTRACE = "ptrace"


@dataclass(frozen=True)
class LoadRequest:
    target: Target
    agent_target_path: str
    socket_target_path: str
    nonce: bytes
    timeout: float


@dataclass(frozen=True)
class LoaderProbe:
    kind: LoaderKind
    available: bool
    detail: str


class AgentLoader(Protocol):
    @property
    def kind(self) -> LoaderKind: ...

    @property
    def executable(self) -> Path: ...

    def start(self, request: LoadRequest) -> None: ...
