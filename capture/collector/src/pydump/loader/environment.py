from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from pydump.errors import PydumpError
from pydump.target import Target

_ELF_MACHINE = {
    62: "x86_64",
    183: "aarch64",
}
_MACHINE_ALIASES = {
    "amd64": "x86_64",
    "arm64": "aarch64",
}


@dataclass(frozen=True)
class TargetEnvironment:
    machine: str
    libc: str
    kernel_release: str


def inspect_target_environment(target: Target) -> TargetEnvironment:
    if sys.platform != "linux":
        raise PydumpError("live capture loaders are supported only on Linux")

    machine = _target_machine(target.host_pid)
    host_machine = _MACHINE_ALIASES.get(os.uname().machine, os.uname().machine)
    if machine != host_machine:
        raise PydumpError(
            f"target process {target.host_pid} is {machine}, but the Collector is {host_machine}; "
            "loaders must run on the target architecture"
        )

    libc = _target_libc(target.host_pid)
    if libc != "glibc":
        raise PydumpError(
            f"target process {target.host_pid} uses {libc}; pydump loaders currently require glibc"
        )
    return TargetEnvironment(machine=machine, libc=libc, kernel_release=os.uname().release)


def _target_machine(pid: int) -> str:
    try:
        with Path(f"/proc/{pid}/exe").open("rb") as executable:
            header = executable.read(20)
    except OSError as error:
        raise PydumpError(f"cannot read executable for target process {pid}: {error}") from error
    return _parse_machine(pid, header)


def _parse_machine(pid: int, header: bytes) -> str:
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise PydumpError(f"target process {pid} executable is not an ELF binary")
    if header[4] != 2 or header[5] != 1:
        raise PydumpError(f"target process {pid} must use a little-endian 64-bit ELF executable")
    machine = _ELF_MACHINE.get(int.from_bytes(header[18:20], "little"))
    if machine is None:
        raise PydumpError(f"target process {pid} uses an unsupported ELF architecture")
    return machine


def _target_libc(pid: int) -> str:
    try:
        maps = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise PydumpError(f"cannot inspect libc for target process {pid}: {error}") from error
    return _classify_libc(maps)


def _classify_libc(maps: str) -> str:
    if "ld-musl-" in maps or "libc.musl-" in maps:
        return "musl"
    if "libc.so.6" in maps or "ld-linux-" in maps:
        return "glibc"
    return "unknown libc"
