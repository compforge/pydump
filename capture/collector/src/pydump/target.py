from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydump.errors import PydumpError

_PYTHON_LIBRARY = re.compile(r"libpython(?P<version>3\.[0-9]+).*\.so(?:\.|$)")
_PYTHON_EXECUTABLE = re.compile(r"python(?P<version>3\.[0-9]+)(?:$|[^0-9])")


@dataclass(frozen=True)
class Target:
    host_pid: int
    namespace_pid: int
    python_minor: tuple[int, int]

    @property
    def root(self) -> Path:
        return Path(f"/proc/{self.host_pid}/root")

    @property
    def fs_owner(self) -> tuple[int, int]:
        uid: int | None = None
        gid: int | None = None
        with Path(f"/proc/{self.host_pid}/status").open(encoding="utf-8") as status:
            for line in status:
                if line.startswith("Uid:"):
                    uid = int(line.split()[-1])
                elif line.startswith("Gid:"):
                    gid = int(line.split()[-1])
        if uid is None or gid is None:
            raise PydumpError(f"cannot determine filesystem owner for process {self.host_pid}")
        return uid, gid


def resolve_target(pid: int | None, docker_container: str | None) -> Target:
    host_pid = docker_pid(docker_container) if docker_container is not None else pid
    if host_pid is None or host_pid <= 0:
        raise PydumpError(f"invalid target PID {host_pid}")
    proc = Path(f"/proc/{host_pid}")
    if not proc.exists():
        raise PydumpError(f"target process {host_pid} does not exist")
    return Target(
        host_pid=host_pid,
        namespace_pid=pid_in_own_namespace(host_pid),
        python_minor=detect_python_minor(host_pid),
    )


def docker_pid(container: str) -> int:
    docker = shutil.which("docker")
    if docker is None:
        raise PydumpError("docker executable was not found")
    process = subprocess.run(
        [docker, "inspect", container],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if process.returncode:
        raise PydumpError(f"docker inspect {container!r} failed: {process.stderr.strip()}")
    try:
        inspected = json.loads(process.stdout)
        state = inspected[0]["State"]
        if state["Status"] != "running":
            raise PydumpError(f"Docker container {container!r} is not running")
        return int(state["Pid"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PydumpError(
            f"docker inspect returned an unexpected result for {container!r}"
        ) from error


def pid_in_own_namespace(pid: int) -> int:
    try:
        with Path(f"/proc/{pid}/status").open(encoding="utf-8") as status:
            for line in status:
                if line.startswith("NStgid:"):
                    return int(line.split()[-1])
    except PermissionError as error:
        raise PydumpError(
            f"cannot read process {pid}; try running as the target user or root"
        ) from error
    raise PydumpError(f"cannot determine PID namespace ID for process {pid}")


def detect_python_minor(pid: int) -> tuple[int, int]:
    candidates: list[str] = []
    try:
        candidates.append(os.readlink(f"/proc/{pid}/exe"))
        with Path(f"/proc/{pid}/maps").open(encoding="utf-8") as maps:
            candidates.extend(line.split(maxsplit=5)[-1].strip() for line in maps if "/" in line)
    except PermissionError as error:
        raise PydumpError(
            f"cannot inspect process {pid}; try running as the target user or root"
        ) from error

    versions: set[tuple[int, int]] = set()
    for candidate in candidates:
        match = _PYTHON_LIBRARY.search(candidate) or _PYTHON_EXECUTABLE.search(Path(candidate).name)
        if match is not None:
            major, minor = match.group("version").split(".")
            versions.add((int(major), int(minor)))
    if len(versions) != 1:
        rendered = ", ".join(f"{major}.{minor}" for major, minor in sorted(versions)) or "none"
        raise PydumpError(f"cannot uniquely detect target CPython minor version; found {rendered}")
    version = versions.pop()
    if version < (3, 10):
        raise PydumpError(
            f"CPython {version[0]}.{version[1]} is unsupported; pydump requires 3.10+"
        )
    return version


def verify_agent(agent: Path, target: Target) -> None:
    if not agent.is_file():
        raise PydumpError(f"agent library {agent} does not exist")
    expected = f"{target.python_minor[0]}.{target.python_minor[1]}"
    if f"agent-{expected}-" not in agent.name:
        raise PydumpError(
            f"agent {agent.name!r} does not identify target CPython {expected}; "
            "use an agent built for the target minor"
        )
    if struct.calcsize("P") != 8:
        raise PydumpError("only 64-bit Collector processes are supported")
