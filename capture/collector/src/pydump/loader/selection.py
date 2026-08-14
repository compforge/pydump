from __future__ import annotations

from pathlib import Path

from pydump.errors import PydumpError
from pydump.loader.environment import inspect_target_environment
from pydump.loader.gdb import probe_gdb_loader
from pydump.loader.model import AgentLoader, LoaderKind, LoaderProbe
from pydump.loader.ptrace import probe_pydump_loader
from pydump.target import Target


def select_loader(
    *,
    target: Target,
    kind: LoaderKind,
    gdb: Path | None,
    pydump_loader: Path | None,
) -> AgentLoader:
    environment = inspect_target_environment(target)
    probes: list[tuple[LoaderProbe, AgentLoader | None]] = []
    if kind in {LoaderKind.AUTO, LoaderKind.GDB}:
        gdb_probe, gdb_loader = probe_gdb_loader(gdb)
        probes.append((gdb_probe, gdb_loader))
        if gdb_probe.available and gdb_loader is not None:
            return gdb_loader
    if kind in {LoaderKind.AUTO, LoaderKind.PTRACE}:
        ptrace_probe, ptrace = probe_pydump_loader(
            machine=environment.machine,
            executable=pydump_loader,
        )
        probes.append((ptrace_probe, ptrace))
        if ptrace_probe.available and ptrace is not None:
            return ptrace

    detail = "; ".join(f"{probe.kind.value}: {probe.detail}" for probe, _ in probes)
    raise PydumpError(
        f"no usable {kind.value} loader for PID {target.host_pid} "
        f"({environment.machine}, {environment.libc}, "
        f"kernel {environment.kernel_release}): {detail}"
    )
