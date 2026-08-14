from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydump.errors import PydumpError
from pydump.loader.model import LoaderKind, LoaderProbe, LoadRequest

_AGENT_STARTED_MARKER = "PYDUMP_AGENT_STARTED=0"


@dataclass(frozen=True)
class GdbLoader:
    executable: Path
    kind = LoaderKind.GDB

    def start(self, request: LoadRequest) -> None:
        # Reach a CPython safe point before dlopen. Attaching at an arbitrary instruction may
        # otherwise stop a thread while it owns an allocator, GC, or dynamic-loader lock.
        command = [
            str(self.executable),
            "--batch",
            "--nx",
            "--nw",
            "--readnow",
            "-iex",
            f"set sysroot /proc/{request.target.host_pid}/root",
            "-ex",
            "set debuginfod enabled off",
            "-ex",
            "set unwindonsignal on",
            "-ex",
            "break PyCallable_Check",
            "-ex",
            (
                "set $pydump_pending=(int)Py_AddPendingCall("
                "(int (*)(void *))PyCallable_Check, (void *)0)"
            ),
            "-ex",
            "if $pydump_pending != 0",
            "-ex",
            'printf "PYDUMP_PENDING_CALL_FAILED: %d\\n", $pydump_pending',
            "-ex",
            "quit 80",
            "-ex",
            "end",
            "-ex",
            "continue",
            "-ex",
            "delete 1",
            "-ex",
            f'set $pydump_agent=(void*)dlopen("{_gdb_string(request.agent_target_path)}", 2)',
            "-ex",
            "if $pydump_agent == 0",
            "-ex",
            'printf "PYDUMP_DLOPEN_FAILED: %s\\n", (char*)dlerror()',
            "-ex",
            "quit 81",
            "-ex",
            "end",
            "-ex",
            'set $pydump_start=(void*)dlsym($pydump_agent, "pydump_start")',
            "-ex",
            "if $pydump_start == 0",
            "-ex",
            'printf "PYDUMP_DLSYM_FAILED: %s\\n", (char*)dlerror()',
            "-ex",
            "quit 82",
            "-ex",
            "end",
            "-ex",
            (
                "set $pydump_rc=(int)((int (*)(char*, char*))$pydump_start)"
                f'("{_gdb_string(request.socket_target_path)}", "{request.nonce.hex()}")'
            ),
            "-ex",
            'printf "PYDUMP_AGENT_STARTED=%d\\n", $pydump_rc',
            "-ex",
            "if $pydump_rc != 0",
            "-ex",
            'printf "PYDUMP_START_FAILED: %d\\n", $pydump_rc',
            "-ex",
            "quit 83",
            "-ex",
            "end",
            "-ex",
            "detach",
            "-ex",
            "quit",
            "-p",
            str(request.target.host_pid),
        ]
        try:
            process = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=request.timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise PydumpError(
                f"GDB loader for PID {request.target.host_pid} timed out after {request.timeout:g}s"
            ) from error
        output = process.stdout.strip()
        if process.returncode:
            rendered = shlex.join(command[:7] + ["..."])
            detail = _gdb_failure_detail(output)
            raise PydumpError(
                f"GDB loader failed for PID {request.target.host_pid} with code "
                f"{process.returncode}: {detail}\nCommand: {rendered}\n\nGDB output:\n{output}"
            )
        if _AGENT_STARTED_MARKER not in {line.strip() for line in output.splitlines()}:
            detail = _gdb_failure_detail(output, fallback="GDB returned no Agent start marker")
            raise PydumpError(
                f"GDB loader did not confirm Agent start for PID "
                f"{request.target.host_pid}: {detail}"
                + (f"\n\nGDB output:\n{output}" if output else "")
            )


def probe_gdb_loader(executable: Path | None) -> tuple[LoaderProbe, GdbLoader | None]:
    candidate = executable
    if candidate is None:
        configured = os.environ.get("PYDUMP_GDB")
        candidate = Path(configured) if configured else None
    if candidate is None:
        discovered = shutil.which("gdb")
        candidate = Path(discovered) if discovered else None
    if candidate is None:
        return LoaderProbe(LoaderKind.GDB, False, "gdb executable was not found"), None
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return LoaderProbe(LoaderKind.GDB, False, f"{candidate} is not executable"), None
    resolved = candidate.resolve()
    try:
        process = subprocess.run(
            [str(resolved), "--batch", "--nx", "--version"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return LoaderProbe(LoaderKind.GDB, False, f"gdb probe failed: {error}"), None
    if process.returncode:
        return LoaderProbe(
            LoaderKind.GDB,
            False,
            f"gdb probe exited with code {process.returncode}",
        ), None
    return LoaderProbe(LoaderKind.GDB, True, str(resolved)), GdbLoader(resolved)


def _gdb_failure_detail(output: str, *, fallback: str = "GDB returned no diagnostic") -> str:
    return next(
        (
            line.strip()
            for line in output.splitlines()
            if "extended state status" in line
            or "gdb.error:" in line
            or ("PYDUMP_" in line and "FAILED" in line)
        ),
        fallback,
    )


def _gdb_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
