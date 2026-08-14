from __future__ import annotations

import os
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pydump.errors import PydumpError
from pydump.loader.model import LoaderKind, LoaderProbe, LoadRequest

_AGENT_STARTED_MARKER = "PYDUMP_AGENT_STARTED=0"
_FIRST_ARGUMENT_REGISTER = {
    "x86_64": "$rdi",
    "aarch64": "$x0",
}
_PROBE_TIMEOUT_SECONDS = 10
_PROBE_OK_MARKER = "PYDUMP_GDB_INFERIOR_CALL_OK"
_PROBE_SOURCE = """
import ctypes
import time

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
if libc.prctl(0x59616D61, ctypes.c_ulong(-1).value, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_PTRACER_ANY failed")
print("PYDUMP_GDB_PROBE_READY", flush=True)
time.sleep(30)
"""


@dataclass(frozen=True)
class GdbLoader:
    executable: Path
    machine: str
    kind = LoaderKind.GDB

    def start(self, request: LoadRequest) -> None:
        # Reach a CPython safe point before dlopen. Attaching at an arbitrary instruction may
        # otherwise stop a thread while it owns an allocator, GC, or dynamic-loader lock.
        # The NULL condition distinguishes our pending callback from ordinary PyCallable_Check
        # calls in other threads. CPython 3.10+ accepts NULL here and returns zero after detach.
        argument_register = _FIRST_ARGUMENT_REGISTER[self.machine]
        script = "\n".join(
            [
                "set debuginfod enabled off",
                "set unwindonsignal on",
                # All target threads must run until CPython dispatches the pending callback.
                "set scheduler-locking off",
                "set architecture auto",
                f"tbreak PyCallable_Check if {argument_register} == 0",
                (
                    "set $pydump_pending=(int)Py_AddPendingCall("
                    "(int (*)(void *))PyCallable_Check, (void *)0)"
                ),
                "if $pydump_pending != 0",
                '  printf "PYDUMP_PENDING_CALL_FAILED: %d\\n", $pydump_pending',
                "  quit 80",
                "end",
                "continue",
                f'set $pydump_agent=(void*)dlopen("{_gdb_string(request.agent_target_path)}", 2)',
                "if $pydump_agent == 0",
                '  printf "PYDUMP_DLOPEN_FAILED: %s\\n", (char*)dlerror()',
                "  quit 81",
                "end",
                'set $pydump_start=(void*)dlsym($pydump_agent, "pydump_start")',
                "if $pydump_start == 0",
                '  printf "PYDUMP_DLSYM_FAILED: %s\\n", (char*)dlerror()',
                "  quit 82",
                "end",
                (
                    "set $pydump_rc=(int)((int (*)(char*, char*))$pydump_start)"
                    f'("{_gdb_string(request.socket_target_path)}", "{request.nonce.hex()}")'
                ),
                'printf "PYDUMP_AGENT_STARTED=%d\\n", $pydump_rc',
                "if $pydump_rc != 0",
                '  printf "PYDUMP_START_FAILED: %d\\n", $pydump_rc',
                "  quit 83",
                "end",
                "detach",
                "quit",
            ]
        )
        command_prefix = [
            str(self.executable),
            "--batch",
            "--nx",
            "--nw",
            "--readnow",
            "-iex",
            f"set sysroot /proc/{request.target.host_pid}/root",
            "-p",
            str(request.target.host_pid),
        ]
        try:
            # GDB control structures only span lines inside a command file. Passing each line
            # through an independent -ex option makes GDB execute the conditional body eagerly.
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", prefix="pydump-gdb-", suffix=".gdb"
            ) as command_file:
                command_file.write(f"{script}\n")
                command_file.flush()
                command = command_prefix + ["-x", command_file.name]
                process = subprocess.run(
                    command,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=request.timeout,
                    env=_gdb_environment(),
                )
        except subprocess.TimeoutExpired as error:
            raise PydumpError(
                f"GDB loader for PID {request.target.host_pid} timed out after {request.timeout:g}s"
            ) from error
        output = process.stdout.strip()
        if process.returncode:
            rendered = shlex.join(command_prefix + ["-x", "<temporary-command-file>"])
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


def probe_gdb_loader(executable: Path | None, machine: str) -> tuple[LoaderProbe, GdbLoader | None]:
    if machine not in _FIRST_ARGUMENT_REGISTER:
        return LoaderProbe(LoaderKind.GDB, False, f"unsupported architecture {machine}"), None
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
    inferior_error = _probe_disposable_inferior(resolved)
    if inferior_error is not None:
        return LoaderProbe(
            LoaderKind.GDB,
            False,
            f"gdb disposable inferior call failed: {inferior_error}",
        ), None
    return LoaderProbe(LoaderKind.GDB, True, str(resolved)), GdbLoader(resolved, machine)


def _probe_disposable_inferior(executable: Path) -> str | None:
    helper = subprocess.Popen(
        [sys.executable, "-I", "-c", _PROBE_SOURCE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert helper.stdout is not None
        ready, _, _ = select.select([helper.stdout], [], [], _PROBE_TIMEOUT_SECONDS)
        if not ready or helper.stdout.readline().strip() != "PYDUMP_GDB_PROBE_READY":
            return _helper_failure(helper)
        script = "\n".join(
            [
                "set scheduler-locking off",
                (
                    "set $pydump_probe=(int)Py_AddPendingCall("
                    "(int (*)(void *))PyCallable_Check, (void *)0)"
                ),
                f'printf "{_PROBE_OK_MARKER}=%d\\n", $pydump_probe',
                "detach",
                "quit",
            ]
        )
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", prefix="pydump-gdb-probe-", suffix=".gdb"
            ) as command_file:
                command_file.write(f"{script}\n")
                command_file.flush()
                process = subprocess.run(
                    [
                        str(executable),
                        "--batch",
                        "--nx",
                        "--nw",
                        "--readnow",
                        "-p",
                        str(helper.pid),
                        "-x",
                        command_file.name,
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=_PROBE_TIMEOUT_SECONDS,
                    env=_gdb_environment(),
                )
        except subprocess.TimeoutExpired:
            return f"timed out after {_PROBE_TIMEOUT_SECONDS}s"
        if process.returncode:
            return _gdb_failure_detail(
                process.stdout,
                fallback=f"exited with code {process.returncode}",
            )
        if f"{_PROBE_OK_MARKER}=0" not in {line.strip() for line in process.stdout.splitlines()}:
            return "GDB returned no successful inferior-call marker"
        return None
    finally:
        helper.terminate()
        try:
            helper.wait(timeout=3)
        except subprocess.TimeoutExpired:
            helper.kill()
            helper.wait(timeout=3)


def _helper_failure(helper: subprocess.Popen[str]) -> str:
    helper.terminate()
    try:
        _, stderr = helper.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        helper.kill()
        _, stderr = helper.communicate(timeout=3)
    detail = stderr.strip().splitlines()
    return detail[-1] if detail else "disposable Python helper did not become ready"


def _gdb_environment() -> dict[str, str]:
    environment = os.environ.copy()
    # GDB may embed a different Python build than the Collector. Inheriting these variables can
    # break GDB before it attaches to the target.
    environment.pop("PYTHONIOENCODING", None)
    environment.pop("PYTHONPATH", None)
    return environment


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
