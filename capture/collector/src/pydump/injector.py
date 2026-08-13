from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from pydump.errors import PydumpError
from pydump.target import Target

_AGENT_STARTED_MARKER = "PYDUMP_AGENT_STARTED=0"


def install_agent(target: Target, source: Path) -> tuple[Path, str]:
    """Copy a stable agent path into target `/tmp` and return host/target views."""
    fingerprint = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
    target_path = f"/tmp/pydump-agent-{fingerprint}.so"
    host_path = target.root / target_path.lstrip("/")
    if not host_path.exists():
        temporary = host_path.with_suffix(".partial")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o755)
        os.replace(temporary, host_path)
    return host_path, target_path


def inject(
    *,
    target: Target,
    agent_target_path: str,
    socket_target_path: str,
    nonce: bytes,
    timeout: float,
) -> None:
    gdb = shutil.which("gdb")
    if gdb is None:
        raise PydumpError("gdb executable was not found")

    # CPython 3.11+ inlines Python-to-Python frame calls, so waiting for another
    # _PyEval_EvalFrameDefault entry can block forever. Py_AddPendingCall marks the eval breaker;
    # its NULL-safe PyCallable_Check callback gives GDB a deterministic interpreter safe point.
    # Loading the Agent before that point could interrupt an allocator or GC mutation.
    command = [
        gdb,
        "--batch",
        "--nx",
        "--nw",
        "--readnow",
        "-iex",
        f"set sysroot /proc/{target.host_pid}/root",
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
        f'set $pydump_agent=(void*)dlopen("{_gdb_string(agent_target_path)}", 2)',
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
            f'("{_gdb_string(socket_target_path)}", "{nonce.hex()}")'
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
        str(target.host_pid),
    ]
    try:
        process = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise PydumpError(
            f"GDB attach to PID {target.host_pid} timed out after {timeout:g}s"
        ) from error
    if process.returncode:
        rendered = shlex.join(command[:7] + ["..."])
        detail = _gdb_failure_detail(process.stdout)
        raise PydumpError(
            f"GDB failed for PID {target.host_pid} with code {process.returncode}: {detail}"
            f"\nCommand: {rendered}\n\nGDB output:\n{process.stdout.strip()}"
        )
    if _AGENT_STARTED_MARKER not in {line.strip() for line in process.stdout.splitlines()}:
        output = process.stdout.strip()
        detail = _gdb_failure_detail(output, fallback="GDB returned no Agent start marker")
        raise PydumpError(
            f"GDB did not confirm Agent start for PID {target.host_pid}: {detail}"
            + (f"\n\nGDB output:\n{output}" if output else "")
        )


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
