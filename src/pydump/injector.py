from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from pydump.errors import PydumpError
from pydump.target import Target


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

    # The breakpoint makes dlopen happen at a normal Python evaluation point. Calling the Agent
    # directly while GDB interrupted an allocator or GC mutation would be unsafe.
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
        "break _PyEval_EvalFrameDefault",
        "-ex",
        "continue",
        "-ex",
        "delete 1",
        "-ex",
        f'set $pydump_agent=(void*)dlopen("{_gdb_string(agent_target_path)}", 2)',
        "-ex",
        (
            'if $pydump_agent == 0\nprintf "PYDUMP_DLOPEN_FAILED: %s\\n", '
            "(char*)dlerror()\nquit 81\nend"
        ),
        "-ex",
        'set $pydump_start=(void*)dlsym($pydump_agent, "pydump_start")',
        "-ex",
        (
            'if $pydump_start == 0\nprintf "PYDUMP_DLSYM_FAILED: %s\\n", '
            "(char*)dlerror()\nquit 82\nend"
        ),
        "-ex",
        (
            "set $pydump_rc=(int)((int (*)(char*, char*))$pydump_start)"
            f'("{_gdb_string(socket_target_path)}", "{nonce.hex()}")'
        ),
        "-ex",
        ('if $pydump_rc != 0\nprintf "PYDUMP_START_FAILED: %d\\n", $pydump_rc' "\nquit 83\nend"),
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
        raise PydumpError(
            f"GDB failed for PID {target.host_pid} with code {process.returncode} "
            f"({rendered}):\n{process.stdout.strip()}"
        )


def _gdb_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
