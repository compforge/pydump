from __future__ import annotations

import hashlib
import os
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
    injector_path: Path | None = None,
) -> None:
    _inject_with_ptrace(
        injector=_resolve_ptrace_injector(injector_path),
        target=target,
        agent_target_path=agent_target_path,
        socket_target_path=socket_target_path,
        nonce=nonce,
        timeout=timeout,
    )


def _inject_with_ptrace(
    *,
    injector: Path,
    target: Target,
    agent_target_path: str,
    socket_target_path: str,
    nonce: bytes,
    timeout: float,
) -> None:
    command = [
        str(injector),
        "--pid",
        str(target.host_pid),
        "--agent",
        agent_target_path,
        "--socket",
        socket_target_path,
        "--nonce",
        nonce.hex(),
        "--timeout",
        f"{timeout:g}s",
    ]
    try:
        process = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 2,
        )
    except subprocess.TimeoutExpired as error:
        raise PydumpError(
            f"ptrace injector for PID {target.host_pid} timed out after {timeout:g}s"
        ) from error
    output = process.stdout.strip()
    if process.returncode:
        detail = output or "ptrace injector returned no diagnostic"
        raise PydumpError(
            f"ptrace injector failed for PID {target.host_pid} with code "
            f"{process.returncode}: {detail}"
        )
    if _AGENT_STARTED_MARKER not in {line.strip() for line in output.splitlines()}:
        raise PydumpError(
            f"ptrace injector did not confirm Agent start for PID {target.host_pid}"
            + (f": {output}" if output else "")
        )


def _resolve_ptrace_injector(explicit: Path | None) -> Path:
    candidate = explicit
    if candidate is None:
        configured = os.environ.get("PYDUMP_INJECTOR")
        if configured:
            candidate = Path(configured)
    machine = os.uname().machine
    names = {
        "x86_64": "pydump-injector-linux-x86_64",
        "aarch64": "pydump-injector-linux-aarch64",
        "arm64": "pydump-injector-linux-aarch64",
    }
    if candidate is None and machine in names:
        bundled = Path(__file__).with_name("injectors") / names[machine]
        if bundled.exists():
            candidate = bundled
    if candidate is None:
        raise PydumpError(
            f"no ptrace injector is bundled for Linux {machine}; pass --injector explicitly"
        )
    if not candidate.is_file():
        raise PydumpError(f"ptrace injector {candidate} does not exist")
    if not os.access(candidate, os.X_OK):
        raise PydumpError(f"ptrace injector {candidate} is not executable")
    return candidate
