from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from pydump.errors import PydumpError
from pydump.loader.model import LoaderKind, LoaderProbe, LoadRequest

_AGENT_STARTED_MARKER = "PYDUMP_AGENT_STARTED=0"
_BUNDLED_NAMES = {
    "x86_64": "pydump-loader-linux-x86_64",
    "aarch64": "pydump-loader-linux-aarch64",
}


@dataclass(frozen=True)
class PydumpLoader:
    executable: Path
    kind = LoaderKind.PTRACE

    def start(self, request: LoadRequest) -> None:
        command = [
            str(self.executable),
            "--pid",
            str(request.target.host_pid),
            "--agent",
            request.agent_target_path,
            "--socket",
            request.socket_target_path,
            "--nonce",
            request.nonce.hex(),
            "--timeout",
            f"{request.timeout:g}s",
        ]
        try:
            process = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=request.timeout + 2,
            )
        except subprocess.TimeoutExpired as error:
            raise PydumpError(
                f"pydump-loader for PID {request.target.host_pid} timed out after "
                f"{request.timeout:g}s"
            ) from error
        output = process.stdout.strip()
        if process.returncode:
            detail = output or "pydump-loader returned no diagnostic"
            raise PydumpError(
                f"pydump-loader failed for PID {request.target.host_pid} with code "
                f"{process.returncode}: {detail}"
            )
        if _AGENT_STARTED_MARKER not in {line.strip() for line in output.splitlines()}:
            raise PydumpError(
                f"pydump-loader did not confirm Agent start for PID {request.target.host_pid}"
                + (f": {output}" if output else "")
            )


def probe_pydump_loader(
    *, machine: str, executable: Path | None
) -> tuple[LoaderProbe, PydumpLoader | None]:
    candidate = executable
    if candidate is None:
        configured = os.environ.get("PYDUMP_LOADER")
        if configured:
            candidate = Path(configured)
    if candidate is None:
        name = _BUNDLED_NAMES.get(machine)
        if name is None:
            return LoaderProbe(
                LoaderKind.PTRACE, False, f"unsupported architecture {machine}"
            ), None
        bundled = Path(__file__).with_name("bin") / name
        if bundled.exists():
            candidate = bundled
    if candidate is None:
        return LoaderProbe(LoaderKind.PTRACE, False, "no bundled pydump-loader"), None
    if not candidate.is_file():
        return LoaderProbe(LoaderKind.PTRACE, False, f"{candidate} does not exist"), None
    if not os.access(candidate, os.X_OK):
        return LoaderProbe(LoaderKind.PTRACE, False, f"{candidate} is not executable"), None
    resolved = candidate.resolve()
    return LoaderProbe(LoaderKind.PTRACE, True, str(resolved)), PydumpLoader(resolved)
