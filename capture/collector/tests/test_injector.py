from __future__ import annotations

import subprocess

import pydump.injector as injector
import pytest
from pydump.target import Target


def test_inject_waits_for_pending_call_safepoint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[str] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, "")

    monkeypatch.setattr(injector.shutil, "which", lambda _command: "/usr/bin/gdb")
    monkeypatch.setattr(injector.subprocess, "run", run)

    injector.inject(
        target=Target(host_pid=42, namespace_pid=1, python_minor=(3, 12)),
        agent_target_path="/tmp/pydump-agent.so",
        socket_target_path="/tmp/pydump/collector.sock",
        nonce=bytes.fromhex("00112233445566778899aabbccddeeff"),
        timeout=30,
    )

    commands = [captured[index + 1] for index, value in enumerate(captured[:-1]) if value == "-ex"]
    breakpoint = commands.index("break PyCallable_Check")
    pending_call = next(
        index for index, value in enumerate(commands) if value.startswith("set $pydump_pending=")
    )
    resume = commands.index("continue")
    load_agent = next(
        index for index, value in enumerate(commands) if value.startswith("set $pydump_agent=")
    )

    assert breakpoint < pending_call < resume < load_agent
    assert "Py_AddPendingCall" in commands[pending_call]
    assert all("_PyEval_EvalFrameDefault" not in value for value in commands)
