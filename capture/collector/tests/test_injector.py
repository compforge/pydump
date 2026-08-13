from __future__ import annotations

import subprocess
from pathlib import Path

import pydump.injector as injector
import pytest
from pydump.errors import PydumpError
from pydump.target import Target


def test_inject_uses_explicit_ptrace_injector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "pydump-injector"
    executable.touch(mode=0o755)
    captured: list[str] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, "PYDUMP_AGENT_STARTED=0\n")

    monkeypatch.setattr(injector.subprocess, "run", run)

    injector.inject(
        target=Target(host_pid=42, namespace_pid=1, python_minor=(3, 11)),
        agent_target_path="/tmp/pydump-agent.so",
        socket_target_path="/tmp/pydump/collector.sock",
        nonce=bytes.fromhex("00112233445566778899aabbccddeeff"),
        timeout=30,
        injector_path=executable,
    )

    assert captured[0] == str(executable)
    assert captured[captured.index("--pid") + 1] == "42"
    assert captured[captured.index("--nonce") + 1] == "00112233445566778899aabbccddeeff"
    assert captured[captured.index("--timeout") + 1] == "30s"


def test_inject_includes_ptrace_diagnostic_when_injector_returns_nonzero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "pydump-injector"
    executable.touch(mode=0o755)
    monkeypatch.setattr(
        injector.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, "pydump-injector: attach PID 42: operation not permitted\n"
        ),
    )

    with pytest.raises(PydumpError, match="attach PID 42: operation not permitted"):
        injector.inject(
            target=Target(host_pid=42, namespace_pid=1, python_minor=(3, 11)),
            agent_target_path="/tmp/pydump-agent.so",
            socket_target_path="/tmp/pydump/collector.sock",
            nonce=bytes.fromhex("00112233445566778899aabbccddeeff"),
            timeout=30,
            injector_path=executable,
        )


def test_inject_rejects_success_without_agent_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "pydump-injector"
    executable.touch(mode=0o755)
    monkeypatch.setattr(
        injector.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, ""),
    )

    with pytest.raises(PydumpError, match="did not confirm Agent start"):
        injector.inject(
            target=Target(host_pid=42, namespace_pid=1, python_minor=(3, 11)),
            agent_target_path="/tmp/pydump-agent.so",
            socket_target_path="/tmp/pydump/collector.sock",
            nonce=bytes.fromhex("00112233445566778899aabbccddeeff"),
            timeout=30,
            injector_path=executable,
        )
