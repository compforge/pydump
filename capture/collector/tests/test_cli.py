from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pydump.cli as cli
import pytest
from pydump.errors import PydumpError


def test_pyheap_compatible_defaults() -> None:
    args = cli.parser().parse_args(["--pid", "12", "--file", "heap.pyheap"])
    assert args.pid == 12
    assert args.str_repr_len == 1000
    assert args.no_attribute is False


def test_targets_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        cli.parser().parse_args(
            ["--pid", "12", "--docker-container", "target", "--file", "heap.pyheap"]
        )


def test_negative_preview_below_disabled_value_is_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["--pid", "12", "--file", "heap.pyheap", "--str-repr-len", "-2"])


def test_injector_teardown_failure_preserves_delivered_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_root = tmp_path / "target-root"
    (target_root / "tmp").mkdir(parents=True)
    output = tmp_path / "heap.pyheap"
    agent = tmp_path / "agent.so"
    agent.write_bytes(b"agent")
    target = SimpleNamespace(
        root=target_root,
        fs_owner=(os.getuid(), os.getgid()),
        python_minor=(3, 12),
        host_pid=42,
    )

    class FakeConnection:
        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

    class FakeListener(FakeConnection):
        def bind(self, _path: str) -> None:
            return None

        def listen(self, _backlog: int) -> None:
            return None

        def accept(self) -> tuple[FakeConnection, None]:
            return FakeConnection(), None

    class FakeThread:
        def __init__(self, *, target, **_kwargs) -> None:
            self._target = target

        def start(self) -> None:
            return None

        def join(self, _timeout: float) -> None:
            self._target()

    class FakeCollector:
        stats = None

        def __init__(self, **_kwargs) -> None:
            pass

        def capture(self, _connection: FakeConnection, path: Path) -> tuple[Path, int]:
            path.write_bytes(b"complete artifact")
            return path, 1

    def fail_after_capture(**_kwargs) -> None:
        raise PydumpError("GDB detach failed")

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "resolve_target", lambda *_args: target)
    monkeypatch.setattr(cli, "verify_agent", lambda *_args: None)
    monkeypatch.setattr(cli, "install_agent", lambda *_args: (agent, "/tmp/agent.so"))
    monkeypatch.setattr(cli, "inject", fail_after_capture)
    monkeypatch.setattr(cli.socket, "socket", lambda *_args: FakeListener())
    monkeypatch.setattr(cli.threading, "Thread", FakeThread)
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli.os, "chown", lambda *_args: None)
    monkeypatch.setattr(cli.os, "chmod", lambda *_args: None)

    arguments = cli.parser().parse_args(
        ["--pid", "42", "--file", str(output), "--agent", str(agent)]
    )
    with pytest.raises(PydumpError, match="GDB detach failed"):
        cli.run(arguments)

    assert output.read_bytes() == b"complete artifact"
