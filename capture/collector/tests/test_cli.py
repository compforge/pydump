from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pydump.cli as cli
import pytest
from pydump.errors import PydumpError
from pydump.loader import LoaderKind


def test_pyheap_compatible_defaults() -> None:
    args = cli.parser().parse_args(["--pid", "12", "--file", "heap.pyheap"])
    assert args.pid == 12
    assert args.str_repr_len == 1000
    assert args.no_attribute is False
    assert args.loader == "auto"


def test_version_is_available_without_a_capture_target(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit, match="0"):
        cli.parser().parse_args(["--version"])
    assert capsys.readouterr().out == "pydump 0.2.2\n"


def test_targets_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        cli.parser().parse_args(
            ["--pid", "12", "--docker-container", "target", "--file", "heap.pyheap"]
        )


def test_negative_preview_below_disabled_value_is_rejected() -> None:
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["--pid", "12", "--file", "heap.pyheap", "--str-repr-len", "-2"])


def test_loader_teardown_failure_preserves_delivered_artifact(
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

    class FailingLoader:
        kind = LoaderKind.PTRACE
        executable = Path("/opt/pydump-loader")

        def start(self, _request: object) -> None:
            raise PydumpError("pydump-loader detach failed")

    monkeypatch.setattr(cli, "resolve_target", lambda *_args: target)
    monkeypatch.setattr(cli, "verify_agent", lambda *_args: None)
    monkeypatch.setattr(cli, "install_agent", lambda *_args: (agent, "/tmp/agent.so"))
    monkeypatch.setattr(cli, "select_loader", lambda **_kwargs: FailingLoader())
    monkeypatch.setattr(cli.socket, "socket", lambda *_args: FakeListener())
    monkeypatch.setattr(cli.threading, "Thread", FakeThread)
    monkeypatch.setattr(cli, "Collector", FakeCollector)
    monkeypatch.setattr(cli.os, "chown", lambda *_args: None)
    monkeypatch.setattr(cli.os, "chmod", lambda *_args: None)

    arguments = cli.parser().parse_args(
        ["--pid", "42", "--file", str(output), "--agent", str(agent)]
    )
    with pytest.raises(PydumpError, match="pydump-loader detach failed"):
        cli.run(arguments)

    assert output.read_bytes() == b"complete artifact"


def test_agent_connect_timeout_prefers_completed_loader_error(
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
        python_minor=(3, 11),
        host_pid=42,
    )

    class FakeListener:
        def __enter__(self) -> FakeListener:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def bind(self, _path: str) -> None:
            return None

        def listen(self, _backlog: int) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def accept(self) -> tuple[object, None]:
            raise TimeoutError

    class FakeThread:
        def __init__(self, *, target, **_kwargs) -> None:
            self._target = target

        def start(self) -> None:
            self._target()

        def join(self, _timeout: float | None = None) -> None:
            return None

    class FailingLoader:
        kind = LoaderKind.PTRACE
        executable = Path("/opt/pydump-loader")

        def start(self, _request: object) -> None:
            raise PydumpError("pydump-loader did not confirm Agent start")

    monkeypatch.setattr(cli, "resolve_target", lambda *_args: target)
    monkeypatch.setattr(cli, "verify_agent", lambda *_args: None)
    monkeypatch.setattr(cli, "install_agent", lambda *_args: (agent, "/tmp/agent.so"))
    monkeypatch.setattr(cli, "select_loader", lambda **_kwargs: FailingLoader())
    monkeypatch.setattr(cli.socket, "socket", lambda *_args: FakeListener())
    monkeypatch.setattr(cli.threading, "Thread", FakeThread)
    monkeypatch.setattr(cli.os, "chown", lambda *_args: None)
    monkeypatch.setattr(cli.os, "chmod", lambda *_args: None)

    arguments = cli.parser().parse_args(
        ["--pid", "42", "--file", str(output), "--agent", str(agent)]
    )
    with pytest.raises(PydumpError, match="did not confirm Agent start"):
        cli.run(arguments)
