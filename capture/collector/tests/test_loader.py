from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pydump.loader.gdb as gdb_module
import pydump.loader.ptrace as ptrace_module
import pydump.loader.selection as selection
import pytest
from pydump.errors import PydumpError
from pydump.loader.environment import TargetEnvironment, _classify_libc, _parse_machine
from pydump.loader.gdb import GdbLoader
from pydump.loader.model import LoaderKind, LoaderProbe, LoadRequest
from pydump.loader.ptrace import PydumpLoader
from pydump.target import Target

_NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")


def request() -> LoadRequest:
    return LoadRequest(
        target=Target(host_pid=42, namespace_pid=1, python_minor=(3, 11)),
        agent_target_path="/tmp/pydump-agent.so",
        socket_target_path="/tmp/pydump/collector.sock",
        nonce=_NONCE,
        timeout=30,
    )


@pytest.mark.parametrize(("elf_machine", "expected"), [(62, "x86_64"), (183, "aarch64")])
def test_target_machine_is_read_from_elf(elf_machine: int, expected: str) -> None:
    header = bytearray(20)
    header[:6] = b"\x7fELF\x02\x01"
    header[18:20] = elf_machine.to_bytes(2, "little")
    assert _parse_machine(42, bytes(header)) == expected


@pytest.mark.parametrize(
    ("maps", "expected"),
    [
        ("7f00 /usr/lib/x86_64-linux-gnu/libc.so.6", "glibc"),
        ("7f00 /lib/ld-musl-x86_64.so.1", "musl"),
        ("7f00 /opt/python/libpython3.12.so", "unknown libc"),
    ],
)
def test_target_libc_is_read_from_process_maps(maps: str, expected: str) -> None:
    assert _classify_libc(maps) == expected


def test_pydump_loader_starts_agent_with_explicit_protocol(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "pydump-loader"
    executable.touch(mode=0o755)
    captured: list[str] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.extend(command)
        return subprocess.CompletedProcess(command, 0, "PYDUMP_AGENT_STARTED=0\n")

    monkeypatch.setattr(ptrace_module.subprocess, "run", run)
    PydumpLoader(executable).start(request())

    assert captured[0] == str(executable)
    assert captured[captured.index("--pid") + 1] == "42"
    assert captured[captured.index("--nonce") + 1] == _NONCE.hex()


def test_pydump_loader_surfaces_native_diagnostic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "pydump-loader"
    executable.touch(mode=0o755)
    monkeypatch.setattr(
        ptrace_module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, "pydump-loader: attach PID 42: operation not permitted\n"
        ),
    )

    with pytest.raises(PydumpError, match="attach PID 42: operation not permitted"):
        PydumpLoader(executable).start(request())


def test_gdb_loader_waits_for_pending_call_safepoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "gdb"
    executable.touch(mode=0o755)
    captured: list[str] = []
    script = ""

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal script
        captured.extend(command)
        script = Path(command[command.index("-x") + 1]).read_text()
        return subprocess.CompletedProcess(command, 0, "PYDUMP_AGENT_STARTED=0\n")

    monkeypatch.setattr(gdb_module.subprocess, "run", run)
    GdbLoader(executable).start(request())

    assert "-ex" not in captured
    commands = script.splitlines()
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
    assert commands[pending_call + 1 : resume] == [
        "if $pydump_pending != 0",
        '  printf "PYDUMP_PENDING_CALL_FAILED: %d\\n", $pydump_pending',
        "  quit 80",
        "end",
    ]


@pytest.mark.skipif(shutil.which("gdb") is None, reason="GDB is not installed")
def test_gdb_command_file_honors_false_conditional(tmp_path: Path) -> None:
    script = tmp_path / "conditional.gdb"
    script.write_text(
        "\n".join(
            [
                "set $pydump_pending = 0",
                "if $pydump_pending != 0",
                "  quit 80",
                "end",
                'printf "PYDUMP_GDB_CONDITION_OK\\n"',
                "quit",
            ]
        )
    )

    process = subprocess.run(
        [shutil.which("gdb") or "gdb", "--batch", "--nx", "-x", str(script)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
    )

    assert process.returncode == 0, process.stdout
    assert "PYDUMP_GDB_CONDITION_OK" in process.stdout


def test_gdb_loader_rejects_inferior_call_failure_with_zero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "gdb"
    executable.touch(mode=0o755)
    output = "Couldn't write extended state status: Bad address.\n"
    monkeypatch.setattr(
        gdb_module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, output),
    )

    with pytest.raises(PydumpError, match="Couldn't write extended state status: Bad address"):
        GdbLoader(executable).start(request())


def test_auto_loader_prefers_gdb(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = TargetEnvironment("x86_64", "glibc", "6.8")
    gdb = SimpleNamespace(kind=LoaderKind.GDB, executable=Path("/usr/bin/gdb"))
    monkeypatch.setattr(selection, "inspect_target_environment", lambda _target: environment)
    monkeypatch.setattr(
        selection,
        "probe_gdb_loader",
        lambda _path: (LoaderProbe(LoaderKind.GDB, True, "ready"), gdb),
    )
    monkeypatch.setattr(
        selection,
        "probe_pydump_loader",
        lambda **_kwargs: pytest.fail("pydump-loader should not be probed after GDB is selected"),
    )

    selected = selection.select_loader(
        target=request().target,
        kind=LoaderKind.AUTO,
        gdb=None,
        pydump_loader=None,
    )
    assert selected is gdb


def test_auto_loader_uses_ptrace_when_gdb_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = TargetEnvironment("aarch64", "glibc", "5.10")
    ptrace = SimpleNamespace(
        kind=LoaderKind.PTRACE,
        executable=Path("/opt/pydump-loader"),
    )
    monkeypatch.setattr(selection, "inspect_target_environment", lambda _target: environment)
    monkeypatch.setattr(
        selection,
        "probe_gdb_loader",
        lambda _path: (LoaderProbe(LoaderKind.GDB, False, "not found"), None),
    )
    monkeypatch.setattr(
        selection,
        "probe_pydump_loader",
        lambda **_kwargs: (LoaderProbe(LoaderKind.PTRACE, True, "ready"), ptrace),
    )

    selected = selection.select_loader(
        target=request().target,
        kind=LoaderKind.AUTO,
        gdb=None,
        pydump_loader=None,
    )
    assert selected is ptrace


def test_explicit_loader_reports_probe_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = TargetEnvironment("x86_64", "glibc", "6.8")
    monkeypatch.setattr(selection, "inspect_target_environment", lambda _target: environment)
    monkeypatch.setattr(
        selection,
        "probe_gdb_loader",
        lambda _path: (LoaderProbe(LoaderKind.GDB, False, "gdb is broken"), None),
    )

    with pytest.raises(PydumpError, match="gdb: gdb is broken"):
        selection.select_loader(
            target=request().target,
            kind=LoaderKind.GDB,
            gdb=None,
            pydump_loader=None,
        )
