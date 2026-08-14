from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from pydump import cli
from pydump.collector import Collector
from pydump.model import HeapObject
from pydump.protocol import (
    FramedSocket,
    FrameKind,
    decode_hello,
    encode_addresses,
    encode_options,
)


@pytest.mark.skipif(
    "PYDUMP_NATIVE_AGENT" not in os.environ,
    reason="set PYDUMP_NATIVE_AGENT to a native Agent built for this interpreter",
)
def test_native_agent_schedules_and_streams_a_real_cpython_heap(tmp_path: Path) -> None:
    agent = Path(os.environ["PYDUMP_NATIVE_AGENT"]).resolve()
    nonce = os.urandom(16)
    target_code = """
import ctypes
import sys
import time

agent = ctypes.CDLL(sys.argv[1])
start = agent.pydump_schedule
start.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
start.restype = ctypes.c_int
result = start(sys.argv[2].encode(), sys.argv[3].encode())
print(result, flush=True)
time.sleep(60)
"""

    with tempfile.TemporaryDirectory(prefix="pydump-native-", dir="/tmp") as socket_directory:
        socket_path = Path(socket_directory) / "collector.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            _capture_native(listener, socket_path, agent, nonce, target_code, tmp_path)
        finally:
            listener.close()


@pytest.mark.skipif(
    "PYDUMP_NATIVE_AGENT" not in os.environ or "PYDUMP_LOADER" not in os.environ,
    reason="set matching native Agent and pydump-loader paths",
)
def test_pydump_loader_captures_a_real_cpython_heap(tmp_path: Path) -> None:
    agent = Path(os.environ["PYDUMP_NATIVE_AGENT"]).resolve()
    loader = Path(os.environ["PYDUMP_LOADER"]).resolve()
    output = tmp_path / "ptrace.pyheap"
    target_code = """
import ctypes
import os
import time

libc = ctypes.CDLL(None)
if libc.prctl(0x59616D61, -1, 0, 0, 0) != 0:
    raise RuntimeError("PR_SET_PTRACER_ANY failed")
heap = [{"index": index} for index in range(10_000)]
print(os.getpid(), len(heap), flush=True)
while True:
    time.sleep(1)
"""
    target = subprocess.Popen(
        [sys.executable, "-c", target_code],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert target.stdout is not None
        ready = target.stdout.readline().split()
        assert ready[1] == "10000"
        arguments = cli.parser().parse_args(
            [
                "--pid",
                ready[0],
                "--file",
                str(output),
                "--agent",
                str(agent),
                "--loader",
                "ptrace",
                "--pydump-loader",
                str(loader),
                "--no-attribute",
                "--str-repr-len",
                "-1",
            ]
        )
        assert cli.run(arguments) == output
    finally:
        if target.poll() is None:
            target.terminate()
        target.wait(timeout=5)

    assert output.stat().st_size > 0


@pytest.mark.skipif(
    "PYDUMP_NATIVE_AGENT" not in os.environ
    or ("PYDUMP_GDB" not in os.environ and shutil.which("gdb") is None),
    reason="set a matching native Agent and install GDB or set PYDUMP_GDB",
)
def test_gdb_loader_captures_a_real_cpython_heap(tmp_path: Path) -> None:
    agent = Path(os.environ["PYDUMP_NATIVE_AGENT"]).resolve()
    gdb = Path(os.environ.get("PYDUMP_GDB") or shutil.which("gdb") or "").resolve()
    output = tmp_path / "gdb.pyheap"
    target_code = """
import ctypes
import os
import time

libc = ctypes.CDLL(None)
if libc.prctl(0x59616D61, -1, 0, 0, 0) != 0:
    raise RuntimeError("PR_SET_PTRACER_ANY failed")
heap = [{"index": index} for index in range(10_000)]
print(os.getpid(), len(heap), flush=True)
while True:
    time.sleep(1)
"""
    target = subprocess.Popen(
        [sys.executable, "-c", target_code],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert target.stdout is not None
        ready = target.stdout.readline().split()
        assert ready[1] == "10000"
        arguments = cli.parser().parse_args(
            [
                "--pid",
                ready[0],
                "--file",
                str(output),
                "--agent",
                str(agent),
                "--loader",
                "gdb",
                "--gdb",
                str(gdb),
                "--no-attribute",
                "--str-repr-len",
                "-1",
            ]
        )
        assert cli.run(arguments) == output
    finally:
        if target.poll() is None:
            target.terminate()
        target.wait(timeout=5)

    assert output.stat().st_size > 0


@pytest.mark.skipif(
    "PYDUMP_NATIVE_AGENT" not in os.environ,
    reason="set PYDUMP_NATIVE_AGENT to a native Agent built for this interpreter",
)
def test_native_object_facts_match_cpython_without_calling_application_code(
    tmp_path: Path,
) -> None:
    agent = Path(os.environ["PYDUMP_NATIVE_AGENT"]).resolve()
    nonce = os.urandom(16)
    resume_path = tmp_path / "resume"
    target_code = r"""
import ctypes
import inspect
import json
import os
import sys
import time
import weakref

class FixtureMeta(type):
    pass

class FixtureClass(metaclass=FixtureMeta):
    pass

class ApplicationMeta(type):
    calls = 0
    def __sizeof__(self):
        type(self).calls += 1
        return 234567

class ApplicationMetaSized(metaclass=ApplicationMeta):
    pass

class ApplicationSized:
    calls = 0
    def __sizeof__(self):
        type(self).calls += 1
        return 123456

def generator_function():
    yield None

async def coroutine_function():
    return None

async def async_generator_function():
    yield None

fixtures = {
    "dict": {"key": "value"},
    "list": [1, 2, 3],
    "set": {1, 2, 3},
    "frozenset": frozenset({1, 2, 3}),
    "str": "pydump-你好",
    "int": 2**130,
    "bool": True,
    "bytearray": bytearray(b"pydump"),
    "tuple": (1, 2, 3),
    "bytes": b"pydump",
    "generator": generator_function(),
    "coroutine": coroutine_function(),
    "async_generator": async_generator_function(),
    "frame": inspect.currentframe(),
    "code": generator_function.__code__,
    "type": FixtureClass,
    "weakref": weakref.ref(FixtureClass),
}
application_sized = ApplicationSized()
records = {
    label: {
        "address": id(value),
        "size": sys.getsizeof(value),
        "type_name": type(value).__name__,
    }
    for label, value in fixtures.items()
}
records["application_sized"] = {
    "address": id(application_sized),
    "type_name": type(application_sized).__name__,
}
records["application_meta_sized"] = {
    "address": id(ApplicationMetaSized),
    "type_name": type(ApplicationMetaSized).__name__,
}
print(json.dumps(records), flush=True)

agent = ctypes.CDLL(sys.argv[1])
start = agent.pydump_start
start.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
start.restype = ctypes.c_int
print(start(sys.argv[2].encode(), sys.argv[3].encode()), flush=True)
while not os.path.exists(sys.argv[4]):
    time.sleep(0.01)
print(f"{ApplicationSized.calls},{ApplicationMeta.calls}", flush=True)
"""

    with tempfile.TemporaryDirectory(prefix="pydump-facts-", dir="/tmp") as socket_directory:
        socket_path = Path(socket_directory) / "collector.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(10)
        target = subprocess.Popen(
            [
                sys.executable,
                "-c",
                target_code,
                str(agent),
                str(socket_path),
                nonce.hex(),
                str(resume_path),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert target.stdout is not None
            records = json.loads(target.stdout.readline())
            assert target.stdout.readline().strip() == "0"
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(30)
                objects = _request_objects(connection, nonce, records)
            resume_path.touch()
            assert target.stdout.readline().strip() == "0,0"
        finally:
            listener.close()
            if target.poll() is None:
                target.terminate()
            target.wait(timeout=5)

    for label, record in records.items():
        obj = objects[record["address"]]
        assert obj.type_name == record["type_name"], label
        if "size" in record:
            assert obj.shallow_size == record["size"], label
    assert objects[records["application_sized"]["address"]].shallow_size != 123456
    assert objects[records["application_meta_sized"]["address"]].shallow_size != 234567


def _request_objects(
    connection: socket.socket,
    nonce: bytes,
    records: dict[str, dict[str, int | str]],
) -> dict[int, HeapObject]:
    channel = FramedSocket(connection)
    hello_frame = channel.receive()
    assert hello_frame.kind is FrameKind.HELLO
    assert decode_hello(hello_frame.payload).nonce == nonce
    channel.send(FrameKind.HELLO_ACK, encode_options(-1, False))
    assert channel.receive().kind is FrameKind.WELL_KNOWN
    while channel.receive().kind is not FrameKind.ROOTS_DONE:
        pass

    addresses = [int(record["address"]) for record in records.values()]
    channel.send(FrameKind.REQUEST_OBJECTS, encode_addresses(addresses))
    objects = {}
    collector = Collector(nonce=nonce, str_repr_len=-1, dump_attributes=False)
    for address in addresses:
        obj = collector._receive_object(channel, address)
        objects[address] = obj
    assert channel.receive().kind is FrameKind.BATCH_DONE
    channel.send(FrameKind.FINISH)
    assert channel.receive().kind is FrameKind.COMPLETE
    return objects


def _capture_native(
    listener: socket.socket,
    socket_path: Path,
    agent: Path,
    nonce: bytes,
    target_code: str,
    tmp_path: Path,
) -> None:
    with listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(10)
        target = subprocess.Popen(
            [sys.executable, "-c", target_code, str(agent), str(socket_path), nonce.hex()],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert target.stdout is not None
            assert target.stdout.readline().strip() == "0"
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(30)
                output, count = Collector(
                    nonce=nonce,
                    str_repr_len=-1,
                    dump_attributes=False,
                ).capture(connection, tmp_path / "native.pyheap")
        except BaseException:
            target.poll()
            if target.stderr is not None:
                stderr = target.stderr.read()
                if stderr:
                    print(f"native target stderr:\n{stderr}", file=sys.stderr)
            raise
        finally:
            if target.poll() is None:
                target.terminate()
            target.wait(timeout=5)

    assert output.stat().st_size > 0
    assert count > 1_000
