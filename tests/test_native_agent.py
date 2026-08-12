from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from pydump.collector import Collector


@pytest.mark.skipif(
    "PYDUMP_NATIVE_AGENT" not in os.environ,
    reason="set PYDUMP_NATIVE_AGENT to a native Agent built for this interpreter",
)
def test_native_agent_streams_a_real_cpython_heap(tmp_path: Path) -> None:
    agent = Path(os.environ["PYDUMP_NATIVE_AGENT"]).resolve()
    nonce = os.urandom(16)
    target_code = """
import ctypes
import sys
import time

agent = ctypes.CDLL(sys.argv[1])
start = agent.pydump_start
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
