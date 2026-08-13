from __future__ import annotations

import argparse
import ctypes
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from pydump.collector import Collector


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Benchmark native Agent heap streaming.")
    result.add_argument("--objects", type=int, default=1_000_000)
    result.add_argument("--agent", type=Path, required=True)
    result.add_argument("--target", action="store_true", help=argparse.SUPPRESS)
    result.add_argument("--socket", type=Path, help=argparse.SUPPRESS)
    result.add_argument("--nonce", help=argparse.SUPPRESS)
    return result


def run_target(objects: int, agent_path: Path, socket_path: Path, nonce: str) -> None:
    heap = [{"value": index, "next": None} for index in range(objects)]
    print(f"ready {os.getpid()} {len(heap)}", flush=True)
    if not sys.stdin.readline():
        raise RuntimeError("Collector closed before starting the Agent")
    agent = ctypes.CDLL(str(agent_path))
    start = agent.pydump_start
    start.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    start.restype = ctypes.c_int
    result = start(str(socket_path).encode(), nonce.encode())
    print(f"started {result}", flush=True)
    while True:
        time.sleep(60)


def read_rss_bytes(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError(f"VmRSS missing for PID {pid}")


def benchmark(objects: int, agent: Path) -> None:
    nonce = os.urandom(16)
    with tempfile.TemporaryDirectory(prefix="pydump-native-benchmark-", dir="/tmp") as directory:
        socket_path = Path(directory) / "collector.sock"
        output = Path(directory) / "heap.pyheap"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            listener.listen(1)
            listener.settimeout(30)
            target = subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "--target",
                    "--objects",
                    str(objects),
                    "--agent",
                    str(agent),
                    "--socket",
                    str(socket_path),
                    "--nonce",
                    nonce.hex(),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert target.stdin is not None
            assert target.stdout is not None
            ready = target.stdout.readline().split()
            if ready[:1] != ["ready"]:
                stderr = target.stderr.read() if target.stderr is not None else ""
                raise RuntimeError(f"target failed to start: {ready!r} {stderr}")
            pid = int(ready[1])
            before = read_rss_bytes(pid)
            peak = before
            stop = threading.Event()

            def sample_rss() -> None:
                nonlocal peak
                while not stop.wait(0.01):
                    try:
                        peak = max(peak, read_rss_bytes(pid))
                    except FileNotFoundError:
                        return

            sampler = threading.Thread(target=sample_rss)
            sampler.start()
            try:
                target.stdin.write("start\n")
                target.stdin.flush()
                if target.stdout.readline().strip() != "started 0":
                    raise RuntimeError("native Agent failed to start")
                connection, _ = listener.accept()
                started = time.perf_counter()
                collector = Collector(
                    nonce=nonce,
                    str_repr_len=-1,
                    dump_attributes=False,
                )
                with connection:
                    connection.settimeout(30)
                    path, count = collector.capture(connection, output)
                elapsed = time.perf_counter() - started
                stats = getattr(collector, "stats", None)
                if stats is None:
                    print(f"Native capture: objects={count:,}, wall={elapsed:.2f}s")
                else:
                    print(
                        f"Native capture: objects={count:,}, wall={elapsed:.2f}s, "
                        f"target-pause≈{stats.target_pause_seconds:.2f}s, "
                        f"rate={count / stats.objects_seconds:,.0f} objects/s, "
                        f"wire={stats.wire_received_bytes / (1 << 20):.1f} MiB, "
                        f"frames={stats.wire_received_frames:,}, records={stats.bulk_records:,}"
                    )
                print(
                    f"Memory: target-rss={before / (1 << 20):.1f} MiB, "
                    f"target-rss-delta={max(0, peak - before) / (1 << 20):.1f} MiB, "
                    f"artifact={path.stat().st_size / (1 << 20):.1f} MiB"
                )
                if stats is not None:
                    print(f"Collector max RSS: {stats.collector_max_rss_bytes / (1 << 20):.1f} MiB")
            finally:
                stop.set()
                sampler.join()
                target.terminate()
                target.wait(timeout=5)


def main() -> None:
    arguments = parser().parse_args()
    if arguments.target:
        if arguments.socket is None or arguments.nonce is None:
            raise ValueError("target mode requires --socket and --nonce")
        run_target(
            arguments.objects,
            arguments.agent.resolve(),
            arguments.socket,
            arguments.nonce,
        )
    else:
        benchmark(arguments.objects, arguments.agent.resolve())


if __name__ == "__main__":
    main()
