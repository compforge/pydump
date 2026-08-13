from __future__ import annotations

import argparse
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

from pydump.collector import CaptureStats, Collector
from pydump.errors import PydumpError
from pydump.injector import inject, install_agent
from pydump.target import resolve_target, verify_agent


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Dump a live CPython heap.", allow_abbrev=False)
    target = result.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", "-p", type=int, help="target process PID")
    target.add_argument("--docker-container", help="target Docker container")
    result.add_argument("--file", "-f", type=Path, required=True, help="heap file name")
    result.add_argument(
        "--str-repr-len",
        type=_str_repr_length,
        default=1000,
        help="max safe string preview length (-1 disables it)",
    )
    result.add_argument(
        "--no-attribute",
        action="store_true",
        help="do not dump statically readable object attributes",
    )
    result.add_argument(
        "--ignore-compatibility-checks",
        action="store_true",
        help="reserved for PyHeap CLI compatibility; unsafe ABI checks remain mandatory",
    )
    result.add_argument(
        "--force-shadow",
        action="store_true",
        help="reserved for PyHeap CLI compatibility",
    )
    result.add_argument(
        "--agent",
        type=Path,
        default=None,
        help="native agent shared library built for the target CPython minor",
    )
    result.add_argument("--timeout", type=float, default=30.0, help=argparse.SUPPRESS)
    return result


def run(arguments: argparse.Namespace) -> Path:
    if sys.platform != "linux":
        raise PydumpError("live capture is supported only on Linux glibc hosts")
    target = resolve_target(arguments.pid, arguments.docker_container)
    agent = arguments.agent or _bundled_agent(target.python_minor)
    verify_agent(agent, target)
    _, agent_target_path = install_agent(target, agent)

    nonce = os.urandom(16)
    with tempfile.TemporaryDirectory(prefix="pydump-", dir=target.root / "tmp") as host_temp:
        uid, gid = target.fs_owner
        os.chown(host_temp, uid, gid)
        os.chmod(host_temp, 0o700)
        target_temp = f"/tmp/{Path(host_temp).name}"
        socket_target_path = f"{target_temp}/collector.sock"
        socket_host_path = Path(host_temp) / "collector.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_host_path))
            os.chown(socket_host_path, uid, gid)
            listener.listen(1)
            listener.settimeout(arguments.timeout)
            injection_error: list[BaseException] = []
            attach_started = time.monotonic()

            def attach() -> None:
                try:
                    inject(
                        target=target,
                        agent_target_path=agent_target_path,
                        socket_target_path=socket_target_path,
                        nonce=nonce,
                        timeout=arguments.timeout,
                    )
                except BaseException as error:
                    injection_error.append(error)

            thread = threading.Thread(target=attach, name="pydump-gdb", daemon=True)
            thread.start()
            try:
                connection, _ = listener.accept()
            except TimeoutError as error:
                if injection_error:
                    raise injection_error[0] from error
                raise PydumpError(
                    f"agent for PID {target.host_pid} did not connect within {arguments.timeout:g}s"
                ) from error
            with connection:
                connection.settimeout(arguments.timeout)
                started = time.monotonic()

                def progress(done: int, remain: int, elapsed: float) -> None:
                    print(
                        f"{elapsed:.2f} seconds passed, {done} objects done, "
                        f"{remain} remain (more may be added)",
                        end="\r",
                        flush=True,
                    )

                collector = Collector(
                    nonce=nonce,
                    str_repr_len=arguments.str_repr_len,
                    dump_attributes=not arguments.no_attribute,
                    progress=progress,
                )
                path, count = collector.capture(connection, arguments.file)
                stats = collector.stats
            thread.join(arguments.timeout)
            if injection_error:
                # Collector has already validated and atomically published this artifact.
                # Injector teardown failures must not delete a successfully delivered result.
                raise injection_error[0]
            print()
            print(f"Heap file saved: {path} ({count} objects, {time.monotonic() - started:.2f}s)")
            if stats is not None:
                _print_stats(stats, attach_seconds=started - attach_started)
            return path


def main() -> None:
    try:
        run(parser().parse_args())
    except KeyboardInterrupt:
        print("pydump interrupted", file=sys.stderr)
        raise SystemExit(130) from None
    except PydumpError as error:
        print(f"pydump failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None


def _str_repr_length(value: str) -> int:
    parsed = int(value)
    if parsed < -1:
        raise argparse.ArgumentTypeError("string preview length must be -1 or non-negative")
    return parsed


def _bundled_agent(version: tuple[int, int]) -> Path:
    machine = os.uname().machine
    name = f"pydump-agent-{version[0]}.{version[1]}-{machine}.so"
    candidate = Path(__file__).with_name("agents") / name
    if not candidate.exists():
        raise PydumpError(f"no bundled agent {name}; pass --agent with a matching build")
    return candidate


def _print_stats(stats: CaptureStats, *, attach_seconds: float) -> None:
    object_rate = stats.object_count / stats.objects_seconds if stats.objects_seconds else 0.0
    wire_rate = (
        stats.wire_received_bytes / stats.target_pause_seconds / (1 << 20)
        if stats.target_pause_seconds
        else 0.0
    )
    print(
        "Capture profile: "
        f"attach={attach_seconds:.2f}s, hello-wait={stats.hello_wait_seconds:.2f}s, "
        f"setup={stats.setup_seconds:.2f}s, roots={stats.roots_seconds:.2f}s, "
        f"objects={stats.objects_seconds:.2f}s, target-pause≈{stats.target_pause_seconds:.2f}s, "
        f"finalize={stats.artifact_finalize_seconds:.2f}s"
    )
    print(
        "Capture throughput: "
        f"{object_rate:,.0f} objects/s, {wire_rate:.1f} MiB/s wire, "
        f"{stats.referent_count:,} referents, "
        f"{stats.wire_received_frames:,} received frames, "
        f"{stats.wire_sent_frames:,} sent frames, {stats.bulk_records:,} bulk records"
    )
    print(
        "Collector peaks: "
        f"pending={stats.pending_peak:,}, scheduled={stats.scheduled_peak:,}, "
        f"max-rss={stats.collector_max_rss_bytes / (1 << 20):.1f} MiB, "
        f"artifact={stats.artifact_bytes / (1 << 20):.1f} MiB"
    )
