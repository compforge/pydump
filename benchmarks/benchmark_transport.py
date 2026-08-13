from __future__ import annotations

import argparse
import socket
import statistics
import threading
import time


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Measure local Unix socket throughput.")
    result.add_argument("--mib", type=int, default=1024, help="MiB transferred per attempt")
    result.add_argument("--attempts", type=int, default=5)
    return result


def measure(*, total: int, block_size: int) -> float:
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    payload = bytes(block_size)
    receive_buffer = bytearray(1 << 20)
    received = 0

    def drain() -> None:
        nonlocal received
        view = memoryview(receive_buffer)
        while received < total:
            count = receiver.recv_into(view)
            if count == 0:
                break
            received += count

    thread = threading.Thread(target=drain)
    thread.start()
    started = time.perf_counter()
    remaining = total
    while remaining:
        count = min(block_size, remaining)
        sender.sendall(payload[:count])
        remaining -= count
    sender.shutdown(socket.SHUT_WR)
    thread.join()
    elapsed = time.perf_counter() - started
    sender.close()
    receiver.close()
    if received != total:
        raise RuntimeError(f"received {received} bytes, expected {total}")
    return total / elapsed / (1 << 20)


def main() -> None:
    arguments = parser().parse_args()
    total = arguments.mib << 20
    for block_size in (32 << 10, 128 << 10, 512 << 10, 1 << 20):
        rates = [measure(total=total, block_size=block_size) for _ in range(arguments.attempts)]
        print(
            f"{block_size // 1024:4d} KiB: median={statistics.median(rates):8.1f} MiB/s "
            f"range={min(rates):.1f}-{max(rates):.1f}"
        )


if __name__ == "__main__":
    main()
