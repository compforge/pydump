from __future__ import annotations

import os
import resource
import socket
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydump.errors import ProtocolError, PydumpError
from pydump.heap_writer import WELL_KNOWN_TYPE_NAMES, HeapWriter, validate_artifact
from pydump.model import ContentKind, HeapObject
from pydump.protocol import (
    NONCE_SIZE,
    Frame,
    FramedSocket,
    FrameKind,
    decode_addresses,
    decode_dict_entries,
    decode_hello,
    decode_object_begin,
    decode_text,
    encode_addresses,
    encode_options,
)

Progress = Callable[[int, int, float], None]


@dataclass
class CaptureStats:
    total_seconds: float = 0.0
    hello_wait_seconds: float = 0.0
    setup_seconds: float = 0.0
    roots_seconds: float = 0.0
    objects_seconds: float = 0.0
    finish_handshake_seconds: float = 0.0
    artifact_finalize_seconds: float = 0.0
    target_pause_seconds: float = 0.0
    object_count: int = 0
    referent_count: int = 0
    pending_peak: int = 0
    scheduled_peak: int = 0
    wire_sent_bytes: int = 0
    wire_received_bytes: int = 0
    wire_sent_frames: int = 0
    wire_received_frames: int = 0
    bulk_records: int = 0
    artifact_bytes: int = 0
    collector_max_rss_bytes: int = 0


class Collector:
    """Owns graph traversal and artifact state for one Agent connection."""

    def __init__(
        self,
        *,
        nonce: bytes,
        str_repr_len: int,
        dump_attributes: bool,
        batch_size: int = 256,
        progress: Progress | None = None,
    ) -> None:
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must contain {NONCE_SIZE} bytes")
        self._nonce = nonce
        self._str_repr_len = str_repr_len
        self._dump_attributes = dump_attributes
        self._batch_size = batch_size
        self._progress = progress
        self.stats: CaptureStats | None = None

    def capture(self, sock: socket.socket, output: Path) -> tuple[Path, int]:
        final_path = available_output_path(output)
        temporary = final_path.with_name(f".{final_path.name}.{self._nonce.hex()}.partial")
        started = time.monotonic()
        stats = CaptureStats()
        self.stats = stats
        channel = FramedSocket(sock)
        try:
            with temporary.open("xb") as file:
                count = self._capture(
                    channel,
                    HeapWriter(file, with_str_repr=self._str_repr_len >= 0),
                    started,
                    stats,
                )
            validate_artifact(temporary)
            os.replace(temporary, final_path)
            stats.artifact_bytes = final_path.stat().st_size
            return final_path, count
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        finally:
            stats.total_seconds = time.monotonic() - started
            stats.wire_sent_bytes = channel.stats.sent_bytes
            stats.wire_received_bytes = channel.stats.received_bytes
            stats.wire_sent_frames = channel.stats.sent_frames
            stats.wire_received_frames = channel.stats.received_frames
            stats.bulk_records = channel.stats.received_records
            stats.collector_max_rss_bytes = _max_rss_bytes()

    def _capture(
        self,
        channel: FramedSocket,
        writer: HeapWriter,
        started: float,
        stats: CaptureStats,
    ) -> int:
        hello = decode_hello(self._expect(channel, FrameKind.HELLO).payload)
        hello_received = time.monotonic()
        stats.hello_wait_seconds = hello_received - started
        if hello.nonce != self._nonce:
            raise ProtocolError("agent returned a different session nonce")
        if hello.python_major != 3 or hello.python_minor < 10:
            raise ProtocolError(
                "native agent reported unsupported CPython "
                f"{hello.python_major}.{hello.python_minor}"
            )
        if hello.pointer_size != 8:
            raise ProtocolError(f"unsupported target pointer size {hello.pointer_size}")
        if not hello.little_endian:
            raise ProtocolError("big-endian targets are not supported")
        channel.send(
            FrameKind.HELLO_ACK,
            encode_options(self._str_repr_len, self._dump_attributes),
        )

        well_known_addresses = decode_addresses(self._expect(channel, FrameKind.WELL_KNOWN).payload)
        if len(well_known_addresses) != len(WELL_KNOWN_TYPE_NAMES):
            raise ProtocolError(
                f"agent returned {len(well_known_addresses)} well-known types, "
                f"expected {len(WELL_KNOWN_TYPE_NAMES)}"
            )
        well_known_types = dict(zip(WELL_KNOWN_TYPE_NAMES, well_known_addresses, strict=True))
        writer.write_header(well_known_types)
        writer.write_threads([])
        writer.begin_objects()
        roots_started = time.monotonic()
        stats.setup_seconds = roots_started - hello_received

        scheduled: set[int] = set()
        pending: list[int] = []

        def schedule(addresses: list[int] | tuple[int, ...] | set[int]) -> None:
            for address in addresses:
                if address and address not in scheduled:
                    scheduled.add(address)
                    pending.append(address)
            stats.pending_peak = max(stats.pending_peak, len(pending))
            stats.scheduled_peak = max(stats.scheduled_peak, len(scheduled))

        while True:
            frame = channel.receive()
            if frame.kind is FrameKind.ROOT_BATCH:
                schedule(decode_addresses(frame.payload))
            elif frame.kind is FrameKind.ROOTS_DONE:
                break
            else:
                self._raise_unexpected(frame, "root enumeration")
        schedule(well_known_addresses)
        objects_started = time.monotonic()
        stats.roots_seconds = objects_started - roots_started

        types: dict[int, str] = dict(zip(well_known_addresses, WELL_KNOWN_TYPE_NAMES, strict=True))
        completed = 0
        while pending:
            batch = [pending.pop() for _ in range(min(self._batch_size, len(pending)))]
            channel.send(FrameKind.REQUEST_OBJECTS, encode_addresses(batch))
            for expected_address in batch:
                obj = self._receive_object(channel, expected_address)
                writer.write_object(obj, well_known_types)
                types[obj.type_address] = obj.type_name
                schedule(obj.referents)
                if obj.content_kind is ContentKind.DICT:
                    for key, value in obj.dict_content:
                        schedule((key, value))
                else:
                    schedule(obj.sequence_content)
                schedule(tuple(attribute.address for attribute in obj.attributes))
                schedule((obj.type_address,))
                completed += 1
                stats.object_count = completed
                stats.referent_count += len(obj.referents)
            self._expect(channel, FrameKind.BATCH_DONE)
            if self._progress is not None:
                self._progress(completed, len(pending), time.monotonic() - started)

        finish_started = time.monotonic()
        stats.objects_seconds = finish_started - objects_started
        channel.send(FrameKind.FINISH)
        self._expect(channel, FrameKind.COMPLETE)
        agent_completed = time.monotonic()
        stats.finish_handshake_seconds = agent_completed - finish_started
        stats.target_pause_seconds = agent_completed - hello_received
        writer.finish(types)
        stats.artifact_finalize_seconds = time.monotonic() - agent_completed
        return completed

    def _receive_object(self, channel: FramedSocket, expected_address: int) -> HeapObject:
        begin = decode_object_begin(self._expect(channel, FrameKind.OBJECT_BEGIN).payload)
        if begin.address != expected_address:
            raise ProtocolError(
                f"agent returned object 0x{begin.address:x}, expected 0x{expected_address:x}"
            )
        try:
            content_kind = ContentKind(begin.content_kind)
        except ValueError as error:
            raise ProtocolError(
                f"object 0x{begin.address:x} has unknown content kind {begin.content_kind}"
            ) from error

        obj = HeapObject(
            address=begin.address,
            type_address=begin.type_address,
            type_name=begin.type_name,
            shallow_size=begin.shallow_size,
            content_kind=content_kind,
        )
        while True:
            frame = channel.receive()
            if frame.kind is FrameKind.REFERENTS:
                obj.referents.update(decode_addresses(frame.payload))
            elif frame.kind is FrameKind.SEQUENCE_CONTENT:
                obj.sequence_content.extend(decode_addresses(frame.payload))
            elif frame.kind is FrameKind.DICT_CONTENT:
                obj.dict_content.extend(decode_dict_entries(frame.payload))
            elif frame.kind is FrameKind.PREVIEW:
                obj.str_repr = decode_text(frame.payload)
            elif frame.kind is FrameKind.WARNING:
                print(f"pydump agent warning: {decode_text(frame.payload)}", file=sys.stderr)
            elif frame.kind is FrameKind.OBJECT_END:
                if self._str_repr_len >= 0 and not obj.str_repr:
                    obj.str_repr = f"<{obj.type_name} at 0x{obj.address:x}>"[: self._str_repr_len]
                return obj
            else:
                self._raise_unexpected(frame, f"object 0x{expected_address:x}")

    @staticmethod
    def _expect(channel: FramedSocket, expected: FrameKind) -> Frame:
        frame = channel.receive()
        if frame.kind is FrameKind.ERROR:
            raise PydumpError(f"agent failed: {decode_text(frame.payload)}")
        if frame.kind is not expected:
            raise ProtocolError(f"expected {expected.name}, received {frame.kind.name}")
        return frame

    @staticmethod
    def _raise_unexpected(frame: Frame, stage: str) -> None:
        if frame.kind is FrameKind.ERROR:
            raise PydumpError(f"agent failed during {stage}: {decode_text(frame.payload)}")
        raise ProtocolError(f"received unexpected {frame.kind.name} during {stage}")


def available_output_path(requested: Path) -> Path:
    if not requested.exists():
        return requested
    index = 0
    while True:
        candidate = Path(f"{requested}.{index}")
        if not candidate.exists():
            return candidate
        index += 1


def _max_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)
