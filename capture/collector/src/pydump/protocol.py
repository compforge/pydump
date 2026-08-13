from __future__ import annotations

import socket
import struct
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from pydump.errors import ProtocolError

MAGIC: Final = b"PYDP"
VERSION: Final = 2
NONCE_SIZE: Final = 16
MAX_PAYLOAD: Final = 1 << 20
ADDRESS_SIZE: Final = 8
BULK_PAYLOAD_SIZE: Final = 32 << 10

_HEADER = struct.Struct("!4sBBHI")
_RECORD_HEADER = struct.Struct("!BI")
_HELLO = struct.Struct("!BBBB16s")
_OPTIONS = struct.Struct("!iB")
_OBJECT_BEGIN = struct.Struct("!QQIBH")


class FrameKind(IntEnum):
    HELLO = 1
    HELLO_ACK = 2
    WELL_KNOWN = 3
    ROOT_BATCH = 4
    ROOTS_DONE = 5
    REQUEST_OBJECTS = 6
    OBJECT_BEGIN = 7
    REFERENTS = 8
    SEQUENCE_CONTENT = 9
    DICT_CONTENT = 10
    ATTRIBUTES = 11
    PREVIEW = 12
    OBJECT_END = 13
    BATCH_DONE = 14
    FINISH = 15
    COMPLETE = 16
    ERROR = 17
    WARNING = 18
    CANCEL = 19
    BULK_BATCH = 20


_BULK_RECORD_KINDS: Final = frozenset(
    {
        FrameKind.ROOT_BATCH,
        FrameKind.OBJECT_BEGIN,
        FrameKind.REFERENTS,
        FrameKind.SEQUENCE_CONTENT,
        FrameKind.DICT_CONTENT,
        FrameKind.ATTRIBUTES,
        FrameKind.PREVIEW,
        FrameKind.OBJECT_END,
        FrameKind.WARNING,
    }
)


@dataclass(frozen=True)
class Frame:
    kind: FrameKind
    payload: bytes


@dataclass(frozen=True)
class Hello:
    python_major: int
    python_minor: int
    pointer_size: int
    little_endian: bool
    nonce: bytes


@dataclass(frozen=True)
class ObjectBegin:
    address: int
    type_address: int
    shallow_size: int
    content_kind: int
    type_name: str


@dataclass
class SocketStats:
    sent_bytes: int = 0
    received_bytes: int = 0
    sent_frames: int = 0
    received_frames: int = 0
    received_records: int = 0


class FramedSocket:
    """Length-delimited Agent protocol with strict frame and payload validation."""

    def __init__(self, sock: socket.socket) -> None:
        self._socket = sock
        self._pending: deque[Frame] = deque()
        self.stats = SocketStats()

    def send(self, kind: FrameKind, payload: bytes = b"") -> None:
        if len(payload) > MAX_PAYLOAD:
            raise ProtocolError(f"{kind.name} payload exceeds {MAX_PAYLOAD} bytes")
        wire = _HEADER.pack(MAGIC, VERSION, kind, 0, len(payload)) + payload
        self._socket.sendall(wire)
        self.stats.sent_bytes += len(wire)
        self.stats.sent_frames += 1

    def receive(self) -> Frame:
        if self._pending:
            return self._pending.popleft()
        frame = self._receive_wire_frame()
        if frame.kind is not FrameKind.BULK_BATCH:
            return frame
        records = decode_bulk_batch(frame.payload)
        if not records:
            raise ProtocolError("BULK_BATCH must contain at least one record")
        self.stats.received_records += len(records)
        self._pending.extend(records)
        return self._pending.popleft()

    def _receive_wire_frame(self) -> Frame:
        header = self._receive_exact(_HEADER.size)
        magic, version, raw_kind, flags, payload_size = _HEADER.unpack(header)
        if magic != MAGIC:
            raise ProtocolError(f"invalid protocol magic {magic!r}")
        if version != VERSION:
            raise ProtocolError(f"unsupported protocol version {version}")
        if flags != 0:
            raise ProtocolError(f"unsupported frame flags {flags}")
        if payload_size > MAX_PAYLOAD:
            raise ProtocolError(f"frame payload {payload_size} exceeds {MAX_PAYLOAD} bytes")
        try:
            kind = FrameKind(raw_kind)
        except ValueError as error:
            raise ProtocolError(f"unknown frame kind {raw_kind}") from error
        payload = self._receive_exact(payload_size)
        self.stats.received_bytes += _HEADER.size + payload_size
        self.stats.received_frames += 1
        return Frame(kind=kind, payload=payload)

    def _receive_exact(self, size: int) -> bytes:
        chunks = bytearray(size)
        view = memoryview(chunks)
        received = 0
        while received < size:
            count = self._socket.recv_into(view[received:])
            if count == 0:
                raise ProtocolError(f"agent disconnected with {size - received} bytes pending")
            received += count
        return bytes(chunks)


def encode_bulk_batch(records: list[Frame] | tuple[Frame, ...]) -> bytes:
    payload = bytearray()
    for record in records:
        if record.kind not in _BULK_RECORD_KINDS:
            raise ProtocolError(f"{record.kind.name} is not a bulk record")
        payload.extend(_RECORD_HEADER.pack(record.kind, len(record.payload)))
        payload.extend(record.payload)
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"BULK_BATCH payload exceeds {MAX_PAYLOAD} bytes")
    return bytes(payload)


def decode_bulk_batch(payload: bytes) -> list[Frame]:
    """Decode bounded wire aggregation while preserving logical record order."""
    records: list[Frame] = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < _RECORD_HEADER.size:
            raise ProtocolError("BULK_BATCH ends in a partial record header")
        raw_kind, record_size = _RECORD_HEADER.unpack_from(payload, offset)
        offset += _RECORD_HEADER.size
        end = offset + record_size
        if end > len(payload):
            raise ProtocolError("BULK_BATCH ends in a partial record payload")
        try:
            kind = FrameKind(raw_kind)
        except ValueError as error:
            raise ProtocolError(f"BULK_BATCH contains unknown record kind {raw_kind}") from error
        if kind not in _BULK_RECORD_KINDS:
            raise ProtocolError(f"BULK_BATCH contains invalid record {kind.name}")
        records.append(Frame(kind=kind, payload=payload[offset:end]))
        offset = end
    return records


def encode_hello(hello: Hello) -> bytes:
    if len(hello.nonce) != NONCE_SIZE:
        raise ProtocolError(f"session nonce must contain {NONCE_SIZE} bytes")
    return _HELLO.pack(
        hello.python_major,
        hello.python_minor,
        hello.pointer_size,
        hello.little_endian,
        hello.nonce,
    )


def decode_hello(payload: bytes) -> Hello:
    if len(payload) != _HELLO.size:
        raise ProtocolError(f"HELLO has invalid length {len(payload)}")
    major, minor, pointer_size, little_endian, nonce = _HELLO.unpack(payload)
    if little_endian not in (0, 1):
        raise ProtocolError(f"HELLO has invalid byte order marker {little_endian}")
    return Hello(major, minor, pointer_size, bool(little_endian), nonce)


def encode_options(str_repr_len: int, dump_attributes: bool) -> bytes:
    return _OPTIONS.pack(str_repr_len, dump_attributes)


def decode_options(payload: bytes) -> tuple[int, bool]:
    if len(payload) != _OPTIONS.size:
        raise ProtocolError(f"HELLO_ACK has invalid length {len(payload)}")
    str_repr_len, dump_attributes = _OPTIONS.unpack(payload)
    if dump_attributes not in (0, 1):
        raise ProtocolError("HELLO_ACK has invalid attribute marker")
    return str_repr_len, bool(dump_attributes)


def encode_addresses(addresses: list[int] | tuple[int, ...]) -> bytes:
    return struct.pack(f"!{len(addresses)}Q", *addresses)


def decode_addresses(payload: bytes) -> list[int]:
    if len(payload) % ADDRESS_SIZE:
        raise ProtocolError(f"address batch has invalid length {len(payload)}")
    count = len(payload) // ADDRESS_SIZE
    return list(struct.unpack(f"!{count}Q", payload)) if count else []


def decode_dict_entries(payload: bytes) -> list[tuple[int, int]]:
    addresses = decode_addresses(payload)
    if len(addresses) % 2:
        raise ProtocolError("dictionary batch has an odd address count")
    return list(zip(addresses[::2], addresses[1::2], strict=True))


def decode_object_begin(payload: bytes) -> ObjectBegin:
    if len(payload) < _OBJECT_BEGIN.size:
        raise ProtocolError(f"OBJECT_BEGIN has invalid length {len(payload)}")
    address, type_address, size, content_kind, name_size = _OBJECT_BEGIN.unpack_from(payload)
    type_name_bytes = payload[_OBJECT_BEGIN.size :]
    if len(type_name_bytes) != name_size:
        raise ProtocolError("OBJECT_BEGIN type name length does not match payload")
    return ObjectBegin(
        address=address,
        type_address=type_address,
        shallow_size=size,
        content_kind=content_kind,
        type_name=type_name_bytes.decode("utf-8", "backslashreplace"),
    )


def encode_object_begin(begin: ObjectBegin) -> bytes:
    name = begin.type_name.encode("utf-8", "backslashreplace")
    if len(name) > 0xFFFF:
        name = name[:0xFFFF]
    return (
        _OBJECT_BEGIN.pack(
            begin.address,
            begin.type_address,
            begin.shallow_size,
            begin.content_kind,
            len(name),
        )
        + name
    )


def decode_text(payload: bytes) -> str:
    return payload.decode("utf-8", "backslashreplace")
