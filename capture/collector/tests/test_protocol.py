from __future__ import annotations

import socket

import pytest
from pydump.errors import ProtocolError
from pydump.protocol import (
    Frame,
    FramedSocket,
    FrameKind,
    Hello,
    decode_addresses,
    decode_hello,
    encode_addresses,
    encode_bulk_batch,
    encode_hello,
)


def test_frame_round_trip_survives_short_reads() -> None:
    left, right = socket.socketpair()
    try:
        sender = FramedSocket(left)
        receiver = FramedSocket(right)
        sender.send(FrameKind.ROOT_BATCH, encode_addresses([1, 2, 0xFFFF_FFFF_FFFF]))
        frame = receiver.receive()
    finally:
        left.close()
        right.close()

    assert frame.kind is FrameKind.ROOT_BATCH
    assert decode_addresses(frame.payload) == [1, 2, 0xFFFF_FFFF_FFFF]


def test_hello_round_trip() -> None:
    hello = Hello(3, 12, 8, True, b"n" * 16)
    assert decode_hello(encode_hello(hello)) == hello


def test_address_batch_rejects_partial_address() -> None:
    with pytest.raises(ProtocolError, match="invalid length"):
        decode_addresses(b"not-eight")


def test_bulk_batch_is_exposed_as_logical_records() -> None:
    left, right = socket.socketpair()
    try:
        sender = FramedSocket(left)
        receiver = FramedSocket(right)
        records = [
            Frame(FrameKind.OBJECT_BEGIN, b"begin"),
            Frame(FrameKind.REFERENTS, encode_addresses([1, 2])),
            Frame(FrameKind.OBJECT_END, b""),
        ]
        sender.send(FrameKind.BULK_BATCH, encode_bulk_batch(records))
        received = [receiver.receive() for _ in records]
    finally:
        left.close()
        right.close()

    assert received == records
    assert receiver.stats.received_frames == 1
    assert receiver.stats.received_records == 3


def test_bulk_batch_rejects_control_records() -> None:
    with pytest.raises(ProtocolError, match="not a bulk record"):
        encode_bulk_batch([Frame(FrameKind.COMPLETE, b"")])


@pytest.mark.parametrize("payload", [b"\x07", b"\x07\x00\x00\x00\x02x"])
def test_bulk_batch_rejects_partial_records(payload: bytes) -> None:
    left, right = socket.socketpair()
    try:
        sender = FramedSocket(left)
        receiver = FramedSocket(right)
        sender.send(FrameKind.BULK_BATCH, payload)
        with pytest.raises(ProtocolError, match="partial record"):
            receiver.receive()
    finally:
        left.close()
        right.close()
