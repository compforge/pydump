from __future__ import annotations

import socket

import pytest

from pydump.errors import ProtocolError
from pydump.protocol import (
    FramedSocket,
    FrameKind,
    Hello,
    decode_addresses,
    decode_hello,
    encode_addresses,
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
