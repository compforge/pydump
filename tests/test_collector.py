from __future__ import annotations

import socket
import threading
from pathlib import Path

from pydump.collector import Collector
from pydump.heap_writer import MAGIC, WELL_KNOWN_TYPE_NAMES
from pydump.model import ContentKind
from pydump.protocol import (
    FramedSocket,
    FrameKind,
    Hello,
    ObjectBegin,
    decode_addresses,
    encode_addresses,
    encode_hello,
    encode_object_begin,
)


def test_collector_owns_graph_walk_and_delivers_artifact(tmp_path: Path) -> None:
    collector_socket, agent_socket = socket.socketpair()
    nonce = b"session-nonce-12"
    known = {name: 0x1000 + index for index, name in enumerate(WELL_KNOWN_TYPE_NAMES)}
    objects = {
        0x2000: ObjectBegin(0x2000, known["list"], 48, ContentKind.LIST, "list"),
        0x3000: ObjectBegin(0x3000, known["object"], 16, ContentKind.NONE, "object"),
    }

    def fake_agent() -> None:
        channel = FramedSocket(agent_socket)
        channel.send(FrameKind.HELLO, encode_hello(Hello(3, 12, 8, True, nonce)))
        assert channel.receive().kind is FrameKind.HELLO_ACK
        channel.send(FrameKind.WELL_KNOWN, encode_addresses(list(known.values())))
        channel.send(FrameKind.ROOT_BATCH, encode_addresses([0x2000]))
        channel.send(FrameKind.ROOTS_DONE)

        while True:
            frame = channel.receive()
            if frame.kind is FrameKind.FINISH:
                channel.send(FrameKind.COMPLETE)
                return
            for address in decode_addresses(frame.payload):
                begin = objects.get(
                    address,
                    ObjectBegin(address, known["type"], 16, ContentKind.NONE, "type"),
                )
                channel.send(FrameKind.OBJECT_BEGIN, encode_object_begin(begin))
                if address == 0x2000:
                    channel.send(FrameKind.SEQUENCE_CONTENT, encode_addresses([0x3000]))
                    channel.send(FrameKind.REFERENTS, encode_addresses([0x3000]))
                channel.send(FrameKind.OBJECT_END)
            channel.send(FrameKind.BATCH_DONE)

    thread = threading.Thread(target=fake_agent)
    thread.start()
    try:
        output, count = Collector(
            nonce=nonce,
            str_repr_len=-1,
            dump_attributes=False,
        ).capture(collector_socket, tmp_path / "heap.pyheap")
    finally:
        collector_socket.close()
        agent_socket.close()
        thread.join()

    assert count >= 2
    assert output.exists()
    assert int.from_bytes(output.read_bytes()[-8:], "big") == MAGIC
    assert not list(tmp_path.glob("*.partial"))
