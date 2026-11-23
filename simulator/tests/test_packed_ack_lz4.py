"""Independent compression never changes the canonical source retained for repair."""
import pytest

from l2tunnel_sim.compact import tcp_profile_frame
from l2tunnel_sim.packed_ack_lz4 import ShortAckBlocks


def unit(record, payload=0, flags=0x10):
    frame = tcp_profile_frame(identification=record, acknowledged=record * 512,
                              payload_bytes=payload, flags=flags)
    return b"\x00" + record.to_bytes(2, "big") + b"\x02" + len(frame).to_bytes(2, "big") + frame


def packed(*units):
    return bytes([255, len(units)]) + b"".join(len(u).to_bytes(2, "big") + u for u in units)


def test_independent_ack_source_round_trips_and_mixed_data_falls_back():
    codec = ShortAckBlocks(1460, 128, 16)
    original = packed(*(unit(i) for i in range(8)))
    wire = codec.encode(original)
    assert wire[0] == codec.marker and len(wire) < len(original)
    assert int.from_bytes(wire[1:3], "big") == len(original)
    assert ShortAckBlocks(1460, 128, 16).decode(wire) == original
    for mixed in (packed(unit(1), unit(2, payload=1)), packed(unit(1), unit(2, flags=0x11))):
        assert codec.encode(mixed) == mixed
        assert codec.decode(mixed) == mixed


def test_invalid_compressed_sources_cannot_supply_recovery_bytes():
    codec = ShortAckBlocks(1460, 128, 16)
    original = packed(*(unit(i) for i in range(4)))
    wire = codec.encode(original)
    mixed = packed(unit(0), unit(1, payload=16))
    encoded_mixed = bytes([codec.marker]) + len(mixed).to_bytes(2, "big") + codec.block.compress(
        mixed, store_size=False)
    for invalid in (wire[:-1], bytes([codec.marker, 5, 181]) + wire[3:], encoded_mixed, b""):
        with pytest.raises(ValueError):
            codec.decode(invalid)
