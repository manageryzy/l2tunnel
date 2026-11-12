"""Byte-parsed compact transport, finite identifiers and charged framing."""

from functools import partial
from struct import pack
from types import SimpleNamespace
from zlib import crc32

import pytest

from l2tunnel_sim.coding import PRODUCT, INVERSE
from l2tunnel_sim.compact import CompactSource, coefficient, tcp_profile_frame
from l2tunnel_sim.compact_ack import CoalescedACKTCP
from l2tunnel_sim.compact_wire import (
    CompactWireConfig, CompactWireTransport, GLOBAL_WINDOW, ID_MODULUS,
    SYMBOL_BYTES, decode_packet, encode_repair, encode_source,
)
from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.shared_records import SharedRecordMultiFlow


def fixture(encapsulation='udp', ratio=0, jitter=0, trim=False, **config_options):
    packets = []
    sim = SimpleNamespace(now=0, scenario=Scenario(70, 0, mtu=1500), traffic=Traffic(),
                          links=[[SimpleNamespace(rtt=.07, jitter=jitter)]] * 2, at=lambda *args: None)
    def send(reverse, size, kind, receive):
        packets.append((reverse, size, kind, receive))
        return sim.now, .07
    sim.send = send
    transport = CompactWireTransport(sim, False, CompactWireConfig(
        repair_ratio=ratio, elide_payload_length=True, encapsulation=encapsulation,
        trim_repair_padding=trim, **config_options))
    return transport, packets


def submit(transport, sequence=0, identification=0, channel=0, delivered=None):
    frame = tcp_profile_frame(sequence=sequence, identification=identification, payload_bytes=64)
    transport.submit_channel(channel, len(frame), 64,
                             lambda: delivered.append(frame) if delivered is not None else None, frame=frame)
    return frame


@pytest.mark.parametrize('encapsulation', ['udp', 'raw_ipv4_crc32'])
def test_real_wire_fields_determine_support_and_seed(encapsulation):
    data = bytes(range(256)) * 5 + bytes(180)
    source = decode_packet(encode_source(32770, data, encapsulation), 32768, encapsulation)
    assert source.index == 32770 and source.payload == data
    local = decode_packet(encode_repair(32771, 17, data, encapsulation), 32768, encapsulation)
    assert (local.start, local.end, local.seed) == (32643, 32771, 17 * 2654435761 & 0xffffffff)
    global_packet = decode_packet(encode_repair(32771, 16, data, encapsulation), 32768, encapsulation)
    assert (global_packet.start, global_packet.end) == (24579, 32771)
    tail = decode_packet(encode_repair(32771, 5, data, encapsulation, tail=True, seed=918), 32768, encapsulation)
    assert (tail.kind, tail.start, tail.end, tail.seed) == ('tail', 24579, 32771, 918)


def test_source_wrap_and_bounded_reorder_are_unambiguous():
    for index in [32770, 32766, 32769, 32768]:
        wire = encode_source(index, b'abc')
        assert decode_packet(wire, 32768).index == index
    with pytest.raises(ValueError, match='window'):
        decode_packet(encode_source(32768 + GLOBAL_WINDOW, b'abc'), 32768)
    with pytest.raises(ValueError, match='window'):
        decode_packet(encode_repair(32768 + GLOBAL_WINDOW + 1, 1, bytes(SYMBOL_BYTES)), 32768)


def test_serial_wrap_is_wire_defined_and_preserves_global_slot():
    packet = decode_packet(encode_repair(100, ID_MODULUS, bytes(SYMBOL_BYTES)), 0)
    assert packet.serial == packet.seed == packet.start == 0
    assert packet.end == 100
    next_packet = decode_packet(encode_repair(200, ID_MODULUS + 1, bytes(SYMBOL_BYTES)), 100)
    assert next_packet.serial == 1 and next_packet.start == 72


@pytest.mark.parametrize('is_repair', [False, True])
def test_raw_crc_covers_metadata_payload_and_crc_field(is_repair):
    wire = (encode_repair(1, 1, bytes(SYMBOL_BYTES), 'raw_ipv4_crc32') if is_repair
            else encode_source(0, b'actual source bytes', 'raw_ipv4_crc32'))
    for offset in [0, len(wire)//2, len(wire)-1]:
        corrupted = bytearray(wire)
        corrupted[offset] ^= 1
        with pytest.raises(ValueError, match='CRC'):
            decode_packet(corrupted, 0, 'raw_ipv4_crc32')


def test_numeric_gf_repair_and_crc_preserve_subtractable_known_columns():
    first, second = bytes((i * 7) % 256 for i in range(SYMBOL_BYTES)), bytes((i * 13 + 3) % 256 for i in range(SYMBOL_BYTES))
    serial = 16
    seed = serial * 2654435761 & 0xffffffff
    a, b = coefficient(seed, 0), coefficient(seed, 1)
    assert b
    repair = bytes(PRODUCT[a][x] ^ PRODUCT[b][y] for x, y in zip(first, second))
    packet = decode_packet(encode_repair(2, serial, repair, 'raw_ipv4_crc32'), 1, 'raw_ipv4_crc32')
    assert packet.start == 0 and packet.end == 2
    recovered = bytes(PRODUCT[INVERSE[b]][value ^ PRODUCT[a][known]] for value, known in zip(packet.payload, first))
    assert recovered == second


@pytest.mark.parametrize('encapsulation,source_header,regular_size,tail_size', [
    ('udp', 30, 1492, 1500), ('raw_ipv4_crc32', 26, 1488, 1496)])
def test_packet_accounting_retains_full_repair_extent(encapsulation, source_header, regular_size, tail_size):
    transport, packets = fixture(encapsulation, .5)
    submit(transport)
    transport._repair(True)
    sources = [size for _, size, kind, _ in packets if kind == 'source']
    repairs = [size for _, size, kind, _ in packets if kind == 'repair']
    assert sources == [source_header + item.size for item in transport.sources]
    assert repairs == [regular_size, tail_size]
    assert transport.wire_header_bytes == 2 * len(sources) + 4 + 12
    assert transport.wire_crc_bytes == (4 * len(packets) if encapsulation == 'raw_ipv4_crc32' else 0)
    assert transport.symbol_bytes == 1460


def test_lost_sources_recover_from_parsed_tail_repairs():
    transport, packets = fixture('raw_ipv4_crc32')
    delivered = []
    expected = submit(transport, delivered=delivered)
    # Both original source packets are withheld. Actual tail metadata supplies
    # the complete support and seed to the rank model.
    for _ in range(8):
        transport._repair(True)
        packets[-1][3]()
        if delivered:
            break
    assert delivered == [expected]
    assert transport.received_prefix == len(transport.sources)
    assert not transport.received_source
    assert not transport.wire_invalid_packets


def test_received_source_uses_its_crc_checked_wire_payload():
    transport, packets = fixture('raw_ipv4_crc32')
    delivered = []
    expected = submit(transport, delivered=delivered)
    for packet in list(packets):
        packet[3]()
    assert delivered == [expected]
    assert not transport.wire_received_symbols
    wire = bytearray(encode_source(0, b'invalid', 'raw_ipv4_crc32'))
    wire[-1] ^= 1
    transport._receive_wire(wire)
    assert transport.wire_invalid_packets == 1


def test_acknowledged_sources_are_retained_for_fixed_global_support():
    transport, _ = fixture()
    count = GLOBAL_WINDOW + 100
    transport.sources = [CompactSource(i, 1, i+1) for i in range(count)]
    transport.source_payloads = [b'x'] * count
    transport._receive_feedback(500, 0)
    assert all(value is None for value in transport.source_payloads[:100])
    assert all(value == b'x' for value in transport.source_payloads[100:])
    assert transport.source_payloads[499] == b'x'
    assert transport.wire_retained_start == 100
    transport.base = 99
    with pytest.raises(ValueError, match='unconfirmed'):
        transport._prune_sender_payloads()


@pytest.mark.parametrize('encapsulation', ['udp', 'raw_ipv4_crc32'])
@pytest.mark.parametrize('loss', [0, .15])
@pytest.mark.parametrize('packed', [False, True])
@pytest.mark.parametrize('trim', [False, True])
def test_normal_shared_tcp_entry_confirms_original_cohort_and_exact_wire_bytes(encapsulation, loss, packed, trim):
    config = CompactWireConfig(repair_ratio=.22, feedback_ms=1, encapsulation=encapsulation,
                               elide_payload_length=True, packed_predictive_records=packed,
                               trim_repair_padding=trim)
    factory = partial(CoalescedACKTCP, compact_config=config, ack_copies=3, ack_coalesce_ms=.25,
                      acknowledged_segment_slow_start=True)
    sim = SharedRecordMultiFlow(
        Scenario(20, loss), Traffic(duration_s=.03, drain_s=3, payload_bytes=1448,
             frame_bytes=1514, window_bytes=32768, frame_interval_ms=1),
        (PathConfig(10, 10),), Strategy('compact wire', mode='tcp', tcp_rto_min_ms=1000), 42, 4,
        compact_config=config, simulation_factory=factory, transport_type=CompactWireTransport)
    sim.run()
    shared = sim.shared_forward
    assert all(flow.tcp_received == flow.tcp_acked == len(flow.sent_times) for flow in sim.flows)
    assert shared.base == len(shared.sources)
    assert not shared.buffer_bytes and not shared.callbacks and not shared.wire_invalid_packets
    row = sim.measurements()
    assert row['forward_source_bytes'] == sum(shared.source_header + source.size for source in shared.sources)
    full_repair_bytes = (shared.scheduled_repairs * (shared.repair_header + SYMBOL_BYTES)
        + shared.tail_repairs * (shared.ip_header_bytes + shared.crc_bytes + 12 + SYMBOL_BYTES))
    assert row['forward_repair_bytes'] == full_repair_bytes - shared.wire_trimmed_repair_bytes
    assert bool(shared.wire_trimmed_repair_bytes) == trim
    assert row['reverse_source_bytes'] == row['reverse_source_datagrams'] * 102
    assert shared.wire_retained_peak_symbols <= GLOBAL_WINDOW
    assert bool(shared.packed_predictive_records) == packed


def test_unsupported_window_configuration_is_explicit():
    for fields in [{'block_sources': 16384}, {'repair_window_sources': 256}, {'global_repair_every': 4}, {'authentication_bytes': 16}]:
        with pytest.raises(ValueError):
            CompactWireConfig(**fields)


def test_forward_jitter_requires_a_different_identifier_contract():
    with pytest.raises(ValueError, match='zero forward-path jitter'):
        fixture(jitter=.001)


def test_receiver_support_uses_received_fields_after_sender_state_changes():
    transport, _ = fixture()
    rows = []
    transport.decoder.insert = lambda row: rows.append(row) or []
    transport._new_known = lambda solved: None
    transport._advance = lambda: None
    wire = encode_repair(4, 16, bytes(SYMBOL_BYTES))
    transport.base, transport.repair_serial = 999, 887
    transport._receive_wire(wire)
    expected_seed = 16 * 2654435761 & 0xffffffff
    assert rows == [{index: coefficient(expected_seed, index) for index in range(4)}]


def test_admission_cannot_expire_an_original_unknown_source():
    transport, _ = fixture()
    transport.sources = [None] * GLOBAL_WINDOW
    with pytest.raises(ValueError, match='admission'):
        transport._aligned_source(b'new source')


@pytest.mark.parametrize('value', [0, 1, None, 'true', [], {}])
def test_trim_option_requires_a_boolean(value):
    with pytest.raises(ValueError, match='must be boolean'):
        CompactWireConfig(trim_repair_padding=value)


@pytest.mark.parametrize('encapsulation', ['udp', 'raw_ipv4_crc32'])
@pytest.mark.parametrize('tail', [False, True])
@pytest.mark.parametrize('extent', [1, 72, 1454, 1460])
def test_short_repair_wire_length_zero_extends_after_parsing(encapsulation, tail, extent):
    data = bytes(i % 256 for i in range(extent))
    wire = encode_repair(400, 16, data, encapsulation, tail=tail, seed=39 if tail else None)
    packet = decode_packet(wire, 300, encapsulation)
    assert len(wire) == (12 if tail else 4) + extent + (4 if encapsulation == 'raw_ipv4_crc32' else 0)
    assert packet.payload == data + bytes(SYMBOL_BYTES - extent)
    assert (packet.start, packet.end, packet.serial) == (0, 400, 16)
    assert packet.seed == (39 if tail else 16 * 2654435761 & 0xffffffff)


@pytest.mark.parametrize('tail', [False, True])
def test_empty_oversized_and_crc_truncated_repairs_are_rejected(tail):
    fields = dict(tail=tail, seed=9 if tail else None)
    for size in (0, SYMBOL_BYTES + 1):
        with pytest.raises(ValueError, match='payload'):
            encode_repair(2, 1, bytes(size), **fields)
    minimal = encode_repair(2, 1, b'x', **fields)
    full = encode_repair(2, 1, bytes(SYMBOL_BYTES), **fields)
    for invalid in (minimal[:-1], full + b'\0'):
        with pytest.raises(ValueError, match='repair length'):
            decode_packet(invalid, 0)
        # Even a correctly recomputed CRC cannot legitimize a bad length.
        protected = invalid + pack('!I', crc32(invalid))
        with pytest.raises(ValueError, match='repair length'):
            decode_packet(protected, 0, 'raw_ipv4_crc32')
    wire = encode_repair(2, 1, b'abc\0\0', 'raw_ipv4_crc32', **fields)
    for invalid in (wire[:-1], wire[:-5] + wire[-4:]):
        with pytest.raises(ValueError, match='CRC'):
            decode_packet(invalid, 0, 'raw_ipv4_crc32')


@pytest.mark.parametrize('encapsulation', ['udp', 'raw_ipv4_crc32'])
@pytest.mark.parametrize('tail', [False, True])
def test_numeric_short_repair_preserves_variable_extents_and_known_subtraction(encapsulation, tail):
    sources = [bytes((i * 7 + 1) % 256 for i in range(72)),
               bytes((i * 13 + 3) % 256 for i in range(1454)), bytes(1456)]
    extent = max(map(len, sources))
    padded = [source + bytes(SYMBOL_BYTES - len(source)) for source in sources]
    serial = 16
    seed = serial * 2654435761 & 0xffffffff
    coefficients = [coefficient(seed, index) for index in range(3)]
    assert all(coefficients)
    full_parity = bytes(PRODUCT[coefficients[0]][a] ^ PRODUCT[coefficients[1]][b]
                        ^ PRODUCT[coefficients[2]][c] for a, b, c in zip(*padded))
    assert full_parity[extent:] == bytes(SYMBOL_BYTES - extent)
    wire = encode_repair(3, serial, full_parity[:extent], encapsulation,
                         tail=tail, seed=seed if tail else None)
    packet = decode_packet(wire, 0, encapsulation)
    assert packet.payload == full_parity
    for missing in range(3):
        recovered = []
        for column, value in enumerate(packet.payload):
            for known in range(3):
                if known != missing:
                    value ^= PRODUCT[coefficients[known]][padded[known][column]]
            recovered.append(PRODUCT[INVERSE[coefficients[missing]]][value])
        assert bytes(recovered) == padded[missing]
    # The zero-valued source retains its full 1456-byte encoded extent.
    assert extent == 1456 and len(wire) >= extent + 4


@pytest.mark.parametrize('encapsulation', ['udp', 'raw_ipv4_crc32'])
def test_disabled_trimming_preserves_legacy_regular_and_tail_wire_bytes(encapsulation):
    transport, _ = fixture(encapsulation)
    wires = []
    transport._send_wire = lambda wire, kind, header: wires.append((wire, kind, header)) or (0, .07)
    submit(transport)
    end = len(transport.sources)
    transport._repair(False)
    transport._repair(True)
    bodies = [pack('!HH', 32768 | end, 1) + bytes(SYMBOL_BYTES),
              pack('!HHII', 32768 | end, 32768 | 2, end, 2 * 2654435761 & 0xffffffff) + bytes(SYMBOL_BYTES)]
    expected = [body + pack('!I', crc32(body)) if encapsulation == 'raw_ipv4_crc32' else body for body in bodies]
    assert [wire for wire, kind, _ in wires if kind == 'repair'] == expected
    assert transport.wire_trimmed_repair_bytes == 0
    assert CompactWireConfig().trim_repair_padding is False


def test_trim_uses_actual_local_global_and_tail_support_including_zero_data():
    transport, packets = fixture('raw_ipv4_crc32', trim=True)
    sizes = [1460] + [72] * 128
    transport.sources = [CompactSource(index, size, 0) for index, size in enumerate(sizes)]
    transport.source_payloads = [bytes(SYMBOL_BYTES)] * len(sizes)
    transport._repair(False)
    assert packets[-1][1] == transport.repair_header + 72
    transport.repair_serial = 15
    transport._repair(False)
    assert packets[-1][1] == transport.repair_header + SYMBOL_BYTES
    transport._repair(True)
    assert packets[-1][1] == transport.ip_header_bytes + transport.crc_bytes + 12 + SYMBOL_BYTES
    assert transport.wire_trimmed_repair_bytes == SYMBOL_BYTES - 72
    for index in range(len(sizes), GLOBAL_WINDOW + 1):
        transport.sources.append(CompactSource(index, 72, 0))
        transport.source_payloads.append(bytes(SYMBOL_BYTES))
    transport.base = 1
    transport._prune_sender_payloads()
    transport._repair(True)
    assert packets[-1][1] == transport.ip_header_bytes + transport.crc_bytes + 12 + 72
    assert transport.wire_trimmed_repair_bytes == 2 * (SYMBOL_BYTES - 72)


def test_trim_context_and_fragment_extents_preserve_exact_frame_recovery():
    transport, packets = fixture('raw_ipv4_crc32', trim=True)
    delivered = []
    frame = tcp_profile_frame(payload_bytes=4000)
    transport.submit_channel(0, len(frame), 4000, lambda: delivered.append(frame), frame=frame)
    assert transport.context_records == 1 and transport.sources[0].size == 72
    assert transport.fragment_sources == 3 and max(source.size for source in transport.sources) == SYMBOL_BYTES
    transport._repair(True)
    assert packets[-1][1] == 1496 and transport.wire_trimmed_repair_bytes == 0
    for packet in list(packets):
        packet[3]()
    assert delivered == [frame]
    assert not transport.receiver.fragments and not transport.wire_invalid_packets


@pytest.mark.parametrize('options', [
    dict(short_source_max_bytes=-1), dict(short_source_max_bytes=1461),
    dict(short_source_max_bytes=True), dict(short_source_max_bytes=128.5),
    dict(short_source_copies=0), dict(short_source_copies=True), dict(short_source_copies=1.5),
])
def test_short_source_protection_validates_configuration(options):
    with pytest.raises(ValueError, match='short source'):
        CompactWireConfig(**options)


@pytest.mark.parametrize('encapsulation', ['udp', 'raw_ipv4_crc32'])
def test_short_source_copies_share_one_window_slot_and_deliver_once(encapsulation):
    transport, packets = fixture(encapsulation, short_source_max_bytes=128, short_source_copies=4)
    delivered = []
    expected = submit(transport, delivered=delivered)
    sources = [packet for packet in packets if packet[2] == 'source']
    assert len(transport.sources) == 2
    assert len(sources) == 8
    assert transport.wire_protected_sources == 2
    assert transport.wire_peak_outstanding_sources == 2
    assert transport.wire_repeated_source_packets == 6
    assert transport.wire_repeated_source_bytes == sum(packet[1] for packet in sources) * 3 // 4
    # Erase the first three copies of each source. Fourth copies still decode.
    sources[3][3]()
    sources[7][3]()
    assert delivered == [expected]
    for packet in sources:
        packet[3]()
    assert delivered == [expected]
    assert transport.received_prefix == 2
    assert not transport.wire_invalid_packets


def test_short_source_protection_applies_to_context_but_preserves_large_payload_budget():
    transport, packets = fixture(short_source_max_bytes=128, short_source_copies=4)
    frame = tcp_profile_frame(payload_bytes=1448)
    transport.submit_channel(0, len(frame), 1448, lambda: None, frame=frame)
    sources = [packet for packet in packets if packet[2] == 'source']
    assert len(transport.sources) == 2
    assert len(sources) == 5
    assert transport.wire_protected_sources == 1
    assert transport.wire_repeated_source_packets == 3
    assert sources[-1][1] > 128


def test_short_source_copies_retain_normal_repair_credit():
    transport, packets = fixture(ratio=.5, short_source_max_bytes=128, short_source_copies=4)
    submit(transport)
    assert len(transport.sources) == 2
    assert len([packet for packet in packets if packet[2] == 'source']) == 8
    assert len([packet for packet in packets if packet[2] == 'repair']) == 1
    assert transport.scheduled_repairs == 1


def test_short_source_copies_wait_for_shared_window_credit():
    transport, packets = fixture(short_source_max_bytes=128, short_source_copies=4)
    transport.sources = [CompactSource(index, 1, index + 1) for index in range(GLOBAL_WINDOW)]
    transport.source_payloads = [b'x'] * GLOBAL_WINDOW
    submit(transport, channel=1)
    assert len(transport.source_queue) == 2
    assert not packets
    assert transport.wire_repeated_source_packets == 0
    transport._receive_feedback(2, 0)
    assert not transport.source_queue
    assert len(transport.sources) - transport.base == GLOBAL_WINDOW
    assert len([packet for packet in packets if packet[2] == 'source']) == 8
    assert transport.wire_repeated_source_packets == 6


def test_short_source_copies_remain_adjacent_across_source_identifier_wrap():
    transport, _ = fixture(short_source_max_bytes=128, short_source_copies=4)
    start = ID_MODULUS - 1
    transport.sources = [CompactSource(index, 1, index + 1) for index in range(start)]
    transport.source_payloads = [b'x'] * start
    transport.base = start
    transport.wire_retained_start = start
    transmitted = []
    original_send = transport._send_wire

    def send(wire, kind, header_bytes):
        transmitted.append(wire)
        return original_send(wire, kind, header_bytes)

    transport._send_wire = send
    submit(transport)
    assert len(transmitted) == 8
    assert transmitted[:4] == [transmitted[0]] * 4
    assert transmitted[4:] == [transmitted[4]] * 4
    assert [decode_packet(wire, start).index for wire in transmitted] == [start] * 4 + [start + 1] * 4
    assert transport.wire_source_wraps == 1
