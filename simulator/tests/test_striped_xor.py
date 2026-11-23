from itertools import permutations
from pathlib import Path
from types import SimpleNamespace

import pytest

from l2tunnel_sim import striped_cauchy, striped_xor


FULL = striped_cauchy.Geometry(4, 1)


@pytest.mark.parametrize("lengths", [(1, 1), (1, 1, 1, 1, 1), (65, 1079), (23, 400, 1079),
                                      (1079, 33, 800, 406), (1079, 406, 1079, 17, 730)])
def test_unequal_helpers_restore_each_erasure_and_protect_another_member(lengths):
    raw = [bytes((11*i + j) % 256 for j in range(n)) for i, n in enumerate(lengths)]
    wires = striped_xor.encode_packets(2**63, raw, FULL, 1451)
    assert max(map(len,wires)) == striped_xor.group_max_wire(2**63, raw, FULL) <= 1451
    members = [striped_xor.inspect_packet(wire, FULL, 1451) for wire in wires]
    n = len(members)
    for slot, (base, geometry, split, ordinal, body) in enumerate(members):
        assert base == 2**63 and ordinal == slot and split is None
        assert geometry.own(body) == raw[slot] and len(body.parity) >= 1
        changed = list(raw)
        prev = (slot - 1) % n
        changed[prev] = bytes([raw[prev][0] ^ 1]) + raw[prev][1:]
        altered = striped_xor.encode_packets(2**63, changed, FULL, 1451)
        alternate = striped_xor.inspect_packet(altered[slot], FULL, 1451)[-1]
        assert body.original == alternate.original and body.parity != alternate.parity
    for erased in range(n):
        kept = set(range(n)) - {erased}
        for arrivals in permutations(kept):
            receiver = striped_xor.Receiver(geometry)
            for j in arrivals:
                assert receiver.recover_missing() == {}
                assert receiver.add(j, members[j][-1]) == raw[j]
                assert receiver.add(j, members[j][-1]) is None
            assert receiver.recover_missing() == {erased: raw[erased]}
            assert receiver.add(erased, members[erased][-1]) is None
            assert receiver.recover_missing() == {}


def test_parser_rejects_bad_width_and_receiver_rejects_conflicting_total():
    wires = striped_xor.encode_packets(0, [b'aaa',b'abcdef',b'longer here'], FULL, 1451)
    base, geo, _, i, member = striped_xor.inspect_packet(wires[0], FULL, 1451)
    with pytest.raises(ValueError):
        striped_xor.inspect_packet(wires[0][:-len(member.parity)], FULL, 1451)
    with pytest.raises(ValueError):
        striped_xor.inspect_packet(wires[0][:1] + b'\x80' + wires[0][1:], FULL, 1451)
    receiver = striped_xor.Receiver(geo)
    receiver.add(i, member)
    other = striped_xor.inspect_packet(wires[1], FULL, 1451)[-1]
    with pytest.raises(ValueError, match='total'):
        receiver.add(1, striped_xor.Member(other.total+1,other.original,other.parity))
    assert list(receiver.packets) == [0]


def test_timed_unequal_pair_sends_two_mixed_members_and_singleton_still_splits(monkeypatch):
    from test_packed_wire import make_transport

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath
    sim, t = make_transport()
    path = StripedPath(SimpleNamespace(transport=t), FULL)
    path.select_variable_parity()
    path.short_prefix_groups = True
    sent = []
    path.emit = lambda wire, kind: sent.append(wire)
    raw = [bytes(65), bytes(1079)]
    assert striped_cauchy.group_max_wire(0,raw,FULL) > path.max_wire
    for body in raw:
        t.sources.append(None)
        path.first(body+b'crc!', "source", 0)
    assert not sent
    sim.now = path.pending_deadline
    t.sources.append(None)
    path.first(b'xcrc!', "source", 0)
    assert len(sent) == 2 and path.counts["groups_2"] == 1
    assert all(path.codec.inspect_packet(w,FULL,path.max_wire)[2] is None for w in sent)
    sim.now = path.pending_deadline
    path.seal(2)
    assert len(sent) == 4 and path.counts["groups_1"] == 1
    for packet in sent[2:]:
        _, _, length, ordinal, body = path.codec.inspect_packet(packet,FULL,path.max_wire)
        assert striped_cauchy.reconstruct_split(body,ordinal,length) == b'x'
