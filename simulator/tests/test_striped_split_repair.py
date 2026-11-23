from itertools import combinations

import pytest

from l2tunnel_sim.striped_split_repair import Receiver, encode, inspect


@pytest.mark.parametrize("sizes", [(1079,1079,820), (1,17,348)])
def test_every_four_members_restore_all_and_one_still_delivers_its_source(sizes):
    sources = [bytes((13*i + 17*j) % 256 for j in range(n-1))+b"\x00" for i,n in enumerate(sizes)]
    wires = encode(1711, sources, 1451)
    members = [inspect(wire,1451) for wire in wires]
    for count in range(1,7):
        for slots in combinations(range(6), count):
            rx = Receiver(members[slots[-1]])
            delivered = {}
            for slot in reversed(slots):
                fresh = rx.add(members[slot])
                assert not delivered.keys() & fresh.keys()
                delivered.update(fresh)
                assert delivered[slot//2] == sources[slot//2]
                assert rx.add(members[slot]) == {}
            direct = {i//2 for i in slots}
            expected = set(range(3)) if count >= 4 else direct
            assert delivered == {i:sources[i] for i in expected}


def test_short_group_refuses_over_mtu_and_conflicting_copies():
    sources = [b"a"*1079,b"b"*1079,b"c"*820]
    wires = encode(1711,sources,1451)
    assert encode(1711,sources,max(map(len,wires))-1) is None
    with pytest.raises(ValueError):
        inspect(wires[0][:-1],1451)
    member = inspect(wires[0],1451)
    rx = Receiver(member)
    rx.add(member)
    changed = bytearray(wires[1])
    changed[-len(member.parity)-1] ^= 1
    with pytest.raises(ValueError, match="conflicting.*source"):
        rx.add(inspect(bytes(changed),1451))


def test_two_lost_first_members_recover_through_the_normal_packed_path(monkeypatch):
    from pathlib import Path
    from l2tunnel_sim.packed_receiver_service import PackedReceiverService, ReceiverCost
    from l2tunnel_sim.packed_targeted import TargetedPolicy
    from l2tunnel_sim.striped_cauchy import Geometry
    from test_packed_targeted import fixture, step

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from packed_striped_path import StripedPath

    sim, tx, log = fixture({("source", 1), ("source", 2)}, policy=TargetedPolicy(probe_ms=500))
    service = PackedReceiverService(tx, ReceiverCost(15, 0, 1, 12))
    path = StripedPath(service, Geometry(10, 2))
    path.short_prefix_groups = path.protect_split_triples = True
    path.install()
    arrivals = []
    frames = []
    for lane, length in enumerate((1064, 1064, 805)):
        frame = bytes.fromhex("02000000000202000000000188b5") + bytes([lane]) * (length - 14)
        frames.append(frame)
        tx.submit_channel(lane, length, length - 66, lambda f: arrivals.append((sim.now, f)),
                          frame=frame, deliver_frame=True)
        tx.flush()
    needed_before_recovery = []
    needs = path.receiver_needs
    def record_interest(received):
        if set(received) == {1}:
            needed_before_recovery.append(tuple(needs(i, False) for i in range(3)))
    original_add = Receiver.add
    def observe(receiver, member):
        fresh = original_add(receiver, member)
        record_interest(receiver.sources)
        return fresh
    monkeypatch.setattr(Receiver, "add", observe)
    step(sim, .15)
    assert needed_before_recovery and set(needed_before_recovery) == {(True, False, True)}
    assert [frame for _, frame in arrivals] == [frames[1], frames[2], frames[0]]
    assert arrivals[-1][0] < .040
    assert tx.received_prefix == tx.base == 3 and not path.split_triples
    assert path.counts["split_triples"] == path.counts["split_triple_recovered"] == 1
    assert [lost for _, _, _, kind, lost in log if kind == "source"] == [True, True] + [False]*4
    assert path.counts["source_ip_bytes"] == sum(size for _, _, size, kind, _ in log if kind == "source")
    assert all(kind != "retry" for _, _, _, kind, _ in log)
