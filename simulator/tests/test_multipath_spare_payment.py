"""Physical payment, expiration and byte accounting of the optional shared-pacer spare work."""
from collections import Counter
from dataclasses import replace

from l2tunnel_sim import multipath_wire as wire
from l2tunnel_sim.path_transport import PathConfig, PathNetwork
from test_multipath_transport import Clock


class MonotoneClock(Clock):
    def at(self, t, callback, *args):
        assert t >= self.now
        super().at(t, callback, *args)


def setup(**options):
    clock = MonotoneClock()
    cfg = PathConfig(6, 5, (1500,)*6, (500,)*6, (35,)*6,
                     rank_requests=True, physical_recovery=True, shared_pending=True,
                     link_ethernet=True, paced_recovery=True, proactive=True, early_forward=True)
    net = PathNetwork(clock, replace(cfg, **options), 1, (bytes, bytes))
    return clock, net, net.directions[0]


def test_spare_freeze_is_unpaid_and_only_serializer_completion_wakes_next_work():
    clock, net, d = setup()
    costs = Counter()
    original = net.send

    def send(reverse, path, kind, payload, meta=()):
        if kind != "spare":
            return original(reverse, path, kind, payload, meta)
        price = len(payload)+49+14
        assert d.spare.pending[0] == price
        assert d.counts["spare_paid_wire_bytes"] == costs["bytes"]
        accepted = original(reverse, path, kind, payload, meta)
        costs["bytes"] += price
        costs["packets"] += 1
        assert d.counts["spare_paid_wire_bytes"] == costs["bytes"]
        assert d.spare.pending is not None and d.spare.wake is None
        return accepted

    net.send = send
    d.submit(bytes(1500))
    clock.until(.009)
    assert net.totals[0]["fresh_packets"] == 6
    assert costs["packets"] == net.totals[0]["spare_packets"] > 0
    assert d.spare.pending is None
    assert costs["bytes"] == net.totals[0]["spare_ip_bytes"] + 14*costs["packets"]
    assert d.spare.recent == net.totals[0]["serialized_ethernet_bytes"]


def test_late_payment_of_the_final_original_cannot_restart_a_spare_deadline():
    clock, net, d = setup(hold_us=(500,)*5+(13_000,), spare_deadline_us=50_000)
    d.submit(bytes(1500))
    clock.until(.03)
    assert net.totals[0]["fresh_packets"] == 6
    assert not d.spare.future and not any(d.spare.ready)
    assert d.counts["spare_shards"] == 0


def test_candidate_needs_time_for_the_ethernet_header_before_its_expiry():
    clock, net, d = setup(hold_us=(20_000,)*6)
    d.submit(bytes(1500))
    clock.until(.001)
    gid, path, ordinal = 0, 1, 0
    entry = gid, ordinal, d.tx[gid].parts[ordinal]
    ip = len(wire.encode_data(path, 0, [entry]))+49
    due = clock.now+(ip+7)/d.spare.link.bytes_per_s
    d.spare.ready[path].append((gid, ordinal, due, False))
    d.spare.arm(clock.now)
    clock.until(.002)
    assert d.counts["spare_expired_or_confirmed_shards"] == 1
    assert not d.spare.ready[path] and net.totals[0]["spare_packets"] == 0
