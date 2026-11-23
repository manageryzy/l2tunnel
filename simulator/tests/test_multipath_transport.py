from collections import Counter
from heapq import heappop, heappush
from itertools import count
from random import Random

import pytest

from l2tunnel_sim.config import PathConfig as Capacity, Scenario
from l2tunnel_sim.model import Link
from l2tunnel_sim import multipath_wire as wire
from l2tunnel_sim.path_transport import PathConfig, PathNetwork


class Clock:
    def __init__(self):
        self.scenario = Scenario(0, 0, "iid", mtu=1500)
        capacity = Capacity(100, 10)
        self.now = 0
        self.events = []
        self.seq = count()
        self.links = [[Link(self.scenario, capacity, rev, Random(1))] for rev in (False, True)]
        self.wire = [Counter(), Counter()]
        self.datagrams = [Counter(), Counter()]

    def at(self, t, callback, *args):
        heappush(self.events, (t, next(self.seq), callback, args))

    def until(self, end):
        while self.events and self.events[0][0] < end:
            self.now, _, callback, args = heappop(self.events)
            callback(*args)
        self.now = end


def test_aggregated_paths_deliver_on_kth_arrival_before_slowest_path_flushes():
    clock = Clock()
    frames = []
    cfg = PathConfig(4, 3, (1500,)*4, (100, 200, 300, 10_000), (0,)*4)
    net = PathNetwork(clock, cfg, 1, (frames.append, lambda packet: None))
    fwd = net.directions[0]
    originals = [bytes(range(100)), bytes(range(109))]
    for packet in originals:
        fwd.submit(packet)
    clock.until(.004)
    assert frames == originals
    assert [lane.next_pn for lane in fwd.lanes] == [1, 1, 1, 0]
    assert [lane.counts["aggregates"] for lane in fwd.lanes] == [1, 1, 1, 0]
    assert not fwd.tx and fwd.tx_prefix == 2
    clock.until(.15)
    assert frames == originals
    assert net.totals[0]["fresh_packets"] == 4


def test_optional_ethernet_charge_reserves_shared_link_for_erased_data_and_feedback():
    clock = Clock()
    cfg = PathConfig(2, 1, (1500,)*2, (500,)*2, (35,)*2, loss_rates=(1, 1), link_ethernet=True)
    net = PathNetwork(clock, cfg, 1, (bytes, bytes))
    for reverse in (False, True):
        for path, kind in ((0, "fresh"), (1, "ack"), (0, "shard_request")):
            net.send(reverse, path, kind, bytes(37))
        link = clock.links[reverse][0]
        assert link.reserved_bytes == 3 * (37 + 49 + 14)
        assert link.free_at == pytest.approx(link.reserved_bytes / link.bytes_per_s)
        assert net.totals[reverse]["socket_submitted_ip_bytes"] == 3 * (37 + 49)
        assert net.totals[reverse]["erased_packets"] == 0
    clock.until(.01)
    for reverse in (False, True):
        counters = net.totals[reverse]
        assert counters["erased_packets"] == 3
        assert counters["serialized_ethernet_bytes"] == counters["erased_after_serialization_ethernet_bytes"] == 300
        assert counters["erased_after_serialization_ip_bytes"] == 258
        delays = net.socket_delay_report(reverse)
        expected = 300 / clock.links[reverse][0].bytes_per_s * 1e6
        assert delays["packets"] == 3
        assert expected <= delays["p99_upper_us"] <= expected + 10


def test_paced_recovery_uses_paid_physical_rtt_even_after_logical_release():
    clock = Clock()
    cfg = PathConfig(1, 1, (1500,), (500,), (1000,), physical_recovery=True,
                     shared_pending=True, link_ethernet=True, paced_recovery=True)
    d = PathNetwork(clock, cfg, 0, (bytes, bytes)).directions[0]
    d.submit(b"original")
    clock.until(.01)
    ledger = d.arq[0]
    assert ledger.packets[0].paid == .0005
    assert ledger.rtt.srtt is None
    d.acknowledged(((255,0,1,()),))
    assert not ledger.packets and ledger.rtt.srtt is None
    clock.until(.1005)
    d.acknowledged(((0,0,1,()),))
    assert (ledger.rtt.srtt,ledger.rtt.variation,ledger.rtt.rto) == (100000,50000,300000)
    d.acknowledged(((0,0,1,()),))
    assert ledger.stats["physical_rtt_samples"] == 1


def test_rtt_uses_highest_first_positive_once_and_keeps_exactly_256_paid_pns():
    from l2tunnel_sim.path_paced import PhysicalRtt

    rtt = PhysicalRtt()
    for pn in range(259):
        rtt.sent(pn, 1000*pn)
    assert (min(rtt.history),len(rtt.history)) == (3,256)
    assert rtt.observe(0,3,(),200000) is None
    assert rtt.observe(0,5,((17,20),),200000) == 181000
    assert (rtt.srtt,rtt.variation,rtt.rto) == (181000,90500,500000)
    assert rtt.observe(0,5,((17,20),),200000) is None
    assert rtt.observe(16,20,(),200000) == 184000
    assert (rtt.srtt,rtt.variation,rtt.rto) == (181375,68625,455875)


def test_one_extra_selective_ack_is_driven_by_actual_payment_and_stops_when_idle():
    clock = Clock()
    cfg = PathConfig(2, 2, (1500,)*2, (500,)*2, (35,)*2, gap_us=1000000,
                     physical_recovery=True, shared_pending=True, link_ethernet=True,
                     paced_recovery=True, loss_rates=(1,1))
    net = PathNetwork(clock, cfg, 0, (bytes,bytes))
    direction = net.directions[0]
    part = wire.shards(b"independent",2,2)[0]
    direction.received("fresh",0,wire.encode_data(0,1,[(0,0,part)]))
    clock.until(.0089)
    assert net.totals[1]["ack_packets"] == 1
    clock.until(.02)
    assert net.totals[1]["ack_packets"] == 2
    clock.until(.08)
    assert net.totals[1]["ack_packets"] == 2 and not direction.dirty_lanes


def test_a_selective_repeat_waits_for_its_own_paid_deadline_and_forgets_evicted_pns():
    from l2tunnel_sim.path_transport import ReceiptWindow

    ledger = ReceiptWindow()
    ledger.observe(1)
    ledger.positive_paid(0, 0, ((1,2),), .001)
    ledger.positive_paid(0, 0, ((1,2),), .003)
    due = ledger.repeat_deadline()
    assert due == pytest.approx(.009)
    ledger.observe(0)
    ledger.positive_paid(0, 2, (), due)
    assert ledger.repeat_deadline() is None
    ledger.observe(4)
    ledger.positive_paid(0, 2, ((4,5),), .02)
    ledger.observe(280)
    assert ledger.repeat_deadline() is None and not ledger.repeat


def test_paced_path_recovery_drains_a_fully_erased_initial_group_via_quiet_or_physical_repair():
    clock = Clock()
    frames = []
    cfg = PathConfig(3,2,(1500,)*3,(500,)*3,(35,)*3, rank_requests=True,
                     physical_recovery=True, shared_pending=True, link_ethernet=True, paced_recovery=True)
    net = PathNetwork(clock, cfg, 1, (frames.append,bytes))
    class FirstLost:
        def __init__(self):
            self.first = True

        def lost(self):
            lost, self.first = self.first, False
            return lost
    net.loss[0] = [FirstLost() for _ in range(3)]
    d = net.directions[0]
    d.submit(bytes(750))
    clock.until(.08)
    assert not frames and d.tx
    clock.until(.5)
    assert frames == [bytes(750)] and not d.tx and not d.service.chosen
    assert all(not arq.active for arq in d.arq)
    assert d.counts["paced_ethernet_bytes"] == net.totals[0]["serialized_ethernet_bytes"]


def test_pacer_keeps_already_selected_large_packet_and_allows_other_classes_after_payment():
    clock = Clock()
    cfg = PathConfig(2, 2, (1500,)*2, (500,)*2, (35,)*2, max_entries=(1,1), rank_requests=True,
                     physical_recovery=True, shared_pending=True, link_ethernet=True,
                     paced_recovery=True, loss_rates=(1,1))
    net = PathNetwork(clock, cfg, 0, (bytes,bytes))
    direction = net.directions[1]
    log = []
    send = net.send
    def capture(reverse,path,kind,payload,meta=()):
        log.append((clock.now,path,kind,len(payload)+49))
        return send(reverse,path,kind,payload,meta)
    net.send = capture
    for _ in range(5):
        direction.submit(bytes(1450))
    clock.until(.000001)
    assert len(log) == 1 and direction.service.chosen
    direction.control("shard_request",wire.encode_shard_request([(0,(1,))],2))
    clock.until(.01)
    assert [p[1] for p in log[:2]] == [0,1]
    assert [p[2] for p in log[:3]] == ["fresh","fresh","shard_request"]
    assert sum(1 for _,_,kind,_ in log if kind=="fresh") == 10
    assert direction.counts["pacing_credit_deferrals"] and direction.counts["pacing_credit_wait_us"]
    total = 0
    for t,_,_,ip in log:
        total += ip + 14
        assert total <= 1514+int(t*1e6+1e-7)*1.25+1e-9


def test_quiet_recovery_finds_erased_terminal_group_and_physical_ack_cannot_release_it():
    clock = Clock()
    frames = []
    cfg = PathConfig(4, 3, (1500,)*4, (500,)*4, (0,)*4)
    net = PathNetwork(clock, cfg, 9, (frames.append, lambda packet: None))
    fwd = net.directions[0]

    class LoseFirst:
        def __init__(self):
            self.first = True

        def lost(self):
            lost, self.first = self.first, False
            return lost

    net.loss[0] = [LoseFirst() for _ in range(4)]
    fwd.submit(b"last native packet")
    clock.until(.005)
    assert not frames and set(fwd.tx) == {0}
    fwd.acknowledged([(0, 1, 1, ())])
    assert set(fwd.tx) == {0}
    clock.until(.45)
    assert frames == [b"last native packet"] and not fwd.tx
    assert fwd.tx_prefix == fwd.rx_prefix == 1
    assert fwd.counts["quiet_repairs"] == 1 and fwd.counts["repair_shards"] == 3


def test_logical_ack_pages_continue_after_payment_and_include_late_lower_runs():
    clock = Clock()
    cfg = PathConfig(2, 1, (1500,)*2, (500,)*2, (0,)*2, gap_us=1000000)
    net = PathNetwork(clock, cfg, 0, (bytes, bytes))
    direction = net.directions[0]
    part = wire.shards(b"one", 2, 1)[0]
    def receive(pn, gid):
        direction.received("fresh", 0, wire.encode_data(0, pn, [(gid, 0, part)]))
    for pn, gid in enumerate(range(1, 30, 3)):
        receive(pn, gid)
    first, receipt = direction.pending_ack()
    assert wire.decode_ack(first)[-1][-1][-1] == (22, 23)
    # Preparing a piggyback that does not fit cannot advance the cursor.
    assert direction.pending_ack() == (first, receipt)
    direction.ack_sent(receipt)
    assert direction.ack_at == .001
    receive(10, 2)
    page, receipt = direction.pending_ack()
    assert wire.decode_ack(page)[-1][-1] == ((25, 26), (28, 29))
    direction.ack_sent(receipt)
    page, receipt = direction.pending_ack()
    assert wire.decode_ack(page)[-1][-1][0] == (1, 3)
    direction.ack_sent(receipt)
    _, receipt = direction.pending_ack()
    direction.ack_sent(receipt)
    assert direction.pending_ack() == (b"", ()) and direction.ack_at is None


def test_ninth_physical_ack_run_is_due_immediately_and_only_dirty_runs_repeat():
    clock = Clock()
    net = PathNetwork(clock, PathConfig(2, 1, (1500,)*2, (500,)*2, (0,)*2), 0, (bytes, bytes))
    direction = net.directions[0]
    part = wire.shards(b"same native group", 2, 1)[0]
    def receive(pn):
        direction.received("fresh", 0, wire.encode_data(0, pn, [(0, 0, part)]))
    for pn in range(1, 20, 2):
        receive(pn)
    first, payment = direction.pending_ack()
    assert wire.decode_ack(first)[0][-1] == tuple((i, i+1) for i in range(1, 16, 2))
    assert direction.pending_ack() == (first, payment)
    direction.ack_sent(payment)
    assert direction.ack_at == clock.now
    # Joining previously reported runs makes the whole span dirty again.
    receive(14)
    second, payment = direction.pending_ack()
    assert wire.decode_ack(second)[0][-1] == ((13, 16), (17, 18), (19, 20))
    direction.ack_sent(payment)
    assert direction.ack_at is None
    receive(19)
    repeated, _ = direction.pending_ack()
    assert wire.decode_ack(repeated)[0][-1] == ((19, 20),)


def test_quiet_waits_for_actual_payment_and_rearms_after_lost_quiet_attempt():
    clock = Clock()
    clock.links[0][0].free_at = .25
    cfg = PathConfig(1, 1, (1500,), (500,), (0,), quiet_us=10000)
    delivered = []
    net = PathNetwork(clock, cfg, 0, (delivered.append, bytes))
    direction = net.directions[0]
    class LoseTwice:
        remaining = 2
        def lost(self):
            self.remaining -= 1
            return self.remaining >= 0
    net.loss[0][0] = LoseTwice()
    direction.submit(b"tail")
    clock.until(.24)
    assert direction.quiet_at is None and direction.counts["quiet_repairs"] == 0
    clock.until(.251)
    first_paid = direction.tx[0].last_paid
    assert direction.quiet_at == first_paid + .01
    clock.until(first_paid+.0101)
    assert direction.counts["quiet_repairs"] == 1
    clock.until(first_paid+.011)
    repair_paid = direction.tx[0].last_paid
    clock.until(repair_paid+.0099)
    assert direction.counts["quiet_repairs"] == 1
    clock.until(repair_paid+.012)
    assert direction.counts["quiet_repairs"] == 2 and delivered == [b"tail"] and not direction.tx


def test_quiet_does_not_wait_for_an_unpaid_slow_lane():
    clock = Clock()
    cfg = PathConfig(3, 1, (1500,)*3, (200000, 500, 500), (0,)*3, quiet_us=10000)
    delivered = []
    net = PathNetwork(clock, cfg, 0, (delivered.append, bytes))
    net.loss[0][1:] = [LoseOne(), LoseOne()]
    direction = net.directions[0]
    direction.submit(b"tail")
    clock.until(.02)
    assert direction.lanes[0].next_pn == 0
    assert direction.counts["quiet_repairs"] == 1 and delivered == [b"tail"]


def test_full_path_flushes_on_insert_even_without_another_native_packet():
    clock = Clock()
    cfg = PathConfig(2, 2, (256, 1500), (5000, 5000), (0, 0), max_entries=(255, 1))
    net = PathNetwork(clock, cfg, 1, (bytes, bytes))
    fwd = net.directions[0]
    # On path zero, 4 B prefix + 3 B entry header + 2 B length + 198 direct
    # bytes consume the full 207 B plaintext budget. Path one hits its entry cap.
    fwd.submit(bytes(396))
    assert [lane.next_pn for lane in fwd.lanes] == [1, 1]
    assert all(lane.deadline is None for lane in fwd.lanes)


class LoseOne:
    def __init__(self):
        self.first = True

    def lost(self):
        result, self.first = self.first, False
        return result


def test_sender_spare_opens_before_named_response_can_return():
    clock = Clock()
    opened = []
    cfg = PathConfig(4, 3, (1500,)*4, (500,)*4, (35,)*4, proactive=True)
    net = PathNetwork(clock, cfg, 1, (lambda packet: opened.append((clock.now, packet)), bytes))
    net.loss[0][:2] = [LoseOne(), LoseOne()]
    payload = bytes(range(200))
    net.directions[0].submit(payload)
    clock.until(.045)
    assert len(opened) == 1 and opened[0][1] == payload and .035 < opened[0][0] < .045
    assert net.totals[0]["spare_ip_bytes"] > 0 and net.totals[0]["with_repair_packets"] == 0
    clock.until(.5)
    assert not net.directions[0].tx


def test_rank_request_names_one_missing_ordinal_and_suppresses_immediate_duplicate():
    clock = Clock()
    opened = []
    cfg = PathConfig(4, 3, (1500,)*4, (500,)*4, (35,)*4, rank_requests=True)
    net = PathNetwork(clock, cfg, 1, (opened.append, bytes))
    net.loss[0][:2] = [LoseOne(), LoseOne()]
    flow = net.directions[0]
    flow.submit(bytes(range(60)))
    clock.until(.08)
    assert flow.counts["named_ordinals"] == flow.counts["repair_shards"] == 1
    flow.repair(0, (0,))
    assert flow.counts["suppressed_named_ordinals"] == 1 and not opened
    clock.until(.5)
    assert opened == [bytes(range(60))] and not flow.tx


@pytest.mark.parametrize("lose_first_request", (False, True))
def test_a3_copies_use_distinct_paid_paths_and_recover_after_first_reply_loss(lose_first_request):
    clock = Clock()
    cfg = PathConfig(4, 3, (1500,)*4, (500,)*4, (35,)*4, rank_requests=True,
                     a3_request_copies=2, a3_reply_copies=2)
    opened = []
    net = PathNetwork(clock, cfg, 11, (opened.append, bytes))
    depart = net.depart
    ctl, replies = [], []

    def erase_selected(reverse, path, kind, payload, size, meta):
        erase = not reverse and kind == "fresh" and path < 2
        if reverse and kind.startswith("shard_request"):
            ctl.append((path, payload))
            erase = lose_first_request and kind == "shard_request"
        if not reverse and kind == "with_repair":
            replies.append((path, meta[0][1]))
            erase = meta[0][1] == "named"
        original = net.loss[reverse][path]
        if erase:
            net.loss[reverse][path] = LoseOne()
        depart(reverse, path, kind, payload, size, meta)
        net.loss[reverse][path] = original

    net.depart = erase_selected
    packet = bytes(range(75))
    net.directions[0].submit(packet)
    clock.until(.11)
    assert opened == [packet]
    assert ctl[0][1] == ctl[1][1] and ctl[0][0] != ctl[1][0]
    assert len(replies) == 2 and replies[0][0] != replies[1][0]
    assert {r[1] for r in replies} == {"named", "named_copy"}
    assert net.totals[1]["shard_request_copy_ip_bytes"] >= len(ctl[0][1]) + 49
    assert net.totals[0]["a3_reply_copy_paid_entry_bytes"] > 0
    assert net.directions[0].counts["suppressed_named_ordinals"] == int(not lose_first_request)


def test_a3_copy_count_cannot_exceed_paths_or_enable_a2_copies():
    with pytest.raises(ValueError, match="distinct"):
        PathConfig(1, 1, (1500,), (500,), (0,), rank_requests=True, a3_request_copies=2)
    with pytest.raises(ValueError, match="distinct"):
        PathConfig(2, 1, (1500,)*2, (500,)*2, (0,)*2, rank_requests=False, a3_reply_copies=2)


def test_ack_count_and_group_deadline_are_independent():
    for count_limit, group_us, counter in ((1, 5000, "count_triggered_ack_flushes"),
                                           (8, 100, "deadline_triggered_ack_flushes")):
        clock = Clock()
        cfg = PathConfig(4, 3, (1500,)*4, (50,)*4, (0,)*4, ack_us=10000,
                         ack_count=count_limit, group_ack_us=group_us)
        net = PathNetwork(clock, cfg, 1, (bytes, bytes))
        flow = net.directions[0]
        flow.submit(b"source")
        clock.until(.001)
        assert flow.counts[counter] > 0 and not flow.tx


def test_low_load_extra_is_forward_only_and_shares_the_normal_spare_budget():
    clock = Clock()
    cfg = PathConfig(4, 3, (1500,)*4, (500,)*4, (35,)*4, proactive=True,
                     early_forward=True, loss_rates=(0, 0))
    net = PathNetwork(clock, cfg, 1, (bytes, bytes))
    for direction in net.directions:
        direction.submit(b"short IPv4 fixture")
    clock.until(.02)
    fwd, rev = net.directions
    assert fwd.counts['low_load_extra_shards'] == 4 and rev.counts['low_load_extra_shards'] == 0
    for side, direction in enumerate((fwd, rev)):
        assert net.totals[side]['spare_ip_bytes'] <= clock.now*direction.spare.rate
        assert clock.links[side][0].reserved_bytes == sum(
            v for k,v in net.totals[side].items() if k.endswith('_ip_bytes'))


def test_physical_recovery_needs_distinct_paid_ack_evidence_and_preserves_other_path_credit():
    clock = Clock()
    cfg = PathConfig(2, 2, (1500,)*2, (500,)*2, (1000,)*2, max_entries=(1, 1),
                     physical_recovery=True, physical_window=4)
    net = PathNetwork(clock, cfg, 0, (bytes, bytes))
    flow = net.directions[0]
    for i in range(5):
        flow.submit(bytes([i]))
    clock.until(.002)
    first, other = flow.arq
    assert first.active == other.active == 4 and len(first.waiting) == len(other.waiting) == 1
    flow.acknowledged([(1, 0, 1, ())])
    clock.until(.003)
    assert other.paid_end == 5 and first.paid_end == 4
    for i in (1, 1, 2, 2):
        flow.acknowledged([(0, 0, 0, ((i, i+1),))])
    assert first.stats["physical_loss_sack"] == 0
    flow.acknowledged([(0, 0, 0, ((3, 4),))])
    clock.until(.004)
    assert first.stats["physical_loss_sack"] == 1
    new_pn = first.paid_end - 1
    assert new_pn > 3 and first.packets[new_pn].keys == ((0, 0),)
    flow.acknowledged([(0, 0, 0, ((1, 4),))])
    assert first.stats["physical_loss_sack"] == 1 and first.packets[new_pn].active
    assert set(flow.tx) == set(range(5)) and first.stats["peak_physical_pn_records"] <= 4


def test_physical_floor_and_logical_retirement_have_distinct_accounting():
    clock = Clock()
    cfg = PathConfig(2, 2, (1500,)*2, (100,)*2, (1000,)*2,
                     physical_recovery=True, max_entries=(1, 1))
    flow = PathNetwork(clock, cfg, 0, (bytes, bytes)).directions[0]
    flow.submit(b"one")
    clock.until(.002)
    flow.acknowledged([(0, 1, 1, ())])
    assert flow.lanes[0].counts["physical_loss_floor"] == 1
    assert flow.lanes[0].counts["physically_confirmed_ip_bytes"] == 0
    clock.until(.003)
    assert flow.arq[0].packets[1].keys == ((0, 0),)
    flow.acknowledged([(255, 0, 1, ())])
    assert not flow.tx and all(not lane.packets for lane in flow.arq)
    assert all(lane.stats["physical_retired_by_logical_delivery"] == 1 for lane in flow.arq)
    assert all(lane.stats["physically_confirmed_ip_bytes"] == 0 for lane in flow.arq)


def test_physical_timeout_repairs_a_completely_erased_batch_from_paid_time():
    clock = Clock()
    clock.links[0][0].free_at = .2
    cfg = PathConfig(2, 2, (1500,)*2, (500,)*2, (0,)*2, quiet_us=500000, physical_recovery=True)
    delivered = []
    net = PathNetwork(clock, cfg, 0, (delivered.append, bytes))
    net.loss[0] = [LoseOne(), LoseOne()]
    flow = net.directions[0]
    flow.submit(b"first")
    flow.submit(b"tail")
    clock.until(.199)
    assert all(lane.due is None for lane in flow.arq)
    clock.until(.289)
    assert not delivered and not net.totals[0]["physical_repair_paid_shards"]
    clock.until(.295)
    assert delivered == [b"first", b"tail"] and not flow.tx
    assert net.totals[0]["physical_repair_paid_shards"] == 4
    assert all(lane.stats["physical_loss_timeout"] == 1 for lane in flow.arq)


def test_late_physical_ack_cancels_an_unpaid_retry_after_ack_loss():
    clock = Clock()
    cfg = PathConfig(1, 1, (1500,), (1000,), (1000,), physical_recovery=True,
                     physical_rto_us=5000)
    net = PathNetwork(clock, cfg, 0, (bytes, bytes))
    flow = net.directions[0]
    flow.submit(b"still retained")
    clock.until(.0065)
    assert flow.lanes[0].roles == ["physical"]
    flow.acknowledged([(0, 0, 1, ())])
    clock.until(.02)
    assert net.totals[0]["physical_repair_paid_shards"] == 0 and set(flow.tx) == {0}
    assert flow.lanes[0].counts["physically_confirmed_ip_bytes"] == net.totals[0]["fresh_ip_bytes"]


def test_a3_promotes_a_single_unstaged_first_member_and_keeps_explicit_extra_copy():
    for copies in (1, 2):
        clock = Clock()
        cfg = PathConfig(3, 2, (1500,)*3, (200000,500,500), (35,)*3,
                         rank_requests=True, physical_recovery=True, shared_pending=True,
                         a3_reply_copies=copies)
        net = PathNetwork(clock, cfg, 3, (bytes, bytes))
        flow = net.directions[0]
        depart = net.depart
        paid = []
        def observe(reverse, path, kind, body, size, meta):
            if not reverse and meta:
                for entry, (_, role, _, _) in zip(wire.decode_packet(body)[2], meta):
                    if entry[:2] == (0, 0):
                        paid.append((path, role))
            depart(reverse, path, kind, body, size, meta)
        net.depart = observe
        flow.submit(b"source")
        flow.repair(0, (0,))
        clock.until(.25)
        assert paid == ([(1, "fresh")] if copies == 1 else [(1, "fresh"), (2, "named_copy")])
        assert flow.counts["a3_adopted_unstaged_fresh"] == 1 and not flow.tx


def test_shared_service_retains_cross_path_debt_until_other_unpaid_intent_finishes():
    clock = Clock()
    cfg = PathConfig(2, 2, (1500,)*2, (500,)*2, (1000,)*2,
                     rank_requests=True, physical_recovery=True, shared_pending=True)
    net = PathNetwork(clock, cfg, 2, (bytes, bytes))
    flow = net.directions[0]
    flow.submit(b"packet")
    clock.until(.002)
    flow.repair(0, (0,))
    flow.arq[0].missing(0, "timeout")
    assert flow.service.debt[(0, 0)] == {0}
    clock.until(.004)
    assert not flow.service.debt and not flow.service.owners
    assert net.totals[0]["physical_repair_paid_shards"] == 1
    assert flow.lanes[0].counts["physically_confirmed_ip_bytes"] == 0 and 0 in flow.tx


def test_named_reuses_mutable_then_frozen_first_without_extra_payment():
    clock = Clock()
    net = PathNetwork(clock, PathConfig(3, 2, (1500,)*3, (500,)*3, (1000,)*3,
                      rank_requests=True, physical_recovery=True, shared_pending=True),
                      7, (bytes, bytes))
    flow = net.directions[0]
    clock.links[0][0].free_at = .05
    flow.submit(b"one pending record")
    clock.until(.0001)
    flow.repair(0, (0,))
    assert flow.service.owners[0, 0, None].stage == "batched"
    clock.until(.04)
    flow.repair(0, (0,))
    assert flow.service.owners[0, 0, None].stage == "frozen"
    assert not flow.service.debt and flow.counts["shared_with_batched"] == 1
    assert flow.counts["shared_with_frozen"] == 1
    clock.until(.06)
    assert net.totals[0]["paid_data_entries"] == 3
    assert not net.totals[0]["with_repair_packets"]


def test_shared_service_rounds_grant_each_nonempty_class_an_entry():
    clock = Clock()
    cfg = PathConfig(1, 1, (1500,), (500,), (1000,), rank_requests=True,
                     physical_recovery=True, shared_pending=True)
    net = PathNetwork(clock, cfg, 2, (bytes, bytes))
    flow = net.directions[0]
    for _ in range(6):
        flow.submit(b"x")
    clock.until(.002)
    roles = []
    stage = flow.enqueue_now
    def record(path, entry, role):
        roles.append(role)
        return stage(path, entry, role)
    flow.enqueue_now = record
    for gid in range(3):
        flow.service.push(0, (gid, 0), "physical")
        flow.repair(gid+3, (0,))
        flow.submit(b"y")
    clock.until(.004)
    assert len(roles) == 9
    for offset in range(0, 9, 3):
        assert set(roles[offset:offset+3]) == {"physical", "named", "fresh"}


@pytest.mark.parametrize("shared", (False, True))
def test_overdue_fresh_backlog_can_share_a_turn_without_renewing_its_deadline(shared):
    clock = Clock()
    cfg = PathConfig(1, 1, (1500,), (500,), (1000,), physical_recovery=True,
                     physical_window=1, physical_reorder_packets=1, shared_pending=shared)
    net = PathNetwork(clock, cfg, 1, (bytes, bytes))
    flow = net.directions[0]
    flow.submit(b"head")
    clock.until(.001)
    for i in range(3):
        flow.submit(bytes([i]))
    clock.until(.003)
    flow.acknowledged([(0, 0, 1, ())])
    clock.until(.0031)
    assert flow.arq[0].packets[1].keys == ((1, 0), (2, 0), (3, 0))
    assert .003 <= flow.arq[0].packets[1].paid < .0031


def test_shared_driver_pays_one_datagram_per_slot_and_one_control_per_round():
    clock = Clock()
    cfg = PathConfig(3, 2, (1500,)*3, (500,)*3, (1000,)*3,
                     max_entries=(1,)*3, rank_requests=True, physical_recovery=True, shared_pending=True)
    net = PathNetwork(clock, cfg, 5, (bytes, bytes))
    flow = net.directions[0]
    handoffs = []
    send = net.send
    def capture(reverse, path, kind, payload, meta=()):
        handoffs.append((path, kind))
        return send(reverse, path, kind, payload, meta)
    net.send = capture
    for _ in range(19):
        flow.submit(b"source")
    request = wire.encode_shard_request([(0, (0,))], 3)
    flow.control("shard_request", request)
    flow.control("shard_request", request)
    clock.until(.001)
    for n in range(2):
        assert handoffs[4*n:4*n+3] == [(i, "fresh") for i in range(3)]
        assert handoffs[4*n+3][1] == "shard_request"
    assert [path for path,kind in handoffs if kind == "fresh"] == list(range(3))*19
