"""Keep RACK congestion targets independent of bytes awaiting cumulative TCP ACK."""
import pytest

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.tcp import PlainTCP, Segment
from l2tunnel_sim.tcp_application import PacedSocketWriter
from l2tunnel_sim.tcp_dsack import DuplicateUndo
from l2tunnel_sim.tcp_rack import RackScoreboard
from l2tunnel_sim.tcp_sack import WireAck


def loss_flow(controller, window, count):
    flow = PlainTCP(Scenario(70, 0), Traffic(), (PathConfig(),),
                    Strategy("sender", mode="tcp", tcp_cc=controller), 1)
    flow.window_limit = 2048
    flow.cwnd, flow.ssthresh = window, 1600
    flow.forward.pending = {i: Segment(attempts=1) for i in range(count)}
    flow.forward.pending_bytes = count * flow.smss_bytes
    flow.sent_times = [0] * count
    flow.segment_offsets = [i * flow.smss_bytes for i in range(count + 1)]
    flow.source_timer = 1  # This fixture drives only ACK and recovery events.
    return flow


def attach_sender(flow):
    flow.rack = flow.sack_sender = RackScoreboard(flow, flow.window_limit)
    flow.dsack_undo = DuplicateUndo(flow.window_limit, flow.rack.stats)

    def submit(index):
        segment = flow.forward.pending[index]
        if segment.attempts:
            assert flow.rack.mark_retry(index, flow.recover, int(flow.now * 1000))
            flow.dsack_undo.retry(index, segment.attempts)
        segment.attempts += 1
        segment.last_sent_at = flow.now
        flow.rack.sent(index)

    flow.transmit_segment = submit


def enter_recovery(flow):
    attach_sender(flow)
    flow.now = .05
    last = len(flow.sent_times) - 1
    selective = WireAck(0, ((flow.byte_offset(last), flow.byte_offset(last + 1)),), False, 50, 0)
    flow.rack.observe(selective, 0, flow.segment_offsets)
    flow.rack.lost.add(0)
    flow.rack.service(flow)
    assert flow.in_recovery and flow.forward.pending[0].attempts == 2


@pytest.mark.parametrize("controller,cwnd,custody,target,entry", [
    ("cubic", 740.39165, 1532, 518, 518),
    ("cubic", 38, 100, 26, 26),
    ("reno", 19.9, 100, 9, 9),
    ("cubic", 1, 4, 2, 1),
    ("reno", 2, 4, 2, 2),
])
def test_rack_entry_uses_controller_threshold_and_never_increases_cwnd(controller, cwnd, custody, target, entry):
    flow = loss_flow(controller, cwnd, custody)
    enter_recovery(flow)
    assert flow.ssthresh == target and flow.cwnd == entry
    assert flow.cwnd <= cwnd and len(flow.forward.pending) == custody


def test_rack_recovery_exit_uses_target_and_verified_dsack_can_restore_prior_window():
    flow = loss_flow("cubic", 38, 100)
    enter_recovery(flow)
    flow.now = .1
    flow.on_ack(100)
    assert not flow.in_recovery and not flow.forward.pending
    assert flow.cwnd == flow.ssthresh == 26
    assert not flow.dsack_undo.finish(flow)
    duplicate = WireAck(flow.byte_offset(100), ((0, flow.byte_offset(1)),), True, 100, 0)
    flow.dsack_undo.observe(duplicate, flow.segment_offsets, flow.rack, flow.tcp_acked)
    assert flow.dsack_undo.finish(flow)
    assert (flow.cwnd, flow.ssthresh) == (38, 1600)


def test_legacy_reduction_preserves_its_original_flight_estimate():
    flow = loss_flow("cubic", 38, 100)
    flow.reduce_window()
    assert flow.ssthresh == 70 and flow.cwnd == 38


def test_each_new_selective_delivery_grants_proportional_credit_once():
    flow = loss_flow("cubic", 34, 34)
    enter_recovery(flow)
    rack = flow.rack
    assert (flow.ssthresh, rack.prr_prior, rack.prr_delivered, rack.prr_out) == (23, 34, 1, 1)
    ack = WireAck(0, ((flow.byte_offset(32), flow.byte_offset(34)),), False, 51, 0)
    flow.now += .001
    rack.observe(ack, 0, flow.segment_offsets)
    rack.lost.add(1)
    rack.service(flow)
    assert flow.forward.pending[1].attempts == 2
    assert (rack.prr_delivered, rack.prr_out, rack.send_credit()) == (2, 2, 0)
    rack.observe(ack, 0, flow.segment_offsets)
    rack.service(flow)
    rack.service(flow)
    assert (rack.prr_delivered, rack.prr_out, rack.send_credit()) == (2, 2, 0)


def test_original_and_retry_share_credit_and_only_clean_cumulative_advance_adds_a_slot():
    flow = loss_flow("cubic", 20, 5)
    enter_recovery(flow)
    rack = flow.rack
    flow.ssthresh = 14
    flight = rack.pipe(5)
    rack.update_prr(2, 1, True)
    assert rack.send_credit() == 2
    rack.update_prr(1, 0, True)
    assert rack.send_credit() == 4
    flow.forward.pending[5] = Segment(last_sent_at=flow.now, attempts=1)
    rack.sent(5)
    assert (rack.send_credit(), rack.prr_out, rack.pipe(6)) == (3, 2, flight + 1)
    assert rack.stats["prr_originals"] == 1 and rack.stats["prr_retries"] == 1


def test_reordering_timer_only_grants_one_synthetic_delivery_on_entry():
    flow = loss_flow("cubic", 8, 8)
    attach_sender(flow)
    rack = flow.rack
    flow.now = .12
    rack.latest = (0, 1)
    rack.min_rtt = rack.recent_rtt = .07
    rack.armed = rack.deadline = flow.now
    rack.on_timer(flow.now)
    assert (rack.delivered, rack.prr_delivered, rack.prr_out, rack.stats["prr_timer_entries"]) == (0, 1, 1, 1)
    rack.latest = (0, 2)
    flow.now += .001
    rack.armed = rack.deadline = flow.now
    rack.on_timer(flow.now)
    assert (rack.delivered, rack.prr_delivered, rack.stats["prr_timer_entries"]) == (0, 1, 1)


def test_writer_cannot_reuse_an_allowance_spent_on_fresh_data():
    flow = loss_flow("cubic", 5, 0)
    writer = PacedSocketWriter(flow, 16 * flow.smss_bytes, 1_000_000, 16, tcp_mss=flow.smss_bytes)
    writer.writes.extend([0] * 8)
    writer.send_available()
    assert len(flow.sent_times) == 5
    flow.cwnd = 20
    enter_recovery(flow)
    rack = flow.rack
    assert rack.send_credit() == 0
    ack = WireAck(0, ((flow.byte_offset(3), flow.byte_offset(5)),), False, 51, 0)
    flow.now += .001
    rack.observe(ack, 0, flow.segment_offsets)
    writer.send_available()
    writer.send_available()
    assert len(flow.sent_times) == 6
    assert (rack.stats["prr_retries"], rack.stats["prr_originals"], rack.send_credit()) == (1, 1, 0)


def process_wire_ack(flow, edge, *blocks, dsack=False):
    ack = WireAck(flow.byte_offset(edge), tuple((flow.byte_offset(a), flow.byte_offset(b)) for a,b in blocks),
                  dsack, 50, 0)
    flow.rack.observe(ack, edge, flow.segment_offsets)
    flow.on_ack(edge)
    flow.rack.service(flow)


def test_high_reordering_slow_start_counts_first_ordinary_delivery_once():
    flow = loss_flow("cubic", 10, 20)
    attach_sender(flow)
    flow.now = .05
    flow.window_was_full = True
    flow.rack.stats["reordering_segments"] = 34
    process_wire_ack(flow, 0, (1,3))
    assert flow.cwnd == 12
    process_wire_ack(flow, 0, (1,3))
    process_wire_ack(flow, 0, (1,2), (1,3), dsack=True)
    flow.rack.service(flow)
    assert flow.cwnd == 12
    counts = []
    ordinary = flow.increase_window
    def increase(segments):
        counts.append(segments)
        ordinary(segments)
    flow.increase_window = increase
    process_wire_ack(flow, 3)
    assert counts == [1] and flow.cwnd == 13


@pytest.mark.parametrize("reordering,threshold,prior_flight,timeout_end", [
    (3, 100, 20, 0), (34, 10, 20, 0), (34, 100, 2, 0), (34, 100, 20, 20),
])
def test_sack_only_growth_requires_high_reordering_slow_start_and_window_use(
        reordering, threshold, prior_flight, timeout_end):
    flow = loss_flow("cubic", 10, prior_flight)
    attach_sender(flow)
    flow.now = .05
    flow.ssthresh = threshold
    flow.window_was_full = prior_flight >= 10
    flow.rack.stats["reordering_segments"] = reordering
    flow.rack.rto_recovery_end = timeout_end
    process_wire_ack(flow, 0, (1,2))
    assert flow.cwnd == 10


def test_rack_recovery_and_timeout_relearning_never_reuse_slow_start_credit():
    flow = loss_flow("cubic", 11, 20)
    attach_sender(flow)
    flow.now = .05
    flow.window_was_full = True
    flow.rack.stats["reordering_segments"] = 34
    flow.rack.lost.add(0)
    process_wire_ack(flow, 0, (1,2))
    assert flow.in_recovery and flow.ssthresh == 7
    assert flow.rack.stats["rack_sack_slow_start_segments"] == 0
    flow.rack.reset()
    flow.in_recovery = False
    flow.cwnd, flow.ssthresh = 11, 100
    process_wire_ack(flow, 0, (1,2))
    assert flow.cwnd == 11
