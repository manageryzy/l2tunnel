"""Separate application admission, TCP issue, delivery and cumulative credit."""
import pytest

from l2tunnel_sim.config import PathConfig, Scenario, Strategy, Traffic
from l2tunnel_sim.tcp import PlainTCP
from l2tunnel_sim.tcp_application import PacedSocketWriter


def test_application_credit_includes_unsent_and_drains_past_offer_cutoff():
    flow = PlainTCP(Scenario(70, 0), Traffic(payload_bytes=512, duration_s=.012, drain_s=2, ack_every=1),
                    (PathConfig(),), Strategy("one", mode="tcp", tcp_initial_cwnd=1), 1)
    writer = PacedSocketWriter(flow, 4 * 512, 4_096_000, 10)
    at_cutoff = {}
    flow.at(flow.traffic.duration_s, lambda: at_cutoff.update(writer.outstanding()))
    flow.run()
    assert at_cutoff == dict(written=4, issued=1, acked=0, socket_unsent_bytes=1536, tcp_unacked_bytes=512)
    got = writer.report()
    assert got["peak_outq_bytes"] == 2048
    assert got["offered_records"] == 12 and got["scheduled_unwritten"] == 8
    assert got["fully_read"] == got["written_records"] == got["cumulatively_acked"] == 4
    assert got["end_unconfirmed"] == got["end_unsent"] == 0
    assert got["credit_denials"] > 0 and flow.sent_times[-1] > flow.traffic.duration_s
    assert got["write_to_issue_ms"]["p99"] > 60
    assert got["write_to_read_ms"]["p99"] > got["issue_to_read_ms"]["p99"] + 60


def test_writer_uses_absolute_offer_slots_and_repolls_after_credit_frees():
    flow = PlainTCP(Scenario(10, 0), Traffic(payload_bytes=512, duration_s=.045, drain_s=1, ack_every=1),
                    (PathConfig(),), Strategy("one", mode="tcp"), 1)
    writer = PacedSocketWriter(flow, 512, 4_096_000, 1)
    flow.run()
    got = writer.report()
    assert writer.due_ns(3) == 3_000_000
    assert got["peak_outq_bytes"] == 512 and got["offered_records"] == 45
    assert 2 < got["written_records"] < 10
    assert list(writer.writes) == flow.sent_times
    assert got["write_to_issue_ms"]["p99"] == 0
    assert got["scheduled_to_read_ms"]["p99"] > got["write_to_read_ms"]["p99"] + 10
    assert got["written_records"] == got["cumulatively_acked"]


def test_writer_refuses_insufficient_credit_before_installation():
    flow = PlainTCP(Scenario(70, 0), Traffic(payload_bytes=512), (PathConfig(),), Strategy("one", mode="tcp"), 1)
    with pytest.raises(ValueError, match="one record"):
        PacedSocketWriter(flow, 511, 4_096_000, 1)
    assert flow.produce == flow.__class__.produce.__get__(flow) and not flow.events


def test_segmented_writer_preserves_record_boundaries_and_partial_final_segment():
    flow = PlainTCP(Scenario(70, 0), Traffic(payload_bytes=512, duration_s=.012, drain_s=2, ack_every=1),
                    (PathConfig(),), Strategy("one", mode="tcp", tcp_initial_cwnd=1), 1)
    writer = PacedSocketWriter(flow, 4 * 512, 4_096_000, 1, tcp_mss=1448)
    flow.run()
    assert list(flow.segment_offsets) == [0, 512, 1960, 2048]
    assert flow.forward.pending_bytes == flow.reorder_bytes == 0
    assert flow.forward.delivered_bytes == 2048 + 3 * 66
    got = writer.report()
    assert got["packetization"]["issued_segments"] == 3
    assert got["packetization"]["issued_bytes"] == got["packetization"]["cumulatively_acked_bytes"] == 2048
    assert got["fully_read"] == got["written_records"] == got["cumulatively_acked"] == 4
    assert got["write_to_read_ms"]["n"] == 4 and got["end_unconfirmed"] == 0
    assert got["peak_outq_bytes"] == 2048 and got["packetization"]["full_size_segments"] == 1


def test_segmented_loss_reuses_byte_interval_and_actual_byte_charge():
    from l2tunnel_sim.experiment import measure

    flow = PlainTCP(Scenario(20, 0), Traffic(payload_bytes=512, duration_s=.010, drain_s=4, ack_every=1),
                    (PathConfig(),), Strategy("one", mode="tcp", tcp_initial_cwnd=1), 2)
    writer = PacedSocketWriter(flow, 5 * 512, 4_096_000, 1, tcp_mss=1448)
    charges = []
    send = flow.send

    def drop_once(reverse, size, kind, callback):
        if not reverse:
            charges.append((size, kind))
            if len(charges) == 2:
                callback = lambda: None
        return send(reverse, size, kind, callback)

    flow.send = drop_once
    flow.run()
    assert charges == [(564, "source"), (1500, "source"), (1500, "retry"), (652, "source")]
    assert list(flow.segment_offsets) == [0, 512, 1960, 2560]
    assert measure(flow)["tcp_payload_bytes"] == writer.report()["cumulatively_acked"] * 512 == 2560
    assert flow.forward.pending_bytes == 0 and flow.tcp_timeouts == 1
