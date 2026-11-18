from copy import deepcopy
from pathlib import Path

import pytest

from l2tunnel_sim.packed_frame_path import PackedFramePath
from test_mux_tcp import mux_case


@pytest.mark.parametrize("loss,drain,cost", [(0, .3, 10), (.26, .02, 100)])
def test_passive_original_frame_path_matches_unchanged_simulator(monkeypatch, loss, drain, cost):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    from aggregate_ack_deadlines import execute

    case = mux_case(loss=loss)
    case["profile"]["compact"].update(pack_sources_max_delay_ms=.5)
    case.update(duration_s=.35, warmup_s=.08, drain_s=drain,
                packed_receiver_cost=dict(packet_us=cost,metadata_ns=0,gf_ns_per_byte=0,waiting_slots=8))
    control = execute(deepcopy(case))
    observers = []
    result = execute(deepcopy(case), observe_packed=lambda sim, services: observers.append(PackedFramePath(sim, services)))
    del control["compute_seconds"], result["compute_seconds"]
    assert control == result
    report = observers[0].report(warmup_s=case["warmup_s"])
    all_segments = report["cohorts"]["all"]
    assert all_segments["submitted"] == result["with_drain_tcp_application_delivery_cohort_offered_segments"]
    assert all_segments["censored"] == result["with_drain_tcp_application_delivery_cohort_censored_segments"]
    assert all_segments["completed"] == result["with_drain_tcp_application_delivery_cohort_completed_segments"]
    assert all_segments["completed"] and bool(all_segments["censored"]) == bool(loss)
    tail = all_segments["slowest_completed_1pct"]
    assert sum(tail["phase_mean_ms"].values()) == pytest.approx(tail["mean_total_ms"])
    example = all_segments["worst_examples"][0]
    assert sum(example["phase_ms"].values()) == pytest.approx(example["total_ms"])
    assert example["phase_ms"]["propagation"] == pytest.approx(case["rtt_ms"] / 2)
    assert example["phase_ms"]["decoder_service"] == pytest.approx(cost / 1000)
