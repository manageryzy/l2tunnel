"""Frozen-trace relaxations preserve every segment and assumption cohort."""

from pathlib import Path

import pytest


@pytest.fixture
def analysis(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    import latency_counterfactual
    return latency_counterfactual


def segment(index, sent, ready, delivered, acknowledged, *, flow=0, queue=1):
    return dict(flow_id=flow, segment_id=index, original_submission_s=sent,
                record_ready_s=ready, tcp_contiguous_delivery_s=delivered,
                cumulative_ack_completion_s=acknowledged, source_queue_and_serialization_ms=queue,
                original_extra_field="preserved")


def test_tcp_prefix_retains_earlier_hole_and_independent_flows(analysis):
    rows = [segment(0, 0, .080, .080, .120),
            segment(1, .010, .045, .080, .120),
            segment(0, .010, .045, .045, .085, flow=1)]
    result = analysis.counterfactual_rows(rows, 70)
    assert len(result) == len(rows)
    assert all(row["original_extra_field"] == "preserved" for row in result)
    assert result[1]["tcp_prefix_latency_ms"] == pytest.approx(105)
    assert result[1]["own_ready_latency_ms"] == pytest.approx(70)
    assert result[2]["tcp_prefix_latency_ms"] == pytest.approx(70)
    for row in result:
        assert all(0 <= row[case + "_latency_ms"] <= row["observed_latency_ms"] for case in analysis.CASES)


@pytest.mark.parametrize("changes", [{"segment_id": 1}, {"record_ready_s": ""},
    {"cumulative_ack_completion_s": .060}, {"source_queue_and_serialization_ms": -1}])
def test_missing_duplicate_or_noncausal_segments_fail_explicitly(analysis, changes):
    row = segment(0, 0, .040, .040, .080)
    row.update(changes)
    with pytest.raises(ValueError):
        analysis.counterfactual_rows([row], 70)


def test_duplicate_segments_cannot_disappear_from_denominator(analysis):
    row = segment(0, 0, .040, .040, .080)
    with pytest.raises(ValueError, match="exactly once"):
        analysis.counterfactual_rows([row, row], 70)


def test_frontier_separates_assumptions_and_cohorts_and_retains_ties(analysis):
    def point(case, latency, goodput, cohort="a", eligible=True):
        return dict(case_id=case, cohort=cohort, latency_p99_ms=latency,
                    source_measured_app_mbps=goodput, analytical_eligible=eligible)
    points = [point("observed", 150, 80), point("observed", 160, 79),
              point("optimistic", 110, 81), point("observed", 160, 79, "other"),
              point("observed", 150, 80), point("observed", 1, 100, eligible=False)]
    result = analysis.eligible_frontier(points)
    assert result == [points[index] for index in (0, 2, 3, 4)]


def test_summary_uses_every_original_segment(analysis):
    result = analysis.latency_summary([70, 80, 105, 106], 105)
    assert result["segment_count"] == 4
    assert result["deadline_miss_count"] == 1
    assert result["deadline_miss_fraction"] == .25
