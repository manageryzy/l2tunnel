"""Pareto eligibility must include delivery and per-replication delay limits."""

import importlib.util
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "l2_pareto_study", Path(__file__).resolve().parents[1] / "studies" / "l2_pareto.py"
)
study = importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)


def point(name, overhead, goodput, *, completion=1, delay=40):
    return {"strategy": name, "l2_extra_wire_pct_mean": overhead,
            "l2_goodput_mbps_mean": goodput, "min_delivery_fraction": completion,
            "max_p99_ms": delay, "rtt_ms": 70}


def test_frontier_excludes_incomplete_and_dominated_candidates():
    points = [point("unfinished", 10, 100, completion=.9), point("low cost", 30, 60),
              point("dominated", 40, 50), point("fast", 50, 70), point("same cost", 50, 65)]
    assert [r["strategy"] for r in study.frontier(points)] == ["low cost", "fast"]


def test_delay_budget_uses_worst_replication_and_can_leave_empty_frontier():
    points = [point("low cost", 30, 60, delay=50), point("low delay", 50, 55, delay=39)]
    assert [r["strategy"] for r in study.frontier(points, maximum_extra_delay=5)] == ["low delay"]
    assert study.frontier(points, maximum_extra_delay=1) == []
