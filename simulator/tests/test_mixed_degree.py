"""Sparse schedule hooks must preserve the dense control and causal range."""

import importlib
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_mixed_degree")


def test_sparse_schedule_is_deterministic_and_preserves_global_slots():
    for profile in study.profiles():
        for serial in range(1, 129):
            selected = study.sparse_support(profile, 11, 139, serial)
            assert selected == study.sparse_support(profile, 11, 139, serial)
            if serial % 16 == 0 or not profile["degree"]:
                assert selected is None
            if selected is not None:
                assert len(selected) == profile["degree"]
                assert all(11 <= source < 139 for source in selected)


def test_dense_control_is_identical_and_restores_reference_hooks():
    task = dict(analytic_case_id=1, profile=study.profiles()[0], seed=20261110,
                source_count=1000, warmup_sources=100, tail_sources=100)
    original_support = study.reference.support
    original_coefficient = study.reference.coefficient
    expected = study.reference.execute(task)
    actual = study.execute(task)
    assert actual.pop("sparse_repair_packets") == 0
    actual["record_kind"] = expected["record_kind"]
    assert actual == expected
    assert study.reference.support is original_support
    assert study.reference.coefficient is original_coefficient
