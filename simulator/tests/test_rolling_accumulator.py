"""Repeated absolute-source coefficients must cancel only their shared support."""

import importlib
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_rolling_accumulator")


def test_same_lane_overlap_cancels_and_global_slots_keep_fresh_coefficients():
    for profile in study.PROFILES[1:]:
        first = 1
        second = first + profile["lanes"]
        if second % 16 == 0:
            second += profile["lanes"]
        first_seed = first * study.SERIAL_MULTIPLIER & 0xffffffff
        second_seed = second * study.SERIAL_MULTIPLIER & 0xffffffff
        left = {source: study.repair_coefficient(profile, first_seed, source) for source in range(100, 228)}
        right = {source: study.repair_coefficient(profile, second_seed, source) for source in range(110, 238)}
        assert all(left[source] ^ right[source] == 0 for source in range(110, 228))
        seed = 16 * study.SERIAL_MULTIPLIER & 0xffffffff
        assert all(study.repair_coefficient(profile, seed, source) == study.coefficient(seed, source)
                   for source in range(100, 228))


def test_dense_control_is_identical_and_reference_hooks_are_restored():
    task = dict(analytic_case_id=1, profile=study.PROFILES[0], seed=20261110,
                source_count=1000, warmup_sources=100, tail_sources=100)
    original_support, original_coefficient = study.reference.support, study.reference.coefficient
    expected = study.reference.execute(task)
    actual = study.execute(task)
    assert {key: actual[key] for key in expected if key != "record_kind"} == {
        key: expected[key] for key in expected if key != "record_kind"}
    assert study.reference.support is original_support
    assert study.reference.coefficient is original_coefficient
