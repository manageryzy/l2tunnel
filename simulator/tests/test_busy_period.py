"""Finite independent checks for the busy-period diagnostic's defined models."""

from collections import defaultdict, deque
import importlib
from itertools import product
from pathlib import Path
import subprocess
import sys

import numpy as np
import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_busy_period")


def brute_tagged(events, initial, model):
    probability = 0.
    for erased in product((False, True), repeat=len(events)):
        weight = np.prod([study.LOSS if lost else 1 - study.LOSS for lost in erased])
        queue = deque([False] * initial)
        deficit = initial
        tagged_waiting = False
        for (kind, tag), lost in zip(events, erased):
            if kind == "source" and lost:
                deficit += 1
                queue.append(tag)
                tagged_waiting |= tag
            elif kind == "repair" and not lost and deficit:
                deficit -= 1
                queue.popleft()
                if not deficit:
                    tagged_waiting = False
        if tagged_waiting if model == "dense" else any(queue):
            probability += weight
    return probability


def test_tagged_recurrence_matches_all_finite_erasure_patterns():
    cases = 0
    for chunks in (1, 2, 3):
        events = [("source", True)] * chunks + [("repair", False), ("source", False),
                  ("repair", False), ("source", False), ("repair", False)]
        for initial in (0, 1, 3):
            for model in ("dense", "fifo_oracle"):
                clear, waiting = np.zeros(16), np.zeros(16)
                clear[initial] = 1
                for kind, tag in events:
                    clear, waiting = study.tagged_step(clear, waiting, kind, tag, model)
                assert waiting.sum() == pytest.approx(brute_tagged(events, initial, model), abs=1e-13)
                cases += 1
    assert cases == 18


def test_reflected_queue_matches_independent_state_dictionary():
    values = np.zeros(20)
    values[0] = 1
    law = {0: 1.}
    for kind in ("source", "source", "repair", "source", "repair", "repair", "source"):
        updated = defaultdict(float)
        for queue, mass in law.items():
            if kind == "source":
                updated[queue] += mass * .85
                updated[queue + 1] += mass * .15
            else:
                updated[queue] += mass * .15
                updated[max(0, queue - 1)] += mass * .85
        law = updated
        values = study.birth(values) if kind == "source" else study.death(values)
        assert values == pytest.approx([law.get(index, 0) for index in range(20)])


def test_charged_geometry_and_all_chunks_keep_original_timestamp():
    for format_index in range(4):
        for chunks in (1, 2, 3, 4):
            config = study.profile(format_index, chunks)
            events = study.schedule(config, 375)
            assert sum(event[4] for event in events[:len(events) // 3]) == config["period_bytes"]
            assert len([event for event in events if event[1] == "repair"]) == 78 * chunks
            assert sum(config["chunk_bytes"]) == config["record_bytes"]
            assert max(event[4] for event in events) <= 1500
            assert config["offered_application_mbps"] <= 80
            assert config["allows_80_mbps"] == (config["arrival_ns"] == 144800)
            previous = 0
            for original, _, _, finish, size in events:
                assert finish - size * 80 >= original * config["arrival_ns"]
                assert finish - previous >= size * 80
                previous = finish
            middle = [event for event in events if 125 <= event[0] < 250]
            final = [event for event in events if 250 <= event[0] < 375]
            assert all(right[3] - left[3] == 125 * config["arrival_ns"] for left, right in zip(middle, final))
    assert study.profile(0, 1)["ip_bytes_per_original"] == 1808
    assert study.profile(0, 1)["byte_service_ceiling_mbps"] > 80
    assert study.profile(1, 2)["byte_service_ceiling_mbps"] < 80
    assert study.profile(2, 2)["byte_service_ceiling_mbps"] > 80
    assert study.profile(2, 3)["byte_service_ceiling_mbps"] < 80


def test_finite_cohort_laws_preserve_phase_denominator_and_mass():
    law, counts, defect = study.cohort_laws(study.profile(0, 1))
    assert len(law) == 125
    assert counts.sum() == 16000
    assert set(counts) == {128}
    assert abs(defect) < 1e-10
    assert np.max(abs(law.sum(axis=1) - 1)) < 1e-10


def test_exact_tail_monotonicity_and_oracle_relation():
    result, defect = study.exact_tails(study.profile(0, 1), (10, 35, 70))
    assert np.all(np.diff(result["dense"]) < 0)
    assert np.all(np.diff(result["fifo_oracle"]) < 0)
    assert np.all(result["fifo_oracle"] < result["dense"])
    assert .02 < result["dense"][1] < .025
    assert abs(defect) < 1e-10


def test_matched_trajectory_and_shortening_guard():
    rows = study.trajectory(20261110, study.profile(0, 1))
    assert rows[0]["deadline_misses"] == 544
    assert rows[1]["deadline_misses"] == 0
    assert rows[0]["measured_originals"] == 16000
    assert rows[0]["forward_wire_bytes"] == 20000 * 1496 + 4160 * 1500
    assert rows[0]["erasure_trace_sha256"] == rows[1]["erasure_trace_sha256"]
    with pytest.raises(ValueError):
        study.trajectory(1, study.profile(0, 2))


def test_ratio_schedule_and_conservative_mean_byte_proxies():
    for template in study.RATIO_FORMATS[:2]:
        for ratio in ("0.208", "0.218", "0.220", "0.222"):
            config = study.profile(0, 1, ratio, template)
            events = study.schedule(config, config["phase_period"])
            assert sum(event[4] for event in events) == config["period_bytes"]
            assert sum(event[1] == "repair" for event in events) == config["repair_numerator"]
            assert all(event[3] == int(event[3]) for event in events)
    assert study.profile(0, 1, ".222", study.RATIO_FORMATS[0])["allows_80_mbps"]
    assert study.profile(0, 1, ".218", study.RATIO_FORMATS[1])["allows_80_mbps"]
    assert not study.profile(0, 1, ".220", study.RATIO_FORMATS[1])["allows_80_mbps"]


@pytest.mark.parametrize("module", (False, True))
def test_cli_help_from_repository_root(module):
    root = Path(__file__).resolve().parents[2]
    arguments = ["-m", "simulator.studies.rtt_busy_period"] if module else ["simulator/studies/rtt_busy_period.py"]
    result = subprocess.run([sys.executable, *arguments, "--help"], cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
