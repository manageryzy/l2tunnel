import importlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture
def study(monkeypatch):
    simulator = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(simulator))
    monkeypatch.syspath_prepend(str(simulator / "studies"))
    return importlib.import_module("lrsc_staircase")


def test_staircase_support_is_absolute_and_causal(study):
    equation = study.parity_equation(300, 48)
    assert len(equation) == 240
    assert min(symbol // 5 for symbol in equation) == 13
    assert max(symbol // 5 for symbol in equation) == 299
    for group in range(48):
        for shard in range(5):
            symbol = (300 - 5 - 6 * group + shard) * 5 + shard
            assert equation[symbol] == study.coefficients(48)[group][shard]


def test_staircase_has_no_negative_source_indices(study):
    assert study.parity_equation(0, 48) == {}
    assert set(study.parity_equation(1, 48)) == {4}
    with pytest.raises(ValueError):
        study.coefficients(252)


def test_independent_numeric_rank_and_actual_byte_recovery(study):
    receipt = study.validate()
    assert receipt["independent_numeric_states"] == 48
    assert receipt["rank_and_payload_values_match"]


def test_hook_is_restored_after_failure(study, monkeypatch):
    original = study.reference.parity_equation

    def fail(task):
        raise RuntimeError("expected test failure")

    monkeypatch.setattr(study.reference, "execute", fail)
    with pytest.raises(RuntimeError, match="expected test failure"):
        study.execute({"profile": {"staircase_groups": 16}})
    assert study.reference.parity_equation is original


def test_normal_entry_preserves_exact_bytes_and_charges(study):
    row = study.execute(dict(analytic_case_id=0, seed=7, packet_count=100,
        warmup_packets=20, tail_packets=20, loss_rate=0,
        profile=dict(name="test a16", staircase_groups=16, memory=95, invariant=True)))
    assert row["forward_wire_bytes_analytic"] == 150000
    assert row["source_count"] == 60
    assert row["source_unresolved_count"] == row["source_deadline_miss_count"] == 0
    assert row["record_inorder_unresolved_count"] == row["record_inorder_deadline_miss_count"] == 0
    assert row["actual_reconstructed_frame_bytes"] == row["full_input_records_delivered"] * 1514


@pytest.mark.parametrize("as_module", (False, True))
def test_cli_help_from_normal_entrypoints(as_module):
    root = Path(__file__).resolve().parents[2]
    arguments = ["-m", "studies.lrsc_staircase"] if as_module else ["simulator/studies/lrsc_staircase.py"]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run([sys.executable, *arguments, "--help"],
        cwd=root / "simulator" if as_module else root,
        env=environment, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert "--out" in result.stdout
    assert "--workers" in result.stdout


def test_mean_frontier_excludes_incomplete_cohorts_and_keeps_exact_ties(study):
    rows = []
    for policy, miss, unresolved in (("incomplete", .01, 1), ("best", .05, 0),
                                      ("dominated", .06, 0), ("tied", .05, 0)):
        for seed in study.reference.SEEDS:
            row = dict(policy=policy, seed=seed, offered_application_rate_mbps_analytic=80.2795)
            for prefix in ("source", "record_local", "record_inorder"):
                row.update({prefix + "_count": 100, prefix + "_unresolved_count": unresolved,
                            prefix + "_deadline_miss_fraction": miss})
            rows.append(row)
    assert {point["policy"] for point in study.configuration_frontier(rows, "source")} == {"best", "tied"}
