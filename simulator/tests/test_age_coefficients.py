"""Age taps must preserve causal ranges, coefficient cancellation and the control."""

import importlib
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
study = importlib.import_module("rtt_age_coefficients")


def test_seed_range_reconstruction_and_age_band_transitions():
    for profile in study.PROFILES[1:]:
        seed = study.SERIAL_MULTIPLIER
        next_seed = (1 + profile["lanes"]) * study.SERIAL_MULTIPLIER & 0xffffffff
        width = profile["tap_width"]
        end = 256
        changed = []
        for source in range(end - 128, end):
            first = study.repair_coefficient(profile, seed, source, end)
            same_age_band = study.repair_coefficient(profile, next_seed, source, end)
            next_band = study.repair_coefficient(profile, seed, source, end + width)
            assert first == same_age_band
            band = (end - 1 - source) // width
            assert first == study.coefficient(0x5A000000 + 256 * (1 % profile["lanes"]) + band, source)
            changed.append(first != next_band)
        assert sum(changed) > 120
        global_seed = 16 * study.SERIAL_MULTIPLIER & 0xffffffff
        assert all(study.repair_coefficient(profile, global_seed, source, end) == study.coefficient(global_seed, source)
                   for source in range(end - 128, end))


def test_dense_control_preserves_every_observation_and_restores_hooks():
    task = dict(analytic_case_id=1, profile=study.PROFILES[0], seed=20261110,
                source_count=1000, warmup_sources=100, tail_sources=100)
    original_support, original_coefficient = study.reference.support, study.reference.coefficient
    expected = study.reference.execute(task)
    actual = study.execute(task)
    assert {key: actual[key] for key in expected if key != "record_kind"} == {
        key: expected[key] for key in expected if key != "record_kind"}
    assert study.reference.support is original_support
    assert study.reference.coefficient is original_coefficient


def test_both_cli_entrypoints():
    root = Path(__file__).resolve().parents[2]
    for arguments in (["simulator/studies/rtt_age_coefficients.py", "--help"],
                      ["-m", "simulator.studies.rtt_age_coefficients", "--help"]):
        result = subprocess.run([sys.executable, *arguments], cwd=root, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert "--workers" in result.stdout


def test_each_policy_keeps_one_color_across_all_panels(tmp_path):
    rows = [dict(policy=profile["name"], seed=seed, analytic_case_id=index * 3 + offset + 1,
                 deadline_miss_fraction=.02, unresolved_at_horizon_fraction=0,
                 recovered_only_created_to_known_p99_ms=50,
                 ideal_application_service_ceiling_mbps=80)
            for index, profile in enumerate(study.PROFILES) for offset, seed in enumerate(study.SEEDS)]
    with patch.object(study.go.Figure, "to_html", autospec=True, return_value="chart") as html:
        study.render(tmp_path, rows, study.summarize(rows))
    figure = html.call_args.args[0]
    for profile in study.PROFILES:
        traces = [trace for trace in figure.data if trace.meta["kind"] == "raw-case"
                  and trace.name == profile["name"]]
        assert len(traces) == 4
        assert len({trace.marker.color for trace in traces}) == 1
