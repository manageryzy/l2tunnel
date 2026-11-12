"""Avoid mixing incompatible durations, profiles, or duplicate seeds in payload plots."""

import importlib
import json
from pathlib import Path

import pytest

pytest.importorskip("aioquic")


@pytest.fixture
def report_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "studies"))
    return importlib.import_module("payload_report")


def save_study(root, name, *, seed=1, duration=10, profile=None):
    directory = root / name
    (directory / "runs").mkdir(parents=True)
    (directory / "experiment.json").write_text(json.dumps({"tasks": [{"run_id": 1}]}))
    row = dict(run_id=1, forward_mbps=100, reverse_mbps=10, rtt_ms=70, loss_rate=.15,
               strategy="test", payload_bytes=1448, seed=seed, duration_s=duration,
               warmup_s=2, drain_s=5, profile=json.dumps(profile or {"kind": "tcp"}))
    (directory / "runs/00001.json").write_text(json.dumps(row))


def test_payload_report_preserves_study_identity_and_manifest(report_module, tmp_path):
    save_study(tmp_path, "first")
    rows, manifests = report_module.load_studies(tmp_path, ["first"])
    assert rows[0]["source_study"] == "first"
    assert len(manifests["first"]["sha256"]) == 64


def test_payload_report_rejects_reused_replication(report_module, tmp_path):
    save_study(tmp_path, "first")
    save_study(tmp_path, "second")
    with pytest.raises(ValueError, match="duplicate independent replication"):
        report_module.load_studies(tmp_path, ["first", "second"])


def test_payload_report_rejects_mixed_measurement_periods(report_module, tmp_path):
    save_study(tmp_path, "first")
    save_study(tmp_path, "second", seed=2, duration=60)
    with pytest.raises(ValueError, match="duration-"):
        report_module.load_studies(tmp_path, ["first", "second"])


def test_payload_report_rejects_configurations_under_same_label(report_module, tmp_path):
    save_study(tmp_path, "first")
    save_study(tmp_path, "second", seed=2, profile={"kind": "quic"})
    with pytest.raises(ValueError, match="different transport configurations"):
        report_module.load_studies(tmp_path, ["first", "second"])
