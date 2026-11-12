"""Non-QUIC study tests stay runnable without the optional aioquic extra."""

import os
from pathlib import Path
import re
import subprocess
import sys


def test_non_quic_studies_collect_and_execute_without_aioquic(tmp_path):
    # Block imports only in this owned child interpreter. The caller's packages
    # and already-imported QUIC adapters are not changed.
    (tmp_path / "sitecustomize.py").write_text('''
import importlib.abc
import sys

class NoAioquic(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "aioquic" or fullname.startswith("aioquic."):
            raise ModuleNotFoundError("optional aioquic deliberately unavailable", name="aioquic")

sys.meta_path.insert(0, NoAioquic())
''', encoding="utf-8")
    # Exercise payload_sizes.execute as well as its imported RTT helper. Existing
    # payload-size/FEC test modules independently skip the whole file without
    # aioquic, so these two small native/compact cases cover the lazy boundary.
    (tmp_path / "test_payload_without_quic.py").write_text('''
import pytest
import payload_sizes

@pytest.mark.parametrize("profile_index", [0, 2])
def test_payload_execution_keeps_tcp_metrics(profile_index):
    profile = dict(payload_sizes.default_profiles()[profile_index], window_bytes=2560)
    task = dict(run_id=1, profile=profile, forward_mbps=100, reverse_mbps=10,
                rtt_ms=20, loss_rate=0, loss_model="iid", payload_bytes=256,
                duration_s=.15, warmup_s=.03, drain_s=.3, replication=1, seed=42)
    row = payload_sizes.execute(task)
    assert row["payload_bytes_per_frame"] == 256
    assert row["tcp_ack_rtt_samples"] > 0
    assert row["quic_latest_rtt_p50_ms"] is None
    assert row["measurement_payload_kind"] == "modeled TCP application data"
''', encoding="utf-8")
    simulator = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(
        [str(tmp_path), str(simulator / "src"), str(simulator / "studies")]),
        PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
        str(simulator / "tests/test_syn_measurement_window.py"),
        str(simulator / "tests/test_compact_wire_study.py"),
        str(simulator / "tests/test_predictive_wire_budget.py"),
        str(tmp_path / "test_payload_without_quic.py")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    summary = re.search(r"(\d+) passed, (\d+) skipped", result.stdout)
    assert summary is not None, result.stdout
    assert int(summary[1]) == 25, result.stdout
    assert int(summary[2]) == 2, result.stdout
