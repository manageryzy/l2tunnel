"""Selective fallback consumes charged, finite-width, causally received state."""

import importlib
from pathlib import Path
from struct import error as StructError
import sys
import subprocess

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"studies"))
study=importlib.import_module("rtt_selective_fallback")


def report(serial=1,bitmap=0,count=4,echo=0):
    return study.Feedback(serial,0,0,count,10,echo,bitmap)


def test_feedback_has_exact_charged_size_and_round_trips():
    packet=study.Feedback(1,3,3,1024,2000,77,(1<<1023)|2)
    wire=packet.encode()
    assert len(wire)+28==180
    assert study.Feedback.decode(wire)==packet
    with pytest.raises(StructError):
        study.Feedback(1<<32,0,0,1,2,0,0).encode()
    with pytest.raises(ValueError):
        study.Feedback(1,0,0,1,2,0,2).encode()


def test_repair_header_reconstructs_support_and_serial_without_side_data():
    seed = 16 * study.SERIAL_MULTIPLIER & 0xffffffff
    scalar = study.REPAIR_FIELDS.pack(7, 1, seed, 1)
    assert len(scalar) + 28 + 1460 == 1500
    assert study.repair_equation(scalar) == ({7: 1}, 8, 16)
    dense = study.REPAIR_FIELDS.pack(7, 3, seed, 0)
    assert study.repair_equation(dense) == ({index:study.coefficient(seed,index) for index in range(7,10)},10,16)
    with pytest.raises(ValueError):
        study.repair_equation(study.REPAIR_FIELDS.pack(7,2,seed,1))


def test_out_of_page_and_inflight_sources_are_never_inferred_missing():
    sender=study.SelectiveSender("oldest")
    sender.accept(report(bitmap=0b1010))
    assert set(sender.missing)=={0,2}
    assert sender.choose(10,1000) is None
    assert sender.choose(100,100) is None
    assert sender.choose(100,1000)==0


def test_positive_feedback_is_monotone_under_stale_negative_reports():
    sender=study.SelectiveSender("oldest")
    sender.accept(report(2,bitmap=1))
    sender.accept(report(1,bitmap=0))
    assert 0 in sender.confirmed and 0 not in sender.missing
    sender.accept(report(3,bitmap=0))
    assert 0 not in sender.missing


def test_retry_requires_rtt_guard_and_new_feedback_with_repair_echo():
    sender=study.SelectiveSender("oldest")
    sender.accept(report(count=1))
    sender.target(0,100,16)
    assert sender.choose(169.999,1000) is None
    assert sender.choose(170,1000) is None
    sender.accept(report(2,count=1,echo=15))
    assert sender.choose(170,1000) is None
    sender.accept(report(3,count=1,echo=16))
    assert sender.choose(170,1000)==0


@pytest.mark.parametrize("seed",[20261110,20261111])
def test_prefix_control_exactly_reproduces_previous_scheduler(seed):
    task=dict(analytic_case_id=1,profile=study.PROFILES[0],seed=seed,
              source_count=1000,warmup_sources=100,tail_sources=300)
    expected=study.reference.execute(task)
    actual,rows,targets=study.execute(task)
    assert {key:actual[key] for key in expected if key!="record_kind"}=={key:value for key,value in expected.items() if key!="record_kind"}
    assert len(rows)==1000 and len([row for row in rows if row['measured']])==600
    assert not targets


def test_bitmap_control_preserves_forward_loss_schedule_and_denominator():
    common=dict(analytic_case_id=1,seed=20261110,source_count=1000,warmup_sources=100,tail_sources=300)
    rows=[study.execute(dict(common,profile=profile))[0] for profile in study.PROFILES]
    assert len({row['packet_schedule_sha256'] for row in rows})==1
    assert len({row['forward_total_wire_bytes'] for row in rows})==1
    assert all(row['minimum_feedback_age_ms']>=70 for row in rows)
    assert rows[0]['deadline_miss_fraction']==rows[1]['deadline_miss_fraction']


@pytest.mark.parametrize("entrypoint", [
    ["simulator/studies/rtt_selective_fallback.py"],
    ["-m", "simulator.studies.rtt_selective_fallback"],
])
def test_cli_help_supports_standalone_and_module_entrypoints(entrypoint):
    result = subprocess.run(
        [sys.executable, *entrypoint, "--help"],
        cwd=Path(__file__).resolve().parents[2],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--out" in result.stdout
    assert "--workers" in result.stdout
