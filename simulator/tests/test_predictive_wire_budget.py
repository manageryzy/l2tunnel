import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'studies'))
from predictive_wire_budget import FORMATS, budget, ideal_bound, prediction_savings_count


@pytest.fixture
def source_run():
    root = Path(__file__).resolve().parents[2]
    return json.loads((root / 'work/results-20261110/tcp-latency/aligned-record-elision-long/runs/00004.json').read_text())


def test_predictive_savings_excludes_initial_and_retry_neighbors(source_run):
    assert prediction_savings_count(source_run) == source_run['offered_frames'] - 64 - 1


def test_original_budget_reproduces_all_forward_bytes(source_run):
    row = budget(source_run, 'current_udp', '.208')
    assert row['forward_ip_bytes'] == source_run['forward_wire_bytes']
    assert row['scheduled_repairs'] == source_run['shared_scheduled_repairs']


def test_raw_crc_saves_exactly_four_bytes_per_forward_packet(source_run):
    udp = budget(source_run, 'compact_udp', '.22')
    raw = budget(source_run, 'compact_raw_crc32', '.22')
    packets = udp['source_datagrams'] + udp['scheduled_repairs'] + udp['retained_tail_repairs']
    assert udp['forward_ip_bytes'] - raw['forward_ip_bytes'] == 4 * packets


def test_full_tail_escape_is_charged(source_run):
    row = budget(source_run, 'compact_udp', '.22')
    assert row['forward_ip_bytes'] == row['source_ip_bytes'] + row['scheduled_repairs'] * 1492 + row['retained_tail_repairs'] * 1500


def test_budget_points_preserve_original_cohort_and_no_measured_claim(source_run):
    for name in FORMATS:
        row = budget(source_run, name, '.22')
        assert row['original_segments'] == source_run['offered_frames']
        assert row['candidate_measured_latency_ms'] is None
        assert row['candidate_measured_app_mbps'] is None
        assert row['protocol_frontier_eligible'] is False


def test_ideal_raw_ipv4_still_below_eighty_at_twenty_four_percent():
    assert ideal_bound('raw_ipv4', '.24')['analytical_capacity_mbps'] == pytest.approx(79.56989247311827)


def test_udp_and_raw_crc_parity_ceilings(source_run):
    udp = budget(source_run, 'compact_udp', '.22')
    raw = budget(source_run, 'compact_raw_crc32', '.22')
    assert .218 < udp['continuous_parity_ceiling_at_80_mbps'] < .219
    assert .221 < raw['continuous_parity_ceiling_at_80_mbps'] < .222
    assert udp['analytical_capacity_mbps'] < 80 < raw['analytical_capacity_mbps']


def test_packed_mask_saves_one_more_byte_per_eligible_record(source_run):
    normal = budget(source_run, 'compact_raw_crc32', '.22')
    packed = budget(source_run, 'compact_raw_crc32_packed', '.22')
    assert normal['forward_ip_bytes'] - packed['forward_ip_bytes'] == prediction_savings_count(source_run)


def test_conditional_extent_preserves_global_and_exception_cost(source_run):
    full = budget(source_run, 'compact_raw_crc32_packed', '.22')
    trimmed = budget(source_run, 'compact_raw_crc32_extent1454', '.22')
    assert 0 < trimmed['conditional_shortened_repairs'] < full['scheduled_repairs'] * 15 / 16
    assert full['forward_ip_bytes'] - trimmed['forward_ip_bytes'] == trimmed['conditional_shortened_repairs'] * 6
    assert trimmed['format_status'] == 'unverified common-record extent bound'
