"""Finite ECC study probability and packet-accounting regressions."""

import importlib.util
from pathlib import Path

import numpy as np
import pytest


SPEC = importlib.util.spec_from_file_location(
    'ecc_levels', Path(__file__).parents[1] / 'studies' / 'ecc_levels.py')
ecc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ecc)


def test_five_plus_one_exact_probability_and_completed_redundancy():
    result = ecc.ideal_block(5, 1, .15)
    assert result['initial_block_recovery_probability'] == pytest.approx(.776484296875)
    assert result['ideal_total_packet_redundancy_pct'] == pytest.approx(26.521165073529414)


def test_loss_count_distributions_preserve_stationary_mean():
    for model in ('iid', 'burst'):
        joint = ecc.loss_distribution(60, .15, model)
        assert joint.sum() == pytest.approx(1)
        assert np.dot(np.arange(61), joint.sum(axis=1)) == pytest.approx(9)
        assert joint[:, 1].sum() == pytest.approx(.15)


def test_zero_loss_needs_only_configured_repairs():
    for model in ('iid', 'burst'):
        result = ecc.ideal_block(20, 4, 0, model)
        assert result['initial_block_recovery_probability'] == pytest.approx(1)
        assert result['ideal_additional_repair_packets'] == 0
        assert result['ideal_total_packet_redundancy_pct'] == pytest.approx(20)


def test_no_proactive_repairs_reaches_iid_capacity_bound():
    result = ecc.ideal_block(100, 0, .15)
    assert result['ideal_total_packet_redundancy_pct'] == pytest.approx(100 * .15 / .85)


def test_real_simulation_counts_final_partial_block_and_actual_overhead():
    task = ecc.tasks(.01, 2, 1)[0]
    task['scenario']['loss_rate'] = 0
    result = ecc.execute(task)
    assert result['complete_at_cutoff']
    assert result['source_packet_baseline_complete']
    assert result['partial_code_blocks'] == 1
    assert result['forward_total_packet_redundancy_pct'] >= result['forward_data_packet_redundancy_pct']
    assert result['forward_data_packet_redundancy_pct'] >= result['initial_packet_redundancy_pct']
