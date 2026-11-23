"""Small consistency checks for the offline mixed-shard budget study."""
from itertools import product
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "studies"))
from path_retry_budget import rank_cost, window_observations, window_scenarios


def test_independent_rank_failure_and_innovative_deficit_have_separate_units():
    n, p = 6, .15
    for k in range(1, n+1):
        failed = missing = 0.
        for mask in product((0,1), repeat=n):
            lost = sum(mask)
            weight = p**lost*(1-p)**(n-lost)
            deficit = max(0,k-(n-lost))
            failed += weight*(deficit>0)
            missing += weight*deficit
        assert rank_cost(n,k,p,0) == pytest.approx((failed,missing))
    assert rank_cost(6,5,1,0) == (1,5)
    assert rank_cost(6,5,0,.1) == (0,0)


def test_shared_state_can_change_joint_failure_without_changing_expected_total_losses():
    assert rank_cost(6,6,.15,.25)[1] == pytest.approx(.9)
    assert rank_cost(10,5,.15,.25)[0] > rank_cost(10,5,.15,0)[0]


def test_overlap_and_packet_sharing_do_not_create_independent_window_trials():
    observations = window_observations([False]*8+[True]+[False]*7)
    assert observations[8] == dict(windows=9,any_failed=8,probability=8/9)
    assert window_scenarios(.1,1)[13]["fitted_lag_one"] == pytest.approx(.1)
    assert window_scenarios(.1,0)[13]["independent_groups"] == pytest.approx(1-.9**13)
