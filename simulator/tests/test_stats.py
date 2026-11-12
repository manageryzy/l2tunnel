"""Independent statistical reference cases, including degenerate samples."""

import math

import pytest

from l2tunnel_sim.stats import binomial_tail_failure, mean_ci, paired_difference


def test_student_t_interval_matches_known_two_sample_reference():
    # For [1, 3], mean=2, sample SD=sqrt(2), SEM=1. A t distribution
    # with one degree of freedom is Cauchy: its .975 quantile is tan(.475*pi).
    critical_value = math.tan(0.475 * math.pi)
    result = mean_ci([1.0, 3.0])
    assert result["mean"] == 2.0
    assert result["n"] == 2
    assert result["method"] == "student_t"
    assert result["ci_low"] == pytest.approx(2.0 - critical_value)
    assert result["ci_high"] == pytest.approx(2.0 + critical_value)


def test_confidence_controls_interval_width():
    # The .75 quantile of a standard Cauchy distribution is exactly 1.
    result = mean_ci([1.0, 3.0], confidence=0.5)
    assert result["ci_low"] == pytest.approx(1.0)
    assert result["ci_high"] == pytest.approx(3.0)


def test_empty_and_singleton_samples_do_not_invent_uncertainty():
    assert mean_ci([]) == {
        "mean": None, "ci_low": None, "ci_high": None,
        "n": 0, "method": "student_t",
    }
    assert mean_ci([7.0]) == {
        "mean": 7.0, "ci_low": None, "ci_high": None,
        "n": 1, "method": "student_t",
    }


def test_constant_samples_have_finite_zero_width_interval():
    result = mean_ci([0.0, 0.0, 0.0])
    assert result["mean"] == result["ci_low"] == result["ci_high"] == 0.0


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_nonfinite_observations_are_rejected(bad):
    with pytest.raises(ValueError, match="finite"):
        mean_ci([0.0, bad])
    with pytest.raises(ValueError, match="finite"):
        paired_difference([0.0], [bad])


@pytest.mark.parametrize("confidence", [0.0, 1.0, -0.1, 1.1, math.nan, math.inf])
def test_invalid_confidence_is_rejected_even_for_empty_sample(confidence):
    with pytest.raises(ValueError, match="confidence"):
        mean_ci([], confidence=confidence)


def test_multidimensional_observations_are_rejected():
    with pytest.raises(ValueError, match="one-dimensional"):
        mean_ci([[1.0, 2.0]])


def test_paired_difference_cancels_shared_replication_variation():
    result = paired_difference([101.0, 1001.0, 11.0], [100.0, 1000.0, 10.0])
    assert result["mean"] == result["ci_low"] == result["ci_high"] == 1.0
    assert result["n"] == 3


def test_paired_difference_retains_sign_and_handles_empty_and_singleton():
    assert paired_difference([2.0], [5.0]) == mean_ci([-3.0])
    assert paired_difference([], []) == mean_ci([])
    with pytest.raises(ValueError, match="equal lengths"):
        paired_difference([1.0], [])


@pytest.mark.parametrize(
    "n,k,p,expected",
    [
        (3, 2, 0.1, 0.028),  # Exactly two losses or three losses.
        (3, 3, 0.1, 0.271),  # At least one loss: 1 - .9**3.
        (3, 1, 0.1, 0.001),  # All three packets must be lost.
        (3, 2, 0.5, 0.5),
        (0, 0, 0.7, 0.0),
        (3, 0, 1.0, 0.0),
        (3, 2, 0.0, 0.0),
        (3, 2, 1.0, 1.0),
    ],
)
def test_ideal_mds_oracle_matches_direct_probability(n, k, p, expected):
    assert binomial_tail_failure(n, k, p) == pytest.approx(expected)


def test_small_failure_tail_is_not_rounded_to_zero_by_subtraction():
    # With one source packet, all 20 transmissions must be lost.
    assert binomial_tail_failure(20, 1, 0.01) == pytest.approx(1e-40, rel=1e-12, abs=0)


@pytest.mark.parametrize("n,k", [(-1, 0), (2, -1), (2, 3), (2.5, 1), (2, 1.0), (True, 1), (2, False)])
def test_invalid_mds_dimensions_are_rejected(n, k):
    with pytest.raises(ValueError, match="integers"):
        binomial_tail_failure(n, k, 0.1)


@pytest.mark.parametrize("p", [-0.1, 1.1, math.nan, math.inf, -math.inf])
def test_invalid_loss_probability_is_rejected(p):
    with pytest.raises(ValueError, match="probability"):
        binomial_tail_failure(3, 2, p)
