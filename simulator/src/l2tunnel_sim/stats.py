"""Uncertainty estimates for independent Monte Carlo replications.

The replication, rather than an individual packet, is the sampling unit for
``mean_ci`` and ``paired_difference``. Packet observations within a replication
may share queues and loss bursts and therefore need not be independent.
"""

from collections.abc import Sequence
from numbers import Integral

import numpy as np
from scipy import stats


def _finite_vector(values: Sequence[float]) -> np.ndarray:
    samples = np.asarray(values, dtype=float)
    if samples.ndim != 1:
        raise ValueError("values must be a one-dimensional sequence")
    if not np.all(np.isfinite(samples)):
        raise ValueError("values must contain only finite numbers")
    return samples


def mean_ci(values: Sequence[float], confidence: float = 0.95) -> dict:
    """Estimate a mean and a two-sided Student-t confidence interval.

    Each value must come from an independent replication. The interval assumes
    approximately normal replication means; it is not a bound on packet-level
    tails or model error. Empty samples have no estimate, and a single sample
    has a mean but insufficient information to estimate uncertainty.
    """
    if not np.isfinite(confidence) or not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be finite and strictly between 0 and 1")
    samples = _finite_vector(values)
    count = int(samples.size)
    result = {
        "mean": None,
        "ci_low": None,
        "ci_high": None,
        "n": count,
        "method": "student_t",
    }
    if count == 0:
        return result

    average = float(np.mean(samples))
    result["mean"] = average
    if count == 1:
        return result

    standard_error = float(stats.sem(samples, ddof=1))
    critical_value = float(stats.t.ppf((1.0 + confidence) / 2.0, df=count - 1))
    margin = critical_value * standard_error
    result["ci_low"] = average - margin
    result["ci_high"] = average + margin
    return result


def paired_difference(left: Sequence[float], right: Sequence[float]) -> dict:
    """Return a 95% Student-t interval for mean(left - right).

    Matching positions must represent the same replication conditions and
    seed. Pairing removes common environmental variation from the comparison.
    """
    left_samples = _finite_vector(left)
    right_samples = _finite_vector(right)
    if left_samples.size != right_samples.size:
        raise ValueError("paired samples must have equal lengths")
    return mean_ci(left_samples - right_samples)


def binomial_tail_failure(n: int, k: int, p: float) -> float:
    """Return ideal MDS block failure probability under independent erasures.

    An (n, k) ideal MDS block recovers when at least k of its n transmitted
    packets arrive. Here p is the per-packet *loss* probability, so failure is
    P(received < k) = P(Binomial(n, p) > n - k). This oracle does not describe
    burst losses, deadlines, queues, or a practical codec's decoding behavior.
    A block requiring zero received packets (k=0) cannot fail.
    """
    if (
        isinstance(n, bool)
        or isinstance(k, bool)
        or not isinstance(n, Integral)
        or not isinstance(k, Integral)
        or not 0 <= k <= n
    ):
        raise ValueError("n and k must be integers satisfying 0 <= k <= n")
    if not np.isfinite(p) or not 0.0 <= p <= 1.0:
        raise ValueError("p must be a finite loss probability between 0 and 1")
    return float(stats.binom.sf(int(n - k), int(n), p))
