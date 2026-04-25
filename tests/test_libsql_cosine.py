"""LibSQL backend invariants that don't require a real database (Q17).

Tests that need a live SQL connection live in a separate integration
suite; this module covers the pure-Python helpers we changed.
"""

from __future__ import annotations

import math

import pytest

from titanx.storage.libsql import _cosine


class TestCosineDimensionMismatch:
    def test_dimension_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="dimension mismatch"):
            _cosine([1.0, 2.0], [1.0, 2.0, 3.0])

    def test_orthogonal_vectors_zero(self) -> None:
        assert _cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)

    def test_identical_vectors_one(self) -> None:
        assert _cosine([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == pytest.approx(1.0)

    def test_zero_magnitude_returns_zero(self) -> None:
        # Historical behaviour preserved: rather than NaN-out on a
        # zero vector, fall back to 0. Callers ranking by cosine
        # treat a zero result as "no signal".
        assert _cosine([0.0, 0.0], [1.0, 2.0]) == 0.0

    def test_known_value(self) -> None:
        # cos(45°) = sqrt(2)/2 — sanity check on the math.
        a = [1.0, 0.0]
        b = [1.0, 1.0]
        assert _cosine(a, b) == pytest.approx(math.sqrt(2) / 2)
