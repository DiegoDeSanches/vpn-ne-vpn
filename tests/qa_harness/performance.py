"""Baseline comparison without invented absolute product SLOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Regression:
    metric: str
    baseline: float
    observed: float
    limit: float
    direction: str


def compare_metrics(
    baseline: Mapping[str, float],
    observed: Mapping[str, float],
    thresholds: Mapping[str, Mapping[str, float | str]],
) -> list[Regression]:
    regressions: list[Regression] = []
    for metric, policy in thresholds.items():
        if metric not in baseline or metric not in observed:
            raise ValueError(f"missing required performance metric: {metric}")
        base = float(baseline[metric])
        value = float(observed[metric])
        relative = float(policy.get("relative", 0.0))
        absolute = float(policy.get("absolute", 0.0))
        direction = str(policy["direction"])
        if direction == "lower":
            limit = base * (1.0 + relative) + absolute
            failed = value > limit
        elif direction == "higher":
            limit = max(0.0, base * (1.0 - relative) - absolute)
            failed = value < limit
        else:
            raise ValueError(f"invalid direction for {metric}")
        if failed:
            regressions.append(Regression(metric, base, value, limit, direction))
    return regressions
