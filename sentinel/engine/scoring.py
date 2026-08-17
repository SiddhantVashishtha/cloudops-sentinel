"""
Sentinel Risk Score.

This is a project-defined risk score, NOT an official AWS or industry
security rating. Methodology: start at 100, subtract configurable weight
per finding by severity, floor at 0.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from sentinel.engine.findings import ScanResult, Severity

DEFAULT_WEIGHTS: dict[str, int] = {
    Severity.CRITICAL.value: 20,
    Severity.HIGH.value: 10,
    Severity.MEDIUM.value: 5,
    Severity.LOW.value: 2,
    Severity.INFO.value: 0,
}

# Thresholds for PASS/WARNING/FAIL gate status.
DEFAULT_PASS_THRESHOLD = 85
DEFAULT_WARNING_THRESHOLD = 60
# Any single CRITICAL finding fails the gate outright, regardless of score.


class GateStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


class ScoreResult(BaseModel):
    score: int
    max_score: int = 100
    status: GateStatus
    severity_counts: dict[str, int]
    weights_used: dict[str, int]

    model_config = ConfigDict(use_enum_values=True)


def calculate_score(
    scan_result: ScanResult,
    weights: dict[str, int] | None = None,
    pass_threshold: int = DEFAULT_PASS_THRESHOLD,
    warning_threshold: int = DEFAULT_WARNING_THRESHOLD,
    fail_on_any_critical: bool = True,
) -> ScoreResult:
    """
    Compute the Sentinel Risk Score for a scan result.

    Configurable via `weights` / thresholds so scoring policy can change
    without touching this function's internals or any caller.
    """
    weights = weights or DEFAULT_WEIGHTS
    counts = scan_result.severity_counts()

    score = 100
    for severity, count in counts.items():
        score -= weights.get(severity, 0) * count
    score = max(0, min(100, score))

    if fail_on_any_critical and counts.get(Severity.CRITICAL.value, 0) > 0:
        status = GateStatus.FAIL
    elif score >= pass_threshold:
        status = GateStatus.PASS
    elif score >= warning_threshold:
        status = GateStatus.WARNING
    else:
        status = GateStatus.FAIL

    return ScoreResult(
        score=score,
        status=status,
        severity_counts=counts,
        weights_used=weights,
    )