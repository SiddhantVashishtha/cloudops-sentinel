"""
JSON report generation.

Writes a ScanResult (findings + risk score) to a JSON file on disk.
"""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.engine.findings import ScanResult
from sentinel.engine.scoring import ScoreResult


def build_report_dict(scan_result: ScanResult, score_result: ScoreResult) -> dict:
    """Combine scan results and score into one report structure."""
    return {
        "scan": scan_result.to_dict(),
        "score": score_result.model_dump(),
    }


def write_json_report(scan_result: ScanResult, score_result: ScoreResult, output_path: str) -> str:
    """
    Write the report to disk as JSON.
    Creates parent directories if they don't exist.
    Returns the absolute path written to.
    """
    report = build_report_dict(scan_result, score_result)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    return str(path.resolve())