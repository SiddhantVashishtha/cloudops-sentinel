from sentinel.engine.findings import Finding, ResourceType, ScanResult, Severity
from sentinel.engine.scoring import GateStatus, calculate_score


def make_finding(severity: Severity, finding_id: str = "TEST-001") -> Finding:
    return Finding(
        finding_id=finding_id,
        resource_type=ResourceType.SECURITY_GROUP,
        resource_id="sg-test",
        severity=severity,
        title="Test finding",
        description="Test",
        recommendation="Fix it",
    )


def test_perfect_score_no_findings():
    result = ScanResult()
    score = calculate_score(result)
    assert score.score == 100
    assert score.status == GateStatus.PASS


def test_critical_finding_forces_fail_even_with_high_score():
    result = ScanResult()
    result.add(make_finding(Severity.CRITICAL))
    score = calculate_score(result)
    # 100 - 20 = 80, but any CRITICAL forces FAIL regardless of score
    assert score.score == 80
    assert score.status == GateStatus.FAIL


def test_multiple_high_findings_reduce_score():
    result = ScanResult()
    result.add(make_finding(Severity.HIGH, "H-1"))
    result.add(make_finding(Severity.HIGH, "H-2"))
    score = calculate_score(result)
    assert score.score == 80  # 100 - 10 - 10
    assert score.status == GateStatus.WARNING  # below 85 pass threshold


def test_score_floors_at_zero():
    result = ScanResult()
    for i in range(10):
        result.add(make_finding(Severity.CRITICAL, f"C-{i}"))
    score = calculate_score(result)
    assert score.score == 0
    assert score.status == GateStatus.FAIL


def test_custom_weights_are_respected():
    result = ScanResult()
    result.add(make_finding(Severity.LOW))
    score = calculate_score(result, weights={"LOW": 50, "CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "INFO": 0})
    assert score.score == 50


def test_severity_counts_tracked_correctly():
    result = ScanResult()
    result.add(make_finding(Severity.CRITICAL, "C-1"))
    result.add(make_finding(Severity.LOW, "L-1"))
    score = calculate_score(result)
    assert score.severity_counts["CRITICAL"] == 1
    assert score.severity_counts["LOW"] == 1
    assert score.severity_counts["HIGH"] == 0