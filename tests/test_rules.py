import pytest

from sentinel.engine.findings import ResourceType, Severity
from sentinel.engine import rules


@pytest.fixture(autouse=True)
def reset_registry():
    rules.clear_registry()
    yield
    rules.clear_registry()


def test_rule_registers_and_is_retrievable():
    @rules.rule(
        rule_id="TEST-001",
        resource_type=ResourceType.EC2_INSTANCE,
        severity=Severity.HIGH,
        title="Test rule",
    )
    def check(data):
        return None

    registered = rules.get_rule("TEST-001")
    assert registered.rule_id == "TEST-001"
    assert registered.severity == Severity.HIGH


def test_duplicate_rule_id_raises():
    @rules.rule(
        rule_id="TEST-002",
        resource_type=ResourceType.EC2_INSTANCE,
        severity=Severity.HIGH,
        title="First",
    )
    def check_one(data):
        return None

    with pytest.raises(ValueError):
        @rules.rule(
            rule_id="TEST-002",
            resource_type=ResourceType.EC2_INSTANCE,
            severity=Severity.LOW,
            title="Duplicate",
        )
        def check_two(data):
            return None


def test_rules_for_resource_filters_correctly():
    @rules.rule(
        rule_id="EC2-TEST",
        resource_type=ResourceType.EC2_INSTANCE,
        severity=Severity.HIGH,
        title="EC2 rule",
    )
    def ec2_check(data):
        return None

    @rules.rule(
        rule_id="S3-TEST",
        resource_type=ResourceType.S3_BUCKET,
        severity=Severity.HIGH,
        title="S3 rule",
    )
    def s3_check(data):
        return None

    ec2_rules = rules.rules_for_resource(ResourceType.EC2_INSTANCE)
    assert len(ec2_rules) == 1
    assert ec2_rules[0].rule_id == "EC2-TEST"