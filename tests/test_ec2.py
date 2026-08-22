from sentinel.scanners.ec2 import check_public_ip


def test_running_instance_with_public_ip_is_flagged():
    instance = {
        "InstanceId": "i-12345",
        "State": {"Name": "running"},
        "PublicIpAddress": "1.2.3.4",
    }

    finding = check_public_ip(instance, region="us-east-1")

    assert finding is not None
    assert finding.finding_id == "EC2-001"
    assert finding.resource_id == "i-12345"


def test_instance_without_public_ip_not_flagged():
    instance = {
        "InstanceId": "i-12345",
        "State": {"Name": "running"},
    }

    finding = check_public_ip(instance, region="us-east-1")

    assert finding is None


def test_terminated_instance_not_flagged_even_with_public_ip():
    instance = {
        "InstanceId": "i-12345",
        "State": {"Name": "terminated"},
        "PublicIpAddress": "1.2.3.4",
    }

    finding = check_public_ip(instance, region="us-east-1")

    assert finding is None