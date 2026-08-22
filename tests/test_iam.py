import boto3
from moto import mock_aws

from sentinel.scanners.iam import check_mfa_enabled, check_stale_access_keys


@mock_aws
def test_user_without_mfa_is_flagged(aws_credentials):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="test-user")

    finding = check_mfa_enabled({"UserName": "test-user"}, region="us-east-1")

    assert finding is not None
    assert finding.finding_id == "IAM-001"


@mock_aws
def test_user_with_mfa_not_flagged(aws_credentials):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="test-user")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="test-device")["VirtualMFADevice"]
    iam.enable_mfa_device(
        UserName="test-user",
        SerialNumber=device["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    finding = check_mfa_enabled({"UserName": "test-user"}, region="us-east-1")

    assert finding is None


@mock_aws
def test_recently_created_access_key_not_flagged(aws_credentials):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="test-user")
    iam.create_access_key(UserName="test-user")

    findings = check_stale_access_keys({"UserName": "test-user"}, region="us-east-1")

    assert findings == []