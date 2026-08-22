import boto3
from moto import mock_aws

from sentinel.scanners.s3 import check_public_access_block, check_encryption, check_versioning


@mock_aws
def test_bucket_without_public_access_block_is_flagged(aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    finding = check_public_access_block("test-bucket", region="us-east-1")

    assert finding is not None
    assert finding.finding_id == "S3-001"


@mock_aws
def test_bucket_with_public_access_block_enabled_not_flagged(aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    finding = check_public_access_block("test-bucket", region="us-east-1")

    assert finding is None


@mock_aws
def test_bucket_without_encryption_is_flagged(aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    finding = check_encryption("test-bucket", region="us-east-1")

    assert finding is not None
    assert finding.finding_id == "S3-002"


@mock_aws
def test_bucket_with_encryption_not_flagged(aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    finding = check_encryption("test-bucket", region="us-east-1")

    assert finding is None


@mock_aws
def test_bucket_without_versioning_is_flagged(aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    finding = check_versioning("test-bucket", region="us-east-1")

    assert finding is not None
    assert finding.finding_id == "S3-003"


@mock_aws
def test_bucket_with_versioning_enabled_not_flagged(aws_credentials):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_versioning(Bucket="test-bucket", VersioningConfiguration={"Status": "Enabled"})

    finding = check_versioning("test-bucket", region="us-east-1")

    assert finding is None