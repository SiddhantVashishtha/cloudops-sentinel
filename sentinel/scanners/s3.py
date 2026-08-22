"""
S3 scanner.

Checks buckets for public access exposure, missing encryption,
and versioning status.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from sentinel.engine.findings import Finding, ResourceType, Severity
from sentinel.utils.aws_session import get_client


def fetch_buckets(region: str) -> list[dict]:
    """List all S3 buckets in the account. S3 bucket listing is global, not per-region."""
    s3 = get_client("s3", region=region)
    response = s3.list_buckets()
    return response.get("Buckets", [])


def check_public_access_block(bucket_name: str, region: str) -> Finding | None:
    """
    Checks whether S3 Block Public Access is fully enabled.
    If the config is missing entirely, or any of the 4 settings are off,
    the bucket is potentially exposable to public access.
    """
    s3 = get_client("s3", region=region)
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]
        all_blocked = all(config.values())
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            # No block configuration exists at all — treat as not protected.
            all_blocked = False
            config = {}
        else:
            raise

    if all_blocked:
        return None

    return Finding(
        finding_id="S3-001",
        resource_type=ResourceType.S3_BUCKET,
        resource_id=bucket_name,
        severity=Severity.HIGH,
        title="S3 Block Public Access not fully enabled",
        description=f"Bucket {bucket_name} does not have all Block Public Access settings enabled.",
        evidence={"public_access_block_config": config},
        recommendation="Enable all four S3 Block Public Access settings unless public access is explicitly required.",
        region=region,
    )


def check_encryption(bucket_name: str, region: str) -> Finding | None:
    """Checks whether default server-side encryption is configured."""
    s3 = get_client("s3", region=region)
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return None  # Encryption is configured, no finding.
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code != "ServerSideEncryptionConfigurationNotFoundError":
            raise

    return Finding(
        finding_id="S3-002",
        resource_type=ResourceType.S3_BUCKET,
        resource_id=bucket_name,
        severity=Severity.MEDIUM,
        title="S3 bucket has no default encryption configured",
        description=f"Bucket {bucket_name} does not have default server-side encryption enabled.",
        evidence={},
        recommendation="Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
        region=region,
    )


def check_versioning(bucket_name: str, region: str) -> Finding | None:
    """Checks whether versioning is enabled (helps recover from accidental deletion/overwrite)."""
    s3 = get_client("s3", region=region)
    response = s3.get_bucket_versioning(Bucket=bucket_name)
    status = response.get("Status", "Disabled")

    if status == "Enabled":
        return None

    return Finding(
        finding_id="S3-003",
        resource_type=ResourceType.S3_BUCKET,
        resource_id=bucket_name,
        severity=Severity.LOW,
        title="S3 bucket versioning not enabled",
        description=f"Bucket {bucket_name} does not have versioning enabled.",
        evidence={"versioning_status": status},
        recommendation="Enable versioning to protect against accidental deletion or overwrite.",
        region=region,
    )


def scan(region: str) -> list[Finding]:
    """Entry point called by the CLI. Returns all S3 findings."""
    buckets = fetch_buckets(region)
    findings: list[Finding] = []
    for bucket in buckets:
        bucket_name = bucket["Name"]
        for check_fn in (check_public_access_block, check_encryption, check_versioning):
            result = check_fn(bucket_name, region)
            if result:
                findings.append(result)
    return findings