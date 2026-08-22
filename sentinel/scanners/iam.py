"""
IAM scanner.

Checks IAM users for missing MFA and stale access keys.
Deliberately conservative: only reports what can be reliably
determined via the API, no speculation about permissions being
"dangerous."
"""

from __future__ import annotations

from datetime import datetime, timezone

from sentinel.engine.findings import Finding, ResourceType, Severity
from sentinel.utils.aws_session import get_client

# Access keys older than this are flagged as stale, regardless of use.
STALE_KEY_AGE_DAYS = 90


def fetch_users(region: str) -> list[dict]:
    """List all IAM users in the account. IAM is a global service (no per-region data)."""
    iam = get_client("iam", region=region)
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])
    return users


def check_mfa_enabled(user: dict, region: str) -> Finding | None:
    """Checks whether the user has at least one MFA device registered."""
    iam = get_client("iam", region=region)
    username = user["UserName"]

    response = iam.list_mfa_devices(UserName=username)
    devices = response.get("MFADevices", [])

    if devices:
        return None  # MFA is enabled, no finding.

    return Finding(
        finding_id="IAM-001",
        resource_type=ResourceType.IAM_USER,
        resource_id=username,
        severity=Severity.HIGH,
        title="IAM user does not have MFA enabled",
        description=f"User {username} has no MFA device registered.",
        evidence={},
        recommendation="Enable MFA or use a more appropriate identity mechanism (e.g. IAM Identity Center / SSO).",
        region=region,
    )


def check_stale_access_keys(user: dict, region: str) -> list[Finding]:
    """
    Checks for access keys older than STALE_KEY_AGE_DAYS.
    Only reports the key's age — does NOT claim it's unused, since
    checking last-used activity is a separate, less reliable signal.
    """
    iam = get_client("iam", region=region)
    username = user["UserName"]
    findings = []

    response = iam.list_access_keys(UserName=username)
    for key_metadata in response.get("AccessKeyMetadata", []):
        if key_metadata["Status"] != "Active":
            continue

        created = key_metadata["CreateDate"]
        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < STALE_KEY_AGE_DAYS:
            continue

        findings.append(
            Finding(
                finding_id="IAM-002",
                resource_type=ResourceType.IAM_USER,
                resource_id=username,
                severity=Severity.MEDIUM,
                title="IAM access key older than 90 days",
                description=(
                    f"User {username} has an active access key "
                    f"({key_metadata['AccessKeyId']}) that is {age_days} days old."
                ),
                evidence={
                    "access_key_id": key_metadata["AccessKeyId"],
                    "age_days": age_days,
                    "created": created.isoformat(),
                },
                recommendation="Rotate access keys regularly. Consider using temporary credentials (IAM roles) instead of long-lived keys where possible.",
                region=region,
            )
        )

    return findings


def scan(region: str) -> list[Finding]:
    """Entry point called by the CLI. Returns all IAM findings."""
    users = fetch_users(region)
    findings: list[Finding] = []
    for user in users:
        mfa_finding = check_mfa_enabled(user, region)
        if mfa_finding:
            findings.append(mfa_finding)
        findings.extend(check_stale_access_keys(user, region))
    return findings