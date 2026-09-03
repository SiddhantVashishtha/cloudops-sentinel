"""
Centralized boto3 session handling.

All scanners get their AWS clients through here — never call
boto3.client() directly in a scanner. This keeps region/credential
logic in one place and makes scanners easy to unit test (mock this
function instead of mocking boto3 everywhere).
"""

from __future__ import annotations

import os

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_region() -> str:
    """Resolve region from env var, falling back to a safe default."""
    return os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def get_client(service_name: str, region: str | None = None):
    """
    Return a boto3 client for the given service.

    Relies on the standard boto3 credential chain (env vars, ~/.aws/credentials,
    IAM role, or OIDC-issued short-lived creds in CI). We never accept or
    handle raw credentials ourselves.
    """
    region = region or get_region()
    try:
        return boto3.client(service_name, region_name=region)
    except NoCredentialsError as e:
        raise RuntimeError(
            "No AWS credentials found. Configure via `aws configure`, "
            "environment variables, or an IAM role."
        ) from e


def verify_credentials() -> dict:
    """
    Sanity-check that credentials work before running a full scan.
    Returns caller identity info (account, arn) for the CLI to display.
    """
    sts = get_client("sts")
    try:
        identity = sts.get_caller_identity()
        return {"account": identity["Account"], "arn": identity["Arn"]}
    except ClientError as e:
        raise RuntimeError(f"AWS credential check failed: {e}") from e