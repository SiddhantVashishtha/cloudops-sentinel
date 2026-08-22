"""
EC2 scanner.

Fetches EC2 instance data and reports basic exposure facts.
Port-level exposure (SSH/RDP open to the internet) is determined by
the Security Group scanner, since that's where the actual firewall
rules live — this scanner focuses on instance-level facts.
"""

from __future__ import annotations

from sentinel.engine.findings import Finding, ResourceType, Severity
from sentinel.engine.rules import rule
from sentinel.utils.aws_session import get_client


def fetch_instances(region: str) -> list[dict]:
    """Pull raw EC2 instance data from AWS."""
    ec2 = get_client("ec2", region=region)
    instances = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            instances.extend(reservation["Instances"])
    return instances


@rule(
    rule_id="EC2-001",
    resource_type=ResourceType.EC2_INSTANCE,
    severity=Severity.MEDIUM,
    title="Instance has a public IP address",
)
def check_public_ip(instance: dict, region: str) -> Finding | None:
    """
    Flags instances with a public IP. Not automatically dangerous on its
    own (many instances legitimately need one), but worth surfacing —
    combined with an open security group, this is how exposure happens.
    """
    public_ip = instance.get("PublicIpAddress")
    if not public_ip:
        return None

    state = instance.get("State", {}).get("Name")
    if state not in ("running", "stopped"):
        return None

    return Finding(
        finding_id="EC2-001",
        resource_type=ResourceType.EC2_INSTANCE,
        resource_id=instance["InstanceId"],
        severity=Severity.MEDIUM,
        title="Instance has a public IP address",
        description=f"Instance {instance['InstanceId']} has public IP {public_ip}.",
        evidence={"public_ip": public_ip, "state": state},
        recommendation=(
            "Confirm this instance needs a public IP. If not, use a private "
            "subnet with a NAT gateway or VPC endpoint instead."
        ),
        region=region,
    )


def scan(region: str) -> list[Finding]:
    """Entry point called by the CLI. Returns all EC2 findings."""
    instances = fetch_instances(region)
    findings: list[Finding] = []
    for instance in instances:
        result = check_public_ip(instance, region)
        if result:
            findings.append(result)
    return findings