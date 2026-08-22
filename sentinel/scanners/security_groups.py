"""
Security Group scanner.

Inspects inbound rules for security groups and flags dangerous
open-to-the-internet exposure — SSH, RDP, and common database ports.
"""

from __future__ import annotations

from sentinel.engine.findings import Finding, ResourceType, Severity
from sentinel.utils.aws_session import get_client

# Ports we specifically care about, with their severity if exposed to 0.0.0.0/0
DANGEROUS_PORTS = {
    22: ("SSH", Severity.CRITICAL),
    3389: ("RDP", Severity.CRITICAL),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    1433: ("MSSQL", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
}

OPEN_TO_WORLD = "0.0.0.0/0"


def fetch_security_groups(region: str) -> list[dict]:
    """Pull raw security group data from AWS."""
    ec2 = get_client("ec2", region=region)
    groups = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        groups.extend(page["SecurityGroups"])
    return groups


def _port_in_range(port: int, from_port, to_port) -> bool:
    """Check if a specific port falls within a rule's port range."""
    if from_port is None or to_port is None:
        return True  # No port restriction means ALL ports — always a match
    return from_port <= port <= to_port


def check_security_group(sg: dict, region: str) -> list[Finding]:
    """
    Check a single security group's inbound rules for dangerous
    ports exposed to the entire internet.
    """
    findings: list[Finding] = []
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", "unknown")

    for permission in sg.get("IpPermissions", []):
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        # Is this rule open to the whole internet?
        is_open_to_world = any(
            ip_range.get("CidrIp") == OPEN_TO_WORLD
            for ip_range in permission.get("IpRanges", [])
        )
        if not is_open_to_world:
            continue

        for port, (service_name, severity) in DANGEROUS_PORTS.items():
            if not _port_in_range(port, from_port, to_port):
                continue

            findings.append(
                Finding(
                    finding_id="SG-001",
                    resource_type=ResourceType.SECURITY_GROUP,
                    resource_id=sg_id,
                    severity=severity,
                    title=f"{service_name} exposed to the internet",
                    description=(
                        f"Security group {sg_id} ({sg_name}) allows {service_name} "
                        f"(port {port}) inbound from {OPEN_TO_WORLD}."
                    ),
                    evidence={
                        "group_name": sg_name,
                        "port": port,
                        "service": service_name,
                        "source": OPEN_TO_WORLD,
                    },
                    recommendation=(
                        f"Restrict inbound access on port {port} to specific, "
                        "trusted CIDR ranges instead of the entire internet."
                    ),
                    region=region,
                )
            )

    return findings


def scan(region: str) -> list[Finding]:
    """Entry point called by the CLI. Returns all Security Group findings."""
    groups = fetch_security_groups(region)
    findings: list[Finding] = []
    for sg in groups:
        findings.extend(check_security_group(sg, region))
    return findings