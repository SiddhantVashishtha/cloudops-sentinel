"""
Core finding schema.

Every scanner (EC2, S3, IAM, SG, RDS) must emit Finding objects.
This is the single contract the rest of the system (scoring, reports, CLI)
depends on. Scanners never write to reports or the CLI directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResourceType(str, Enum):
    EC2_INSTANCE = "ec2_instance"
    S3_BUCKET = "s3_bucket"
    IAM_USER = "iam_user"
    SECURITY_GROUP = "security_group"
    RDS_INSTANCE = "rds_instance"


class Finding(BaseModel):
    """A single security finding produced by a scanner."""

    finding_id: str = Field(..., description="Rule identifier, e.g. 'SG-001'")
    resource_type: ResourceType
    resource_id: str
    severity: Severity
    title: str
    description: str
    evidence: dict = Field(default_factory=dict)
    recommendation: str
    region: str = "unknown"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(use_enum_values=True)

    def to_dict(self) -> dict:
        data = self.model_dump()
        data["timestamp"] = self.timestamp.isoformat()
        return data


class ScanResult(BaseModel):
    """Aggregate output of a full scan run across all scanners."""

    findings: list[Finding] = Field(default_factory=list)
    region: str = "unknown"
    scan_started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_seconds: float | None = None
    resources_scanned: int = 0
    services_scanned: list[str] = Field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self, severity: Severity) -> list[Finding]:
        sev = severity.value if isinstance(severity, Severity) else severity
        return [f for f in self.findings if f.severity == sev]

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "region": self.region,
            "scan_started_at": self.scan_started_at.isoformat(),
            "scan_duration_seconds": self.scan_duration_seconds,
            "resources_scanned": self.resources_scanned,
            "services_scanned": self.services_scanned,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
        }