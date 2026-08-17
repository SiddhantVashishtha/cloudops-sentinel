"""
Rule registry.

A "rule" is a small function that inspects one piece of AWS data and
returns a Finding (or None if nothing wrong). Scanners register rules
here instead of hardcoding checks inline — this is what makes it possible
to add a new check later without touching the CLI or scanner loop.

Usage:

    from sentinel.engine.rules import rule

    @rule(rule_id="SG-001", resource_type=ResourceType.SECURITY_GROUP,
          severity=Severity.CRITICAL, title="SSH publicly accessible")
    def check_open_ssh(sg_data: dict) -> Finding | None:
        ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from sentinel.engine.findings import Finding, ResourceType, Severity

RuleFunc = Callable[..., Finding | None]


@dataclass
class RuleMeta:
    rule_id: str
    resource_type: ResourceType
    severity: Severity
    title: str
    func: RuleFunc


_REGISTRY: dict[str, RuleMeta] = {}


def rule(rule_id: str, resource_type: ResourceType, severity: Severity, title: str):
    """Decorator that registers a check function under a rule ID."""

    def decorator(func: RuleFunc) -> RuleFunc:
        if rule_id in _REGISTRY:
            raise ValueError(f"Duplicate rule_id registered: {rule_id}")
        _REGISTRY[rule_id] = RuleMeta(
            rule_id=rule_id,
            resource_type=resource_type,
            severity=severity,
            title=title,
            func=func,
        )
        return func

    return decorator


def get_rule(rule_id: str) -> RuleMeta:
    return _REGISTRY[rule_id]


def all_rules() -> list[RuleMeta]:
    return list(_REGISTRY.values())


def rules_for_resource(resource_type: ResourceType) -> list[RuleMeta]:
    return [r for r in _REGISTRY.values() if r.resource_type == resource_type]


def clear_registry() -> None:
    """Test-only helper to reset state between test modules."""
    _REGISTRY.clear()