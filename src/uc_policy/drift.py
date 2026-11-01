"""Permission drift detection: live state vs. declared policy."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from uc_policy.backend import Backend
from uc_policy.models import CatalogPolicy
from uc_policy.planner import Plan, build_plan


@dataclass(frozen=True)
class GrantDrift:
    securable_type: str
    securable: str
    principal: str
    privileges: list[str]


@dataclass(frozen=True)
class OrphanedPrincipal:
    principal: str
    securables: list[str]
    # None when identities were not resolved (--resolve-principals not set)
    exists: bool | None = None


@dataclass(frozen=True)
class SecurityDrift:
    action: str
    target: str
    detail: str


@dataclass
class DriftReport:
    excess_grants: list[GrantDrift] = field(default_factory=list)
    missing_grants: list[GrantDrift] = field(default_factory=list)
    orphaned_principals: list[OrphanedPrincipal] = field(default_factory=list)
    # Principals the policy grants to, but which do not exist in the workspace.
    unknown_declared_principals: list[str] = field(default_factory=list)
    security_drift: list[SecurityDrift] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(
            self.excess_grants
            or self.missing_grants
            or self.orphaned_principals
            or self.unknown_declared_principals
            or self.security_drift
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["has_drift"] = self.has_drift
        data["summary"] = {
            "excess_grants": len(self.excess_grants),
            "missing_grants": len(self.missing_grants),
            "orphaned_principals": len(self.orphaned_principals),
            "unknown_declared_principals": len(self.unknown_declared_principals),
            "security_drift": len(self.security_drift),
        }
        return data


def detect_drift(
    policies: Iterable[CatalogPolicy],
    backend: Backend,
    *,
    resolve_principals: bool = False,
) -> DriftReport:
    policies = list(policies)
    plan = build_plan(policies, backend)
    report = report_from_plan(plan)
    if resolve_principals:
        report.orphaned_principals = [
            OrphanedPrincipal(o.principal, o.securables, backend.principal_exists(o.principal))
            for o in report.orphaned_principals
        ]
        declared = set().union(*(p.declared_principals() for p in policies))
        report.unknown_declared_principals = sorted(
            p for p in declared if not backend.principal_exists(p)
        )
    return report


def report_from_plan(plan: Plan) -> DriftReport:
    report = DriftReport(warnings=list(plan.warnings))
    for change in plan.grant_changes:
        args = (change.securable_type.value, change.securable, change.principal)
        if change.remove:
            report.excess_grants.append(GrantDrift(*args, sorted(change.remove)))
        if change.add:
            report.missing_grants.append(GrantDrift(*args, sorted(change.add)))
    report.orphaned_principals = [
        OrphanedPrincipal(principal, sorted(set(where)))
        for principal, where in sorted(plan.undeclared_principals.items())
    ]
    report.security_drift = [
        SecurityDrift(c.action.value, c.target, c.detail) for c in plan.sql_changes
    ]
    return report
