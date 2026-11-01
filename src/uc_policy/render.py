"""Human-readable, Markdown (PR comment) and JSON output."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from uc_policy.drift import DriftReport
from uc_policy.planner import Plan

PLAN_COMMENT_MARKER = "<!-- ucpolicy-plan -->"


def plan_to_dict(plan: Plan) -> dict[str, Any]:
    return {
        "changes": len(plan.grant_changes) + len(plan.sql_changes),
        "grant_changes": [
            {
                **asdict(c),
                "securable_type": c.securable_type.value,
                "add": sorted(c.add),
                "remove": sorted(c.remove),
                "sql": c.sql(),
            }
            for c in plan.grant_changes
        ],
        "sql_changes": [{**asdict(c), "action": c.action.value} for c in plan.sql_changes],
        "undeclared_principals": plan.undeclared_principals,
        "warnings": plan.warnings,
    }


def plan_text(plan: Plan) -> str:
    rows: list[list[str]] = []
    for change in plan.grant_changes:
        target = _target(change.securable_type.value, change.securable)
        rows += [["+", target, change.principal, p] for p in sorted(change.add)]
        rows += [["-", target, change.principal, p] for p in sorted(change.remove)]
    lines = _columns(rows)
    lines += _columns(
        [
            ["~", c.action.value, c.target, f"({c.detail})" if c.detail else ""]
            for c in plan.sql_changes
        ]
    )
    for warning in plan.warnings:
        lines.append(f"  ! warning: {warning}")

    adds = sum(len(c.add) for c in plan.grant_changes)
    removes = sum(len(c.remove) for c in plan.grant_changes)
    if plan.is_empty:
        header = "No changes. Live grants match the policy."
    else:
        header = (
            f"Plan: {adds} privilege(s) to grant, {removes} to revoke, "
            f"{len(plan.sql_changes)} row filter/mask statement(s)."
        )
    return "\n".join([header, *lines]) + "\n"


def plan_markdown(plan: Plan) -> str:
    """Rendered as a sticky PR comment by the CI workflow."""
    parts = [PLAN_COMMENT_MARKER, "### Unity Catalog policy plan", ""]
    if plan.is_empty:
        parts.append("No changes. Live grants match the policy.")
    else:
        # GitHub only colours diff lines whose +/- sign is in the first column.
        diff = [line.removeprefix("  ") for line in plan_text(plan).splitlines()]
        parts += ["```diff", *diff, "```", ""]
        sql = [s for c in plan.grant_changes for s in c.sql()]
        sql += [c.statement for c in plan.sql_changes]
        parts += [
            "<details><summary>Equivalent SQL</summary>",
            "",
            "```sql",
            *[s + ";" for s in sql],
            "```",
            "</details>",
        ]
    for warning in plan.warnings:
        parts.append(f"> **Warning:** {warning}")
    parts += ["", "_Merging this PR applies the plan to the workspace._"]
    return "\n".join(parts) + "\n"


def drift_text(report: DriftReport) -> str:
    if not report.has_drift:
        lines = ["No drift. Live grants, row filters and masks match the policy."]
        lines += [f"  ! warning: {w}" for w in report.warnings]
        return "\n".join(lines) + "\n"

    lines = ["DRIFT DETECTED", ""]
    if report.excess_grants:
        lines.append("Excess grants (in the workspace, not in policy):")
        lines += _columns(
            [
                ["-", _target(g.securable_type, g.securable), g.principal, ", ".join(g.privileges)]
                for g in report.excess_grants
            ]
        )
        lines.append("")
    if report.missing_grants:
        lines.append("Missing grants (in policy, not in the workspace):")
        lines += _columns(
            [
                ["+", _target(g.securable_type, g.securable), g.principal, ", ".join(g.privileges)]
                for g in report.missing_grants
            ]
        )
        lines.append("")
    if report.orphaned_principals:
        lines.append("Orphaned principals (hold grants but are declared in no policy):")
        lines += _columns(
            [
                [
                    "!",
                    o.principal,
                    "on " + ", ".join(o.securables),
                    ""
                    if o.exists is None
                    else "[exists]"
                    if o.exists
                    else "[NOT FOUND in workspace]",
                ]
                for o in report.orphaned_principals
            ]
        )
        lines.append("")
    if report.unknown_declared_principals:
        lines.append("Principals referenced by policy but not found in the workspace:")
        lines += [f"  ? {p}" for p in report.unknown_declared_principals]
        lines.append("")
    if report.security_drift:
        lines.append("Row filter / column mask drift:")
        lines += _columns(
            [["~", d.action, d.target, f"({d.detail})"] for d in report.security_drift]
        )
        lines.append("")
    lines += [f"  ! warning: {w}" for w in report.warnings]
    s = report.to_dict()["summary"]
    lines.append(
        f"Summary: {s['excess_grants']} excess, {s['missing_grants']} missing, "
        f"{s['orphaned_principals']} orphaned principal(s), "
        f"{s['security_drift']} row filter/mask difference(s)."
    )
    return "\n".join(lines) + "\n"


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


def _columns(rows: list[list[str]]) -> list[str]:
    """Left-align rows into columns, indented by two spaces."""
    if not rows:
        return []
    widths = [max(len(r[i]) for r in rows) for i in range(1, len(rows[0]) - 1)]
    return [
        f"  {r[0]} "
        + "  ".join(c.ljust(w) for c, w in zip(r[1:-1], widths, strict=True))
        + (f"  {r[-1]}" if r[-1] else "")
        for r in rows
    ]


def _target(securable_type: str, name: str) -> str:
    return f"{securable_type.lower()} {name}"
