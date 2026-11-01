from __future__ import annotations

import json
from typing import Any

from tests.conftest import EXAMPLES, InMemoryBackend
from uc_policy.drift import detect_drift
from uc_policy.models import CatalogPolicy, load_policies
from uc_policy.render import drift_text


def test_example_snapshot_drift(snapshot_data: dict[str, Any]) -> None:
    policies = load_policies(EXAMPLES / "policies")
    report = detect_drift(policies, InMemoryBackend(snapshot_data))

    assert report.has_drift
    excess = {(g.securable, g.principal, tuple(g.privileges)) for g in report.excess_grants}
    assert excess == {
        ("finance.payments.transactions", "contractors_tmp", ("SELECT",)),
        ("finance.crm", "former_finance_lead@example.com", ("USE_SCHEMA",)),
    }
    assert [(g.securable, g.principal, g.privileges) for g in report.missing_grants] == [
        ("finance", "finance_engineers", ["MODIFY"])
    ]
    assert [o.principal for o in report.orphaned_principals] == [
        "contractors_tmp",
        "former_finance_lead@example.com",
    ]
    assert all(o.exists is None for o in report.orphaned_principals)
    assert {(d.action, d.target) for d in report.security_drift} == {
        ("create_function", "hr.core.mask_salary"),
        ("set_mask", "finance.crm.customers.phone"),
        ("set_mask", "hr.core.employees.salary"),
    }


def test_resolve_principals(snapshot_data: dict[str, Any]) -> None:
    snapshot_data["principals"].remove("finance_analysts_eu")
    policies = load_policies(EXAMPLES / "policies")
    report = detect_drift(policies, InMemoryBackend(snapshot_data), resolve_principals=True)

    exists = {o.principal: o.exists for o in report.orphaned_principals}
    assert exists == {"contractors_tmp": False, "former_finance_lead@example.com": True}
    assert report.unknown_declared_principals == ["finance_analysts_eu"]


def test_no_drift(finance_policy: CatalogPolicy, snapshot_data: dict[str, Any]) -> None:
    from uc_policy.planner import apply_plan, build_plan

    backend = InMemoryBackend(snapshot_data)
    apply_plan(build_plan([finance_policy], backend), backend)
    report = detect_drift([finance_policy], backend)

    assert not report.has_drift
    assert drift_text(report).startswith("No drift.")


def test_json_report_shape(snapshot_data: dict[str, Any]) -> None:
    report = detect_drift(load_policies(EXAMPLES / "policies"), InMemoryBackend(snapshot_data))
    data = json.loads(json.dumps(report.to_dict()))
    assert data["has_drift"] is True
    assert data["summary"] == {
        "excess_grants": 2,
        "missing_grants": 1,
        "orphaned_principals": 2,
        "unknown_declared_principals": 0,
        "security_drift": 3,
    }
    assert data["excess_grants"][0].keys() == {
        "securable_type",
        "securable",
        "principal",
        "privileges",
    }


def test_text_report_mentions_each_category(snapshot_data: dict[str, Any]) -> None:
    text = drift_text(
        detect_drift(load_policies(EXAMPLES / "policies"), InMemoryBackend(snapshot_data))
    )
    assert "Excess grants" in text
    assert "contractors_tmp" in text
    assert "Missing grants" in text
    assert "Orphaned principals" in text
    assert "Row filter / column mask drift" in text
