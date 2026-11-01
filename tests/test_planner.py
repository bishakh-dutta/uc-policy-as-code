from __future__ import annotations

from typing import Any

from tests.conftest import InMemoryBackend, WritePolicy, empty_state_for
from uc_policy.models import CatalogPolicy, SecurableType, load_policy_file
from uc_policy.planner import GrantChange, SqlAction, apply_plan, build_plan


def _site_policy(write_policy: WritePolicy) -> CatalogPolicy:
    return load_policy_file(
        write_policy("""
        catalog: finance
        grants:
          - principal: finance_analysts
            privileges: [USE_CATALOG, SELECT]
          - principal: finance_engineers
            privileges: [USE_CATALOG, SELECT, MODIFY]
        unmanaged_principals: [platform_admins]
        """)
    )


def _state(grants: dict[str, list[str]]) -> dict[str, Any]:
    return {"grants": {"CATALOG/finance": grants}}


def test_in_sync_plan_is_empty(write_policy: WritePolicy) -> None:
    backend = InMemoryBackend(
        _state(
            {
                "finance_analysts": ["SELECT", "USE_CATALOG"],
                "finance_engineers": ["MODIFY", "SELECT", "USE_CATALOG"],
            }
        )
    )
    plan = build_plan([_site_policy(write_policy)], backend)
    assert plan.is_empty
    assert not plan.warnings


def test_missing_and_excess_grants(write_policy: WritePolicy) -> None:
    backend = InMemoryBackend(
        _state(
            {
                "finance_analysts": ["SELECT", "USE_CATALOG", "MODIFY"],
                "finance_engineers": ["SELECT", "USE_CATALOG"],
                "contractors_tmp": ["SELECT"],
            }
        )
    )
    plan = build_plan([_site_policy(write_policy)], backend)
    by_principal = {c.principal: c for c in plan.grant_changes}
    assert by_principal["finance_analysts"].remove == {"MODIFY"}
    assert by_principal["finance_engineers"].add == {"MODIFY"}
    assert by_principal["contractors_tmp"].remove == {"SELECT"}
    assert plan.undeclared_principals == {"contractors_tmp": ["finance"]}


def test_unmanaged_principals_are_ignored(write_policy: WritePolicy) -> None:
    backend = InMemoryBackend(
        _state(
            {
                "finance_analysts": ["SELECT", "USE_CATALOG"],
                "finance_engineers": ["MODIFY", "SELECT", "USE_CATALOG"],
                "platform_admins": ["ALL_PRIVILEGES"],
            }
        )
    )
    plan = build_plan([_site_policy(write_policy)], backend)
    assert plan.is_empty
    assert "platform_admins" not in plan.undeclared_principals


def test_missing_securable_is_skipped_with_warning(write_policy: WritePolicy) -> None:
    plan = build_plan([_site_policy(write_policy)], InMemoryBackend({"grants": {}}))
    assert plan.is_empty
    assert plan.warnings == [
        "catalog finance does not exist; skipped (create it first, this tool only manages access)"
    ]


def test_grant_change_sql() -> None:
    change = GrantChange(
        SecurableType.TABLE,
        "finance.payments.transactions",
        "contractors_tmp",
        add=frozenset({"MODIFY"}),
        remove=frozenset({"SELECT", "APPLY_TAG"}),
    )
    assert change.sql() == [
        "GRANT MODIFY ON TABLE finance.payments.transactions TO `contractors_tmp`",
        "REVOKE APPLY TAG, SELECT ON TABLE finance.payments.transactions FROM `contractors_tmp`",
    ]


def test_security_plan_from_scratch(finance_policy: CatalogPolicy) -> None:
    plan = build_plan([finance_policy], InMemoryBackend(empty_state_for(finance_policy)))
    actions = [(c.action, c.target) for c in plan.sql_changes]
    # functions are created before anything references them
    assert actions[:4] == [
        (SqlAction.CREATE_FUNCTION, "finance.governance.mask_card_number"),
        (SqlAction.CREATE_FUNCTION, "finance.governance.mask_email"),
        (SqlAction.CREATE_FUNCTION, "finance.governance.mask_phone"),
        (SqlAction.CREATE_FUNCTION, "finance.governance.region_filter"),
    ]
    assert set(actions[4:]) == {
        (SqlAction.SET_ROW_FILTER, "finance.payments.transactions"),
        (SqlAction.SET_MASK, "finance.payments.transactions.card_number"),
        (SqlAction.SET_MASK, "finance.crm.customers.email"),
        (SqlAction.SET_MASK, "finance.crm.customers.phone"),
    }


def test_masks_not_in_policy_are_dropped(finance_policy: CatalogPolicy) -> None:
    state = empty_state_for(finance_policy)
    state["tables"]["finance.crm.customers"]["column_masks"]["ssn"] = "finance.gov.legacy"
    state["tables"]["finance.crm.customers"]["row_filter"] = {
        "function": "finance.gov.legacy_filter",
        "columns": ["country"],
    }
    plan = build_plan([finance_policy], InMemoryBackend(state))
    drops = [c for c in plan.sql_changes if c.action.value.startswith("drop")]
    assert [(c.action, c.target) for c in drops] == [
        (SqlAction.DROP_ROW_FILTER, "finance.crm.customers"),
        (SqlAction.DROP_MASK, "finance.crm.customers.ssn"),
    ]
    # drops run before sets, so a column can move to a different mask
    first_set = min(i for i, c in enumerate(plan.sql_changes) if c.action.value.startswith("set"))
    assert all(plan.sql_changes.index(d) < first_set for d in drops)


def test_changed_function_definition_is_replaced(
    finance_policy: CatalogPolicy, snapshot_data: dict[str, Any]
) -> None:
    snapshot_data["functions"]["finance.governance.mask_email"] = "CASE WHEN true THEN email END"
    plan = build_plan([finance_policy], InMemoryBackend(snapshot_data))
    replaced = [c for c in plan.sql_changes if c.action is SqlAction.REPLACE_FUNCTION]
    assert [c.target for c in replaced] == ["finance.governance.mask_email"]


def test_apply_converges(finance_policy: CatalogPolicy, snapshot_data: dict[str, Any]) -> None:
    backend = InMemoryBackend(snapshot_data)
    plan = build_plan([finance_policy], backend)
    assert not plan.is_empty

    result = apply_plan(plan, backend)

    assert "REVOKE SELECT ON TABLE finance.payments.transactions FROM `contractors_tmp`" in (
        result.applied
    )
    assert build_plan([finance_policy], backend).is_empty
    # one permissions API call per securable, not per principal
    securables = [(t, n) for t, n, _ in backend.grant_calls]
    assert len(securables) == len(set(securables))


def test_apply_without_revoke_only_adds(
    finance_policy: CatalogPolicy, snapshot_data: dict[str, Any]
) -> None:
    backend = InMemoryBackend(snapshot_data)
    result = apply_plan(build_plan([finance_policy], backend), backend, revoke=False)

    assert result.skipped == [
        "REVOKE SELECT ON TABLE finance.payments.transactions FROM `contractors_tmp`",
        "REVOKE USE SCHEMA ON SCHEMA finance.crm FROM `former_finance_lead@example.com`",
    ]
    remaining = build_plan([finance_policy], backend)
    assert all(not c.add for c in remaining.grant_changes)
    assert {c.principal for c in remaining.grant_changes} == {
        "contractors_tmp",
        "former_finance_lead@example.com",
    }
