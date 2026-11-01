"""End-to-end test against a real workspace. Opt-in: skipped unless UCPOLICY_LIVE_TEST=1.

Needs DATABRICKS_HOST, a token or OAuth M2M credentials, and DATABRICKS_WAREHOUSE_ID.
It creates (or reuses) the sandbox catalog ``uc_policy_demo`` from live/setup.sql,
applies live/policies, and checks that the grants, row filter and masks really
take effect. Run live/teardown.sql afterwards to remove the catalog.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from uc_policy.backend import DatabricksBackend
from uc_policy.drift import detect_drift
from uc_policy.models import CatalogPolicy, SecurableType, load_policies
from uc_policy.planner import apply_plan, build_plan

if TYPE_CHECKING:
    from databricks.sdk import WorkspaceClient

pytestmark = pytest.mark.skipif(
    os.environ.get("UCPOLICY_LIVE_TEST") != "1",
    reason="live test; set UCPOLICY_LIVE_TEST=1 and Databricks credentials to run",
)

LIVE = Path(__file__).resolve().parents[2] / "live"
TABLE = "uc_policy_demo.sales.customers"


def sql_statements(path: Path) -> list[str]:
    text = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
    return [s.strip() for s in text.split(";") if s.strip()]


@pytest.fixture(scope="module")
def client() -> WorkspaceClient:
    from databricks.sdk import WorkspaceClient

    return WorkspaceClient()


@pytest.fixture(scope="module")
def warehouse_id() -> str:
    return os.environ["DATABRICKS_WAREHOUSE_ID"]


@pytest.fixture(scope="module")
def backend(client: WorkspaceClient, warehouse_id: str) -> DatabricksBackend:
    backend = DatabricksBackend(client, warehouse_id)
    for statement in sql_statements(LIVE / "setup.sql"):
        backend.execute_sql(statement)
    return backend


@pytest.fixture(scope="module")
def policies() -> list[CatalogPolicy]:
    return load_policies(LIVE / "policies")


def query(client: WorkspaceClient, warehouse_id: str, sql: str) -> list[list[str]]:
    from databricks.sdk.service.sql import StatementState

    response = client.statement_execution.execute_statement(
        statement=sql, warehouse_id=warehouse_id, wait_timeout="50s"
    )
    assert response.status and response.status.state == StatementState.SUCCEEDED, response.status
    if response.result is None or response.result.data_array is None:
        return []
    return response.result.data_array


def test_apply_converges(backend: DatabricksBackend, policies: list[CatalogPolicy]) -> None:
    apply_plan(build_plan(policies, backend), backend)
    remaining = build_plan(policies, backend)
    assert remaining.is_empty, remaining


def test_row_filter_and_masks_take_effect(
    backend: DatabricksBackend, client: WorkspaceClient, warehouse_id: str
) -> None:
    [[is_admin, is_pii_reader]] = query(
        client,
        warehouse_id,
        "SELECT is_account_group_member('uc_policy_admins'), "
        "is_account_group_member('uc_policy_pii_readers')",
    )
    if is_admin == "true" or is_pii_reader == "true":
        pytest.skip("the test identity is exempt from the filter or masks")

    rows = query(client, warehouse_id, f"SELECT region, email, card_number FROM {TABLE} ORDER BY 1")
    assert rows, "row filter should leave the region IN rows visible"
    assert {r[0] for r in rows} == {"IN"}
    assert all(r[1].startswith("***@") for r in rows)
    assert all(r[2].startswith("XXXX-XXXX-XXXX-") for r in rows)


def test_manual_grant_is_detected_and_reverted(
    backend: DatabricksBackend, policies: list[CatalogPolicy]
) -> None:
    # Simulate someone granting MODIFY by hand, outside the pull-request flow.
    backend.update_grants(
        SecurableType.TABLE, TABLE, {"account users": (frozenset({"MODIFY"}), frozenset())}
    )

    report = detect_drift(policies, backend)
    assert [(g.securable, g.principal, g.privileges) for g in report.excess_grants] == [
        (TABLE, "account users", ["MODIFY"])
    ]

    apply_plan(build_plan(policies, backend), backend)
    assert not detect_drift(policies, backend).has_drift
