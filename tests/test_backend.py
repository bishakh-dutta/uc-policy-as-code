"""DatabricksBackend against a mocked ``WorkspaceClient`` (no workspace needed)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from databricks.sdk.errors import NotFound
from databricks.sdk.service.catalog import (
    ColumnInfo,
    ColumnMask,
    FunctionInfo,
    GetPermissionsResponse,
    PermissionsChange,
    Privilege,
    PrivilegeAssignment,
    TableInfo,
    TableRowFilter,
)
from databricks.sdk.service.sql import (
    ServiceError,
    StatementResponse,
    StatementState,
    StatementStatus,
)

from uc_policy.backend import BackendError, DatabricksBackend
from uc_policy.models import SecurableType


@pytest.fixture
def client() -> MagicMock:
    return MagicMock()


def test_get_grants_follows_pages(client: MagicMock) -> None:
    client.grants.get.side_effect = [
        GetPermissionsResponse(
            privilege_assignments=[
                PrivilegeAssignment("finance_analysts", [Privilege.USE_CATALOG, Privilege.SELECT])
            ],
            next_page_token="p2",
        ),
        GetPermissionsResponse(
            privilege_assignments=[PrivilegeAssignment("finance_engineers", [Privilege.MODIFY])]
        ),
    ]
    grants = DatabricksBackend(client).get_grants(SecurableType.CATALOG, "finance")

    assert grants == {
        "finance_analysts": frozenset({"USE_CATALOG", "SELECT"}),
        "finance_engineers": frozenset({"MODIFY"}),
    }
    assert client.grants.get.call_args_list[1].kwargs["page_token"] == "p2"
    assert client.grants.get.call_args_list[0].args == ("CATALOG", "finance")


def test_get_grants_missing_securable(client: MagicMock) -> None:
    client.grants.get.side_effect = NotFound("no such catalog")
    assert DatabricksBackend(client).get_grants(SecurableType.CATALOG, "nope") is None


def test_update_grants_sends_one_batched_request(client: MagicMock) -> None:
    DatabricksBackend(client).update_grants(
        SecurableType.TABLE,
        "finance.payments.transactions",
        {
            "finance_auditors": (frozenset({"SELECT"}), frozenset()),
            "contractors_tmp": (frozenset(), frozenset({"SELECT"})),
        },
    )
    client.grants.update.assert_called_once_with(
        "TABLE",
        "finance.payments.transactions",
        changes=[
            PermissionsChange(principal="contractors_tmp", add=None, remove=[Privilege.SELECT]),
            PermissionsChange(principal="finance_auditors", add=[Privilege.SELECT], remove=None),
        ],
    )


def test_get_table_security(client: MagicMock) -> None:
    client.tables.get.return_value = TableInfo(
        row_filter=TableRowFilter(
            function_name="finance.governance.region_filter", input_column_names=["region"]
        ),
        columns=[
            ColumnInfo(
                name="card_number",
                mask=ColumnMask(function_name="finance.governance.mask_card_number"),
            ),
            ColumnInfo(name="amount"),
        ],
    )
    security = DatabricksBackend(client).get_table_security("finance.payments.transactions")

    assert security is not None
    assert security.row_filter == ("finance.governance.region_filter", ("region",))
    assert security.column_masks == {"card_number": "finance.governance.mask_card_number"}


def test_get_table_security_missing(client: MagicMock) -> None:
    client.tables.get.side_effect = NotFound("no table")
    assert DatabricksBackend(client).get_table_security("a.b.c") is None


def test_get_function_definition(client: MagicMock) -> None:
    client.functions.get.return_value = FunctionInfo(routine_definition="CASE WHEN x END")
    backend = DatabricksBackend(client)
    assert backend.get_function_definition("a.b.f") == "CASE WHEN x END"
    client.functions.get.side_effect = NotFound("no function")
    assert backend.get_function_definition("a.b.g") is None


def _statement(state: StatementState, error: str | None = None) -> StatementResponse:
    return StatementResponse(
        statement_id="stmt-1",
        status=StatementStatus(state=state, error=ServiceError(message=error) if error else None),
    )


def test_execute_sql_polls_until_done(client: MagicMock) -> None:
    client.statement_execution.execute_statement.return_value = _statement(StatementState.RUNNING)
    client.statement_execution.get_statement.return_value = _statement(StatementState.SUCCEEDED)

    DatabricksBackend(client, "wh-1", poll_interval=0).execute_sql("ALTER TABLE x DROP ROW FILTER")

    kwargs = client.statement_execution.execute_statement.call_args.kwargs
    assert kwargs["warehouse_id"] == "wh-1"
    assert kwargs["statement"] == "ALTER TABLE x DROP ROW FILTER"
    client.statement_execution.get_statement.assert_called_once_with("stmt-1")


def test_execute_sql_failure(client: MagicMock) -> None:
    client.statement_execution.execute_statement.return_value = _statement(
        StatementState.FAILED, "PERMISSION_DENIED: User does not have MANAGE on table"
    )
    with pytest.raises(BackendError, match="PERMISSION_DENIED"):
        DatabricksBackend(client, "wh-1").execute_sql("ALTER TABLE x DROP ROW FILTER")


def test_execute_sql_requires_warehouse(client: MagicMock) -> None:
    with pytest.raises(BackendError, match="SQL warehouse is required"):
        DatabricksBackend(client).execute_sql("SELECT 1")
    client.statement_execution.execute_statement.assert_not_called()


def test_principal_exists(client: MagicMock) -> None:
    client.groups.list.side_effect = lambda **kw: iter(
        [object()] if "finance_analysts" in kw["filter"] else []
    )
    client.users.list.return_value = iter([])
    client.service_principals.list.return_value = iter([])
    backend = DatabricksBackend(client)

    assert backend.principal_exists("finance_analysts")
    assert backend.principal_exists("account users")  # built-in, no lookup
    client.users.list.return_value = iter([])
    assert not backend.principal_exists("contractors_tmp")
