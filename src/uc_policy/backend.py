"""Access to live Unity Catalog state.

``DatabricksBackend`` talks to a workspace through the Databricks SDK.
``SnapshotBackend`` reads the same state from a JSON file, so plans and drift
reports can be produced offline (demos, tests, reviewing an exported snapshot).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from uc_policy.models import SecurableType

if TYPE_CHECKING:
    from databricks.sdk import WorkspaceClient

# principal -> set of privileges directly granted on one securable
Grants = dict[str, frozenset[str]]


@dataclass(frozen=True)
class TableSecurity:
    """Row filter and column masks currently attached to a table."""

    row_filter: tuple[str, tuple[str, ...]] | None = None  # (function, columns)
    column_masks: dict[str, str] = field(default_factory=dict)  # column -> function


class Backend(Protocol):
    def get_grants(self, securable_type: SecurableType, full_name: str) -> Grants | None:
        """Return ``None`` when the securable does not exist."""

    def update_grants(
        self,
        securable_type: SecurableType,
        full_name: str,
        changes: dict[str, tuple[frozenset[str], frozenset[str]]],
    ) -> None:
        """Apply ``principal -> (add, remove)`` privilege changes in one API call."""

    def get_table_security(self, full_name: str) -> TableSecurity | None:
        """Return ``None`` when the table does not exist."""

    def get_function_definition(self, full_name: str) -> str | None:
        """Return the SQL body of a function, or ``None`` when it does not exist."""

    def execute_sql(self, statement: str) -> None: ...

    def principal_exists(self, name: str) -> bool:
        """Whether a group, user or service principal with this name is visible."""


class BackendError(Exception):
    pass


class DatabricksBackend:
    """Live backend. Grants go through the UC permissions API; DDL for row
    filters and masks goes through the SQL statement execution API."""

    def __init__(
        self,
        client: WorkspaceClient,
        warehouse_id: str | None = None,
        *,
        poll_interval: float = 2.0,
        timeout: float = 600.0,
    ) -> None:
        self._w = client
        self._warehouse_id = warehouse_id
        self._poll_interval = poll_interval
        self._timeout = timeout

    def get_grants(self, securable_type: SecurableType, full_name: str) -> Grants | None:
        from databricks.sdk.errors import NotFound

        grants: dict[str, set[str]] = {}
        page_token: str | None = None
        while True:
            try:
                response = self._w.grants.get(
                    securable_type.value, full_name, page_token=page_token
                )
            except NotFound:
                return None
            for assignment in response.privilege_assignments or []:
                if not assignment.principal:
                    continue
                privileges = grants.setdefault(assignment.principal, set())
                privileges.update(_enum_value(p) for p in assignment.privileges or [])
            page_token = response.next_page_token
            if not page_token:
                break
        return {p: frozenset(v) for p, v in grants.items()}

    def update_grants(
        self,
        securable_type: SecurableType,
        full_name: str,
        changes: dict[str, tuple[frozenset[str], frozenset[str]]],
    ) -> None:
        from databricks.sdk.service.catalog import PermissionsChange, Privilege

        self._w.grants.update(
            securable_type.value,
            full_name,
            changes=[
                PermissionsChange(
                    principal=principal,
                    add=[Privilege(p) for p in sorted(add)] or None,
                    remove=[Privilege(p) for p in sorted(remove)] or None,
                )
                for principal, (add, remove) in sorted(changes.items())
            ],
        )

    def get_table_security(self, full_name: str) -> TableSecurity | None:
        from databricks.sdk.errors import NotFound

        try:
            table = self._w.tables.get(full_name)
        except NotFound:
            return None
        row_filter = None
        if table.row_filter and table.row_filter.function_name:
            row_filter = (
                table.row_filter.function_name.lower(),
                tuple(c.lower() for c in table.row_filter.input_column_names or []),
            )
        masks = {
            c.name.lower(): c.mask.function_name.lower()
            for c in table.columns or []
            if c.name and c.mask and c.mask.function_name
        }
        return TableSecurity(row_filter=row_filter, column_masks=masks)

    def get_function_definition(self, full_name: str) -> str | None:
        from databricks.sdk.errors import NotFound

        try:
            fn = self._w.functions.get(full_name)
        except NotFound:
            return None
        return fn.routine_definition or ""

    def execute_sql(self, statement: str) -> None:
        from databricks.sdk.service.sql import StatementState

        if not self._warehouse_id:
            raise BackendError(
                "a SQL warehouse is required to apply row filters and column masks; "
                "pass --warehouse-id or set DATABRICKS_WAREHOUSE_ID"
            )
        response = self._w.statement_execution.execute_statement(
            statement=statement, warehouse_id=self._warehouse_id, wait_timeout="30s"
        )
        deadline = time.monotonic() + self._timeout
        terminal = {
            StatementState.SUCCEEDED,
            StatementState.FAILED,
            StatementState.CANCELED,
            StatementState.CLOSED,
        }
        while response.status is None or response.status.state not in terminal:
            if time.monotonic() > deadline:
                if response.statement_id:
                    self._w.statement_execution.cancel_execution(response.statement_id)
                raise BackendError(f"statement timed out after {self._timeout:.0f}s")
            if not response.statement_id:
                raise BackendError("statement execution returned no statement id")
            time.sleep(self._poll_interval)
            response = self._w.statement_execution.get_statement(response.statement_id)
        if response.status.state != StatementState.SUCCEEDED:
            error = response.status.error
            message = error.message if error and error.message else response.status.state.value
            raise BackendError(f"statement failed: {message}\n{statement}")

    def principal_exists(self, name: str) -> bool:
        if name in _BUILTIN_PRINCIPALS:
            return True
        quoted = name.replace('"', '\\"')
        lookups = (
            (self._w.groups.list, f'displayName eq "{quoted}"'),
            (self._w.users.list, f'userName eq "{quoted}"'),
            (self._w.service_principals.list, f'applicationId eq "{quoted}"'),
        )
        return any(
            next(iter(lookup(filter=query, attributes="id")), None) is not None
            for lookup, query in lookups
        )


class SnapshotBackend:
    """Read-only backend over a JSON snapshot of live state.

    Format::

        {
          "grants": {"CATALOG/finance": {"finance_analysts": ["USE_CATALOG", "SELECT"]}},
          "tables": {"finance.sales.customers": {"row_filter": null, "column_masks": {}}},
          "functions": {"finance.governance.mask_email": "CASE WHEN ... END"},
          "principals": ["finance_analysts", "finance_engineers"]
        }

    ``principals`` is optional; when present it lists the identities that exist.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._grants: dict[str, dict[str, list[str]]] = data.get("grants", {})
        self._tables: dict[str, dict[str, Any]] = data.get("tables", {})
        self._functions: dict[str, str] = data.get("functions", {})
        principals = data.get("principals")
        self._principals: set[str] | None = set(principals) if principals is not None else None

    @classmethod
    def from_file(cls, path: Path) -> SnapshotBackend:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def get_grants(self, securable_type: SecurableType, full_name: str) -> Grants | None:
        raw = self._grants.get(f"{securable_type.value}/{full_name}")
        if raw is None:
            return None
        return {p: frozenset(x.upper() for x in privs) for p, privs in raw.items()}

    def update_grants(
        self,
        securable_type: SecurableType,
        full_name: str,
        changes: dict[str, tuple[frozenset[str], frozenset[str]]],
    ) -> None:
        raise BackendError("a snapshot is read-only; apply needs a live workspace")

    def get_table_security(self, full_name: str) -> TableSecurity | None:
        raw = self._tables.get(full_name)
        if raw is None:
            return None
        row_filter = raw.get("row_filter")
        return TableSecurity(
            row_filter=(
                row_filter["function"].lower(),
                tuple(c.lower() for c in row_filter["columns"]),
            )
            if row_filter
            else None,
            column_masks={k.lower(): v.lower() for k, v in raw.get("column_masks", {}).items()},
        )

    def get_function_definition(self, full_name: str) -> str | None:
        return self._functions.get(full_name)

    def execute_sql(self, statement: str) -> None:
        raise BackendError("a snapshot is read-only; apply needs a live workspace")

    def principal_exists(self, name: str) -> bool:
        if self._principals is None or name in _BUILTIN_PRINCIPALS:
            return True
        return name in self._principals


# Built-in principals that are not returned by SCIM lookups.
_BUILTIN_PRINCIPALS = frozenset({"account users", "users", "admins"})


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value)).upper()
