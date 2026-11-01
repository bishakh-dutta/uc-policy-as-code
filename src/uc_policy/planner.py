"""Diff declared policy against live state, and apply the difference."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from uc_policy.backend import Backend
from uc_policy.models import CatalogPolicy, SecurableType
from uc_policy.sqlgen import (
    create_function_sql,
    drop_mask_sql,
    drop_row_filter_sql,
    function_body,
    same_definition,
    set_mask_sql,
    set_row_filter_sql,
)


@dataclass(frozen=True)
class GrantChange:
    securable_type: SecurableType
    securable: str
    principal: str
    add: frozenset[str] = frozenset()
    remove: frozenset[str] = frozenset()

    def sql(self) -> list[str]:
        """Equivalent SQL, for humans; apply uses the permissions API instead."""
        target = f"{self.securable_type.value} {self.securable}"
        out = []
        if self.add:
            privs = ", ".join(p.replace("_", " ") for p in sorted(self.add))
            out.append(f"GRANT {privs} ON {target} TO `{self.principal}`")
        if self.remove:
            privs = ", ".join(p.replace("_", " ") for p in sorted(self.remove))
            out.append(f"REVOKE {privs} ON {target} FROM `{self.principal}`")
        return out


class SqlAction(StrEnum):
    CREATE_FUNCTION = "create_function"
    REPLACE_FUNCTION = "replace_function"
    SET_ROW_FILTER = "set_row_filter"
    DROP_ROW_FILTER = "drop_row_filter"
    SET_MASK = "set_mask"
    DROP_MASK = "drop_mask"


# Functions must exist before they are attached; drops run before sets so a
# column can switch from one mask to another.
_SQL_ORDER = {
    SqlAction.CREATE_FUNCTION: 0,
    SqlAction.REPLACE_FUNCTION: 0,
    SqlAction.DROP_ROW_FILTER: 1,
    SqlAction.DROP_MASK: 1,
    SqlAction.SET_ROW_FILTER: 2,
    SqlAction.SET_MASK: 2,
}


@dataclass(frozen=True)
class SqlChange:
    action: SqlAction
    target: str
    statement: str
    detail: str = ""


@dataclass
class Plan:
    grant_changes: list[GrantChange] = field(default_factory=list)
    sql_changes: list[SqlChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # principal -> securables where it holds grants but is not declared in the policy
    undeclared_principals: dict[str, list[str]] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.grant_changes and not self.sql_changes

    def extend(self, other: Plan) -> None:
        self.grant_changes += other.grant_changes
        self.sql_changes += other.sql_changes
        self.warnings += other.warnings
        for principal, where in other.undeclared_principals.items():
            self.undeclared_principals.setdefault(principal, []).extend(where)


def build_plan(policies: Iterable[CatalogPolicy], backend: Backend) -> Plan:
    plan = Plan()
    for policy in policies:
        plan.extend(_plan_grants(policy, backend))
        plan.extend(_plan_security(policy, backend))
    plan.sql_changes.sort(key=lambda c: _SQL_ORDER[c.action])
    return plan


def _plan_grants(policy: CatalogPolicy, backend: Backend) -> Plan:
    plan = Plan()
    unmanaged = set(policy.unmanaged_principals)
    declared = policy.declared_principals()
    for securable in policy.securables():
        live = backend.get_grants(securable.type, securable.full_name)
        if live is None:
            plan.warnings.append(
                f"{securable.type.value.lower()} {securable.full_name} does not exist; "
                "skipped (create it first, this tool only manages access)"
            )
            continue
        desired = securable.desired()
        for principal in sorted(set(desired) | set(live)):
            if principal in unmanaged:
                continue
            want = desired.get(principal, frozenset())
            have = live.get(principal, frozenset())
            if want != have:
                plan.grant_changes.append(
                    GrantChange(
                        securable.type,
                        securable.full_name,
                        principal,
                        add=want - have,
                        remove=have - want,
                    )
                )
            if have and principal not in declared:
                plan.undeclared_principals.setdefault(principal, []).append(securable.full_name)
    return plan


def _plan_security(policy: CatalogPolicy, backend: Backend) -> Plan:
    plan = Plan()
    for fn in policy.functions:
        name = policy.qualify(fn.name)
        live_body = backend.get_function_definition(name)
        if live_body is None:
            schema = name.rsplit(".", 1)[0]
            if backend.get_grants(SecurableType.SCHEMA, schema) is None:
                plan.warnings.append(
                    f"schema {schema} does not exist; function {name} skipped "
                    "(create the schema first)"
                )
                continue
            plan.sql_changes.append(
                SqlChange(
                    SqlAction.CREATE_FUNCTION,
                    name,
                    create_function_sql(policy, fn),
                    detail="function does not exist",
                )
            )
        elif not same_definition(live_body, function_body(fn)):
            plan.sql_changes.append(
                SqlChange(
                    SqlAction.REPLACE_FUNCTION,
                    name,
                    create_function_sql(policy, fn),
                    detail="definition differs from policy",
                )
            )

    for table_name, table in policy.tables():
        live = backend.get_table_security(table_name)
        if live is None:
            if table.row_filter or table.column_masks:
                plan.warnings.append(
                    f"table {table_name} does not exist; row filter / masks skipped"
                )
            continue

        if table.row_filter:
            filter_fn = policy.qualify(table.row_filter.function)
            cols = tuple(c.lower() for c in table.row_filter.columns)
            if live.row_filter != (filter_fn, cols):
                plan.sql_changes.append(
                    SqlChange(
                        SqlAction.SET_ROW_FILTER,
                        table_name,
                        set_row_filter_sql(table_name, filter_fn, cols),
                        detail=_was(live.row_filter[0] if live.row_filter else None),
                    )
                )
        elif live.row_filter:
            plan.sql_changes.append(
                SqlChange(
                    SqlAction.DROP_ROW_FILTER,
                    table_name,
                    drop_row_filter_sql(table_name),
                    detail=f"{live.row_filter[0]} is not in policy",
                )
            )

        desired_masks = {m.column.lower(): policy.qualify(m.function) for m in table.column_masks}
        for column in sorted(set(desired_masks) | set(live.column_masks)):
            want, have = desired_masks.get(column), live.column_masks.get(column)
            target = f"{table_name}.{column}"
            if want and want != have:
                plan.sql_changes.append(
                    SqlChange(
                        SqlAction.SET_MASK,
                        target,
                        set_mask_sql(table_name, column, want),
                        detail=_was(have),
                    )
                )
            elif have and not want:
                plan.sql_changes.append(
                    SqlChange(
                        SqlAction.DROP_MASK,
                        target,
                        drop_mask_sql(table_name, column),
                        detail=f"{have} is not in policy",
                    )
                )
    return plan


def _was(previous: str | None) -> str:
    return f"currently {previous}" if previous else "currently unprotected"


@dataclass
class ApplyResult:
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def apply_plan(
    plan: Plan,
    backend: Backend,
    *,
    revoke: bool = True,
    log: Callable[[str], None] = lambda _: None,
) -> ApplyResult:
    """Apply grants first (batched per securable), then filter/mask DDL in order.

    With ``revoke=False`` privileges are only ever added; excess grants are left
    in place and reported as skipped, so a first rollout cannot lock anyone out.
    """
    result = ApplyResult()
    batches: dict[tuple[SecurableType, str], dict[str, tuple[frozenset[str], frozenset[str]]]] = {}
    for change in plan.grant_changes:
        remove = change.remove if revoke else frozenset()
        if change.remove and not revoke:
            result.skipped.extend(s for s in change.sql() if s.startswith("REVOKE"))
        if change.add or remove:
            batch = batches.setdefault((change.securable_type, change.securable), {})
            batch[change.principal] = (change.add, remove)

    for (securable_type, securable), changes in batches.items():
        backend.update_grants(securable_type, securable, changes)
        for principal, (add, remove) in sorted(changes.items()):
            for line in GrantChange(securable_type, securable, principal, add, remove).sql():
                log(f"applied: {line}")
                result.applied.append(line)

    for sql_change in plan.sql_changes:
        backend.execute_sql(sql_change.statement)
        log(f"applied: {sql_change.action.value} {sql_change.target}")
        result.applied.append(sql_change.statement)
    return result
