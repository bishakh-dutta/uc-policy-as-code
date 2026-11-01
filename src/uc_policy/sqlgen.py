"""SQL generation for row filter and column mask functions and their bindings."""

from __future__ import annotations

import re

from uc_policy.models import CatalogPolicy, MaskFunction, RowFilterFunction, quote_ident


def sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _is_member(group: str) -> str:
    return f"is_account_group_member({sql_string(group)})"


def function_body(fn: MaskFunction | RowFilterFunction) -> str:
    """The expression after ``RETURN``; also what UC reports as ``routine_definition``."""
    if isinstance(fn, MaskFunction):
        exempt = " OR ".join(_is_member(g) for g in fn.exempt_groups)
        return f"CASE WHEN {exempt} THEN {fn.parameter.name} ELSE {fn.masked_expression} END"
    clauses = [_is_member(g) for g in fn.exempt_groups]
    clauses += [f"({_is_member(r.group)} AND ({r.condition}))" for r in fn.group_rules]
    return " OR ".join(clauses)


def create_function_sql(policy: CatalogPolicy, fn: MaskFunction | RowFilterFunction) -> str:
    if isinstance(fn, MaskFunction):
        params = f"{fn.parameter.name} {fn.parameter.type}"
        returns = fn.parameter.type
    else:
        params = ", ".join(f"{p.name} {p.type}" for p in fn.parameters)
        returns = "BOOLEAN"
    comment = f"\nCOMMENT {sql_string(fn.comment)}" if fn.comment else ""
    return (
        f"CREATE OR REPLACE FUNCTION {quote_ident(policy.qualify(fn.name))}({params})\n"
        f"RETURNS {returns}{comment}\n"
        f"RETURN {function_body(fn)}"
    )


def set_row_filter_sql(table: str, function: str, columns: list[str] | tuple[str, ...]) -> str:
    cols = ", ".join(quote_ident(c) for c in columns)
    return f"ALTER TABLE {quote_ident(table)} SET ROW FILTER {quote_ident(function)} ON ({cols})"


def drop_row_filter_sql(table: str) -> str:
    return f"ALTER TABLE {quote_ident(table)} DROP ROW FILTER"


def set_mask_sql(table: str, column: str, function: str) -> str:
    return (
        f"ALTER TABLE {quote_ident(table)} ALTER COLUMN {quote_ident(column)} "
        f"SET MASK {quote_ident(function)}"
    )


def drop_mask_sql(table: str, column: str) -> str:
    return f"ALTER TABLE {quote_ident(table)} ALTER COLUMN {quote_ident(column)} DROP MASK"


def same_definition(a: str, b: str) -> bool:
    """Compare SQL bodies ignoring whitespace (not case: literals are case-sensitive)."""

    def norm(sql: str) -> str:
        return re.sub(r"\s+", " ", sql).strip()

    return norm(a) == norm(b)
