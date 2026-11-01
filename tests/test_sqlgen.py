from __future__ import annotations

from uc_policy.models import CatalogPolicy, MaskFunction, RowFilterFunction
from uc_policy.sqlgen import (
    create_function_sql,
    drop_mask_sql,
    function_body,
    same_definition,
    set_mask_sql,
    set_row_filter_sql,
    sql_string,
)


def _fn(policy: CatalogPolicy, name: str) -> MaskFunction | RowFilterFunction:
    return next(f for f in policy.functions if f.name == name)


def test_mask_function_sql(finance_policy: CatalogPolicy) -> None:
    sql = create_function_sql(finance_policy, _fn(finance_policy, "governance.mask_card_number"))
    assert sql == (
        "CREATE OR REPLACE FUNCTION `finance`.`governance`.`mask_card_number`"
        "(card_number STRING)\n"
        "RETURNS STRING\n"
        "COMMENT 'Last four digits only, unless the caller is in finance_pii_readers.'\n"
        "RETURN CASE WHEN is_account_group_member('finance_pii_readers') THEN card_number "
        "ELSE concat('XXXX-XXXX-XXXX-', right(card_number, 4)) END"
    )


def test_row_filter_function_sql(finance_policy: CatalogPolicy) -> None:
    fn = _fn(finance_policy, "governance.region_filter")
    sql = create_function_sql(finance_policy, fn)
    assert sql.startswith(
        "CREATE OR REPLACE FUNCTION `finance`.`governance`.`region_filter`(region STRING)\n"
        "RETURNS BOOLEAN\n"
    )
    assert function_body(fn) == (
        "is_account_group_member('finance_engineers') "
        "OR is_account_group_member('finance_auditors') "
        "OR (is_account_group_member('finance_analysts_in') AND (region = 'IN')) "
        "OR (is_account_group_member('finance_analysts_eu') AND (region IN ('DE', 'FR', 'NL')))"
    )


def test_binding_statements() -> None:
    assert set_row_filter_sql("finance.payments.transactions", "finance.gov.f", ["region"]) == (
        "ALTER TABLE `finance`.`payments`.`transactions` "
        "SET ROW FILTER `finance`.`gov`.`f` ON (`region`)"
    )
    assert set_mask_sql("c.s.t", "email", "c.gov.mask_email") == (
        "ALTER TABLE `c`.`s`.`t` ALTER COLUMN `email` SET MASK `c`.`gov`.`mask_email`"
    )
    assert (
        drop_mask_sql("c.s.t", "email") == "ALTER TABLE `c`.`s`.`t` ALTER COLUMN `email` DROP MASK"
    )


def test_group_names_are_escaped() -> None:
    assert sql_string("o'brien\\team") == "'o\\'brien\\\\team'"


def test_same_definition_ignores_whitespace_only() -> None:
    assert same_definition("CASE WHEN x\n  THEN y END", "CASE WHEN x THEN y END")
    assert not same_definition("region = 'IN'", "region = 'in'")
    assert not same_definition("CASE WHEN x THEN y END", "CASE WHEN x THEN z END")
