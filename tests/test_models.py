from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import EXAMPLES, WritePolicy
from uc_policy.models import (
    CatalogPolicy,
    PolicyError,
    SecurableType,
    load_policies,
    load_policy_file,
    policy_json_schema,
    quote_ident,
)


def test_examples_load() -> None:
    policies = load_policies(EXAMPLES / "policies")
    assert [p.catalog for p in policies] == ["finance", "hr"]


def test_minimal_site_example(write_policy: WritePolicy) -> None:
    policy = load_policy_file(
        write_policy("""
        catalog: finance
        grants:
          - principal: finance_analysts
            privileges: [USE_CATALOG, SELECT]
          - principal: finance_engineers
            privileges: [USE_CATALOG, SELECT, MODIFY]
        """)
    )
    [catalog] = list(policy.securables())
    assert catalog.type is SecurableType.CATALOG
    assert catalog.desired() == {
        "finance_analysts": frozenset({"USE_CATALOG", "SELECT"}),
        "finance_engineers": frozenset({"USE_CATALOG", "SELECT", "MODIFY"}),
    }


def test_securables_cover_catalog_schemas_tables(finance_policy: CatalogPolicy) -> None:
    names = [(s.type.value, s.full_name) for s in finance_policy.securables()]
    assert ("CATALOG", "finance") in names
    assert ("SCHEMA", "finance.payments") in names
    assert ("TABLE", "finance.payments.transactions") in names


def test_sql_spelling_of_privileges_is_normalised(write_policy: WritePolicy) -> None:
    policy = load_policy_file(
        write_policy("""
        catalog: c
        grants:
          - principal: g
            privileges: ["use catalog", "SELECT"]
        """)
    )
    assert policy.grants[0].privileges == ["SELECT", "USE_CATALOG"]


INVALID = {
    "privilege not valid on table": (
        """
        catalog: c
        schemas:
          - name: s
            tables:
              - name: t
                grants:
                  - principal: g
                    privileges: [USE_CATALOG]
        """,
        "USE_CATALOG not valid on a table",
    ),
    "principal listed twice": (
        """
        catalog: c
        grants:
          - principal: g
            privileges: [SELECT]
          - principal: g
            privileges: [MODIFY]
        """,
        "listed twice",
    ),
    "duplicate privileges": (
        """
        catalog: c
        grants:
          - principal: g
            privileges: [SELECT, select]
        """,
        "duplicate privileges",
    ),
    "unmanaged principal granted": (
        """
        catalog: c
        grants:
          - principal: admins
            privileges: [SELECT]
        unmanaged_principals: [admins]
        """,
        "declared unmanaged",
    ),
    "undeclared mask function": (
        """
        catalog: c
        schemas:
          - name: s
            tables:
              - name: t
                column_masks:
                  - column: email
                    function: gov.mask_email
        """,
        "is not declared under functions",
    ),
    "mask used as row filter": (
        """
        catalog: c
        schemas:
          - name: s
            tables:
              - name: t
                row_filter: {function: gov.mask_email, columns: [email]}
        functions:
          - kind: column_mask
            name: gov.mask_email
            parameter: {name: email, type: STRING}
            exempt_groups: [pii]
            masked_expression: "'***'"
        """,
        "is a column mask, not a row filter",
    ),
    "row filter arity": (
        """
        catalog: c
        schemas:
          - name: s
            tables:
              - name: t
                row_filter: {function: gov.f, columns: [a, b]}
        functions:
          - kind: row_filter
            name: gov.f
            parameters: [{name: a, type: STRING}]
            exempt_groups: [admins]
        """,
        r"takes 1 column\(s\), 2 given",
    ),
    "row filter without rules": (
        """
        catalog: c
        functions:
          - kind: row_filter
            name: gov.f
            parameters: [{name: a, type: STRING}]
        """,
        "hides every row",
    ),
    "duplicate schema": (
        """
        catalog: c
        schemas:
          - name: s
          - name: S
        """,
        "duplicate schema",
    ),
    "unsafe identifier": (
        """
        catalog: "c; DROP TABLE x"
        """,
        "String should match pattern",
    ),
    "typo in key": (
        """
        catalog: c
        grant:
          - principal: g
            privileges: [SELECT]
        """,
        "Extra inputs are not permitted",
    ),
}


@pytest.mark.parametrize(("yaml_text", "message"), INVALID.values(), ids=INVALID.keys())
def test_invalid_policies_rejected(write_policy: WritePolicy, yaml_text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        load_policy_file(write_policy(yaml_text))


def test_invalid_yaml(write_policy: WritePolicy) -> None:
    with pytest.raises(PolicyError, match="invalid YAML"):
        load_policy_file(write_policy("catalog: [unclosed"))


def test_duplicate_catalog_across_files(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text("catalog: finance\n")
    (tmp_path / "b.yaml").write_text("catalog: FINANCE\n")
    with pytest.raises(PolicyError, match="more than one file"):
        load_policies(tmp_path)


def test_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match=r"no \.yml"):
        load_policies(tmp_path)


def test_qualify(finance_policy: CatalogPolicy) -> None:
    assert finance_policy.qualify("governance.mask_email") == "finance.governance.mask_email"
    assert finance_policy.qualify("other.gov.f") == "other.gov.f"


def test_declared_principals_include_function_groups(finance_policy: CatalogPolicy) -> None:
    principals = finance_policy.declared_principals()
    assert {"finance_analysts", "finance_pii_readers", "finance_analysts_in"} <= principals


def test_committed_json_schema_is_current() -> None:
    committed = json.loads((EXAMPLES.parent / "schema" / "policy.schema.json").read_text())
    assert committed == policy_json_schema(), "run: ucpolicy schema > schema/policy.schema.json"


def test_quote_ident() -> None:
    assert quote_ident("a.b_1.c") == "`a`.`b_1`.`c`"
    with pytest.raises(ValueError, match="unsafe"):
        quote_ident("a`; DROP")
