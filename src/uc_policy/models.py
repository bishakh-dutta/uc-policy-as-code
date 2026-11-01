"""Policy file schema, validation and loading.

One YAML file declares the desired access state of one Unity Catalog catalog:
grants on the catalog, its schemas and tables, plus the SQL functions used as
row filters and column masks and where they are attached.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


class SecurableType(StrEnum):
    CATALOG = "CATALOG"
    SCHEMA = "SCHEMA"
    TABLE = "TABLE"


# Privileges that Unity Catalog accepts on each securable type. Kept deliberately
# narrow so that a typo (or USE_CATALOG on a table) fails at PR time, not at apply.
# fmt: off
ALLOWED_PRIVILEGES: dict[SecurableType, frozenset[str]] = {
    SecurableType.CATALOG: frozenset(
        {
            "ALL_PRIVILEGES", "APPLY_TAG", "BROWSE", "CREATE_FUNCTION",
            "CREATE_MATERIALIZED_VIEW", "CREATE_MODEL", "CREATE_SCHEMA", "CREATE_TABLE",
            "CREATE_VOLUME", "EXECUTE", "EXTERNAL_USE_SCHEMA", "MANAGE", "MODIFY",
            "READ_VOLUME", "REFRESH", "SELECT", "USE_CATALOG", "USE_SCHEMA", "WRITE_VOLUME",
        }
    ),
    SecurableType.SCHEMA: frozenset(
        {
            "ALL_PRIVILEGES", "APPLY_TAG", "CREATE_FUNCTION", "CREATE_MATERIALIZED_VIEW",
            "CREATE_MODEL", "CREATE_TABLE", "CREATE_VOLUME", "EXECUTE", "EXTERNAL_USE_SCHEMA",
            "MANAGE", "MODIFY", "READ_VOLUME", "REFRESH", "SELECT", "USE_SCHEMA",
            "WRITE_VOLUME",
        }
    ),
    SecurableType.TABLE: frozenset(
        {"ALL_PRIVILEGES", "APPLY_TAG", "MANAGE", "MODIFY", "REFRESH", "SELECT"}
    ),
}
# fmt: on

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
Principal = Annotated[str, StringConstraints(min_length=1, max_length=255, strip_whitespace=True)]
SqlType = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_(), <>:]*$")]
# "schema.function" (resolved inside the policy's catalog) or "catalog.schema.function".
FunctionRef = Annotated[
    str,
    StringConstraints(pattern=r"^([A-Za-z_][A-Za-z0-9_]*\.){1,2}[A-Za-z_][A-Za-z0-9_]*$"),
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Grant(_Strict):
    principal: Principal
    privileges: list[str] = Field(min_length=1)

    @field_validator("privileges")
    @classmethod
    def _normalise(cls, value: list[str]) -> list[str]:
        # Accept both the SQL spelling ("USE CATALOG") and the API spelling ("USE_CATALOG").
        normalised = [p.strip().upper().replace(" ", "_") for p in value]
        if len(set(normalised)) != len(normalised):
            raise ValueError("duplicate privileges")
        return sorted(normalised)


class RowFilterBinding(_Strict):
    function: FunctionRef
    columns: list[Identifier] = Field(min_length=1)


class ColumnMaskBinding(_Strict):
    column: Identifier
    function: FunctionRef


class Table(_Strict):
    name: Identifier
    grants: list[Grant] = Field(default_factory=list)
    row_filter: RowFilterBinding | None = None
    column_masks: list[ColumnMaskBinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_masks(self) -> Table:
        columns = [m.column.lower() for m in self.column_masks]
        if len(set(columns)) != len(columns):
            raise ValueError(f"table {self.name!r}: a column can only have one mask")
        return self


class Schema(_Strict):
    name: Identifier
    grants: list[Grant] = Field(default_factory=list)
    tables: list[Table] = Field(default_factory=list)


class Parameter(_Strict):
    name: Identifier
    type: SqlType


class GroupRule(_Strict):
    group: Principal
    condition: str = Field(min_length=1)


class MaskFunction(_Strict):
    """A column mask: members of ``exempt_groups`` see the raw value."""

    kind: Literal["column_mask"]
    name: FunctionRef
    parameter: Parameter
    exempt_groups: list[Principal] = Field(min_length=1)
    masked_expression: str = Field(min_length=1)
    comment: str | None = None


class RowFilterFunction(_Strict):
    """A row filter: exempt groups see every row, other groups see rows matching their rule."""

    kind: Literal["row_filter"]
    name: FunctionRef
    parameters: list[Parameter] = Field(min_length=1)
    exempt_groups: list[Principal] = Field(default_factory=list)
    group_rules: list[GroupRule] = Field(default_factory=list)
    comment: str | None = None

    @model_validator(mode="after")
    def _has_rule(self) -> RowFilterFunction:
        if not self.exempt_groups and not self.group_rules:
            raise ValueError(
                f"row filter {self.name!r} needs exempt_groups or group_rules, "
                "otherwise it hides every row"
            )
        return self


SecurityFunction = Annotated[MaskFunction | RowFilterFunction, Field(discriminator="kind")]


class CatalogPolicy(_Strict):
    catalog: Identifier
    grants: list[Grant] = Field(default_factory=list)
    schemas: list[Schema] = Field(default_factory=list)
    functions: list[SecurityFunction] = Field(default_factory=list)
    # Principals whose grants this tool must never touch (e.g. a platform admin group
    # that is managed elsewhere). Their grants are neither revoked nor reported as drift.
    unmanaged_principals: list[Principal] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> CatalogPolicy:
        errors: list[str] = []
        for securable in self.securables():
            seen: set[str] = set()
            for grant in securable.grants:
                if grant.principal in seen:
                    errors.append(
                        f"{securable.full_name}: principal {grant.principal!r} "
                        "is listed twice; merge its privileges"
                    )
                seen.add(grant.principal)
                bad = set(grant.privileges) - ALLOWED_PRIVILEGES[securable.type]
                if bad:
                    errors.append(
                        f"{securable.full_name}: {', '.join(sorted(bad))} not valid on a "
                        f"{securable.type.value.lower()} (principal {grant.principal!r})"
                    )
                if grant.principal in self.unmanaged_principals:
                    errors.append(
                        f"{securable.full_name}: {grant.principal!r} is declared "
                        "unmanaged but also granted privileges"
                    )
        for kind, names in (
            ("schema", [s.name.lower() for s in self.schemas]),
            ("function", [self.qualify(f.name) for f in self.functions]),
        ):
            dupes = {n for n in names if names.count(n) > 1}
            if dupes:
                errors.append(f"duplicate {kind} declarations: {', '.join(sorted(dupes))}")
        for schema in self.schemas:
            tables = [t.name.lower() for t in schema.tables]
            dupes = {t for t in tables if tables.count(t) > 1}
            if dupes:
                errors.append(
                    f"{self.catalog}.{schema.name}: duplicate tables {', '.join(sorted(dupes))}"
                )
        errors.extend(self._validate_bindings())
        if errors:
            raise ValueError("; ".join(errors))
        return self

    def _validate_bindings(self) -> list[str]:
        functions = {self.qualify(f.name): f for f in self.functions}
        errors: list[str] = []
        for schema in self.schemas:
            for table in schema.tables:
                where = f"{self.catalog}.{schema.name}.{table.name}"
                if table.row_filter:
                    fn = functions.get(self.qualify(table.row_filter.function))
                    if fn is None:
                        errors.append(
                            f"{where}: row filter {table.row_filter.function!r} "
                            "is not declared under functions"
                        )
                    elif not isinstance(fn, RowFilterFunction):
                        errors.append(f"{where}: {fn.name!r} is a column mask, not a row filter")
                    elif len(fn.parameters) != len(table.row_filter.columns):
                        errors.append(
                            f"{where}: row filter {fn.name!r} takes "
                            f"{len(fn.parameters)} column(s), "
                            f"{len(table.row_filter.columns)} given"
                        )
                for mask in table.column_masks:
                    fn = functions.get(self.qualify(mask.function))
                    if fn is None:
                        errors.append(
                            f"{where}: mask {mask.function!r} is not declared under functions"
                        )
                    elif not isinstance(fn, MaskFunction):
                        errors.append(f"{where}: {fn.name!r} is a row filter, not a column mask")
        return errors

    def qualify(self, ref: str) -> str:
        """Resolve ``schema.fn`` to ``catalog.schema.fn``; full names pass through."""
        parts = ref.split(".")
        return ".".join([self.catalog, *parts] if len(parts) == 2 else parts).lower()

    def securables(self) -> Iterator[DeclaredSecurable]:
        yield DeclaredSecurable(SecurableType.CATALOG, self.catalog.lower(), self.grants)
        for schema in self.schemas:
            yield DeclaredSecurable(
                SecurableType.SCHEMA, f"{self.catalog}.{schema.name}".lower(), schema.grants
            )
            for table in schema.tables:
                yield DeclaredSecurable(
                    SecurableType.TABLE,
                    f"{self.catalog}.{schema.name}.{table.name}".lower(),
                    table.grants,
                )

    def tables(self) -> Iterator[tuple[str, Table]]:
        for schema in self.schemas:
            for table in schema.tables:
                yield f"{self.catalog}.{schema.name}.{table.name}".lower(), table

    def declared_principals(self) -> set[str]:
        principals = {g.principal for s in self.securables() for g in s.grants}
        for fn in self.functions:
            principals.update(fn.exempt_groups)
            if isinstance(fn, RowFilterFunction):
                principals.update(r.group for r in fn.group_rules)
        return principals


@dataclass(frozen=True)
class DeclaredSecurable:
    type: SecurableType
    full_name: str
    grants: list[Grant]

    def desired(self) -> dict[str, frozenset[str]]:
        return {g.principal: frozenset(g.privileges) for g in self.grants}


class PolicyError(Exception):
    """Raised when policy files cannot be loaded or fail validation."""


def load_policy_file(path: Path) -> CatalogPolicy:
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: expected a mapping at the top level")
    try:
        return CatalogPolicy.model_validate(raw)
    except ValueError as exc:
        raise PolicyError(f"{path}: {exc}") from exc


def load_policies(path: Path) -> list[CatalogPolicy]:
    """Load one policy file, or every ``*.yml``/``*.yaml`` file under a directory."""
    if path.is_dir():
        files = sorted(p for p in path.rglob("*") if p.suffix in {".yml", ".yaml"})
        if not files:
            raise PolicyError(f"{path}: no .yml/.yaml policy files found")
    elif path.is_file():
        files = [path]
    else:
        raise PolicyError(f"{path}: no such file or directory")

    policies = [load_policy_file(f) for f in files]
    catalogs = [p.catalog.lower() for p in policies]
    dupes = {c for c in catalogs if catalogs.count(c) > 1}
    if dupes:
        raise PolicyError(f"catalog declared in more than one file: {', '.join(sorted(dupes))}")
    return policies


def policy_json_schema() -> dict[str, Any]:
    """JSON Schema for editors (e.g. the YAML language server) and external validators."""
    return CatalogPolicy.model_json_schema()


_SQL_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def quote_ident(name: str) -> str:
    """Backtick-quote each part of a dotted Unity Catalog name."""
    parts = name.split(".")
    if not all(_SQL_IDENT.match(p) for p in parts):
        raise ValueError(f"unsafe identifier: {name!r}")
    return ".".join(f"`{p}`" for p in parts)
