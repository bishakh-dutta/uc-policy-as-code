from __future__ import annotations

import copy
import json
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from uc_policy.backend import SnapshotBackend
from uc_policy.models import CatalogPolicy, SecurableType, load_policy_file

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

WritePolicy = Callable[..., Path]


class InMemoryBackend(SnapshotBackend):
    """A writable snapshot: apply mutates it, so tests can check convergence."""

    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__(copy.deepcopy(data))
        self.grant_calls: list[tuple[str, str, dict[str, Any]]] = []
        self.statements: list[str] = []

    def update_grants(
        self,
        securable_type: SecurableType,
        full_name: str,
        changes: dict[str, tuple[frozenset[str], frozenset[str]]],
    ) -> None:
        self.grant_calls.append((securable_type.value, full_name, changes))
        live = self._grants.setdefault(f"{securable_type.value}/{full_name}", {})
        for principal, (add, remove) in changes.items():
            privileges = (set(live.get(principal, [])) | add) - remove
            if privileges:
                live[principal] = sorted(privileges)
            else:
                live.pop(principal, None)

    def execute_sql(self, statement: str) -> None:
        self.statements.append(statement)
        # Minimal interpretation of the statements this tool generates.
        words = statement.replace("`", "").split()
        if words[:4] == ["CREATE", "OR", "REPLACE", "FUNCTION"]:
            name = words[4].split("(")[0]
            self._functions[name] = statement.split("\nRETURN ", 1)[1]
        elif words[:2] == ["ALTER", "TABLE"]:
            table = self._tables.setdefault(words[2], {"row_filter": None, "column_masks": {}})
            if words[3:6] == ["SET", "ROW", "FILTER"]:
                cols = statement.split(" ON (", 1)[1].rstrip(")").replace("`", "")
                table["row_filter"] = {
                    "function": words[6],
                    "columns": [c.strip() for c in cols.split(",")],
                }
            elif words[3:6] == ["DROP", "ROW", "FILTER"]:
                table["row_filter"] = None
            elif words[3:5] == ["ALTER", "COLUMN"] and words[6] == "SET":
                table["column_masks"][words[5]] = words[8]
            elif words[3:5] == ["ALTER", "COLUMN"] and words[6] == "DROP":
                table["column_masks"].pop(words[5], None)


@pytest.fixture
def snapshot_data() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / "live_state.json").read_text())
    return data


@pytest.fixture
def finance_policy() -> CatalogPolicy:
    return load_policy_file(EXAMPLES / "policies" / "finance.yml")


@pytest.fixture
def write_policy(tmp_path: Path) -> WritePolicy:
    def _write(yaml_text: str, name: str = "policy.yml") -> Path:
        path = tmp_path / name
        path.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
        return path

    return _write


def empty_state_for(policy: CatalogPolicy) -> dict[str, Any]:
    """Live state where every declared securable exists with no grants."""
    return {
        "grants": {f"{s.type.value}/{s.full_name}": {} for s in policy.securables()},
        "tables": {name: {"row_filter": None, "column_masks": {}} for name, _ in policy.tables()},
        "functions": {},
    }
