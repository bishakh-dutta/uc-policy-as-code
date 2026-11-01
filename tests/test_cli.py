from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import EXAMPLES, InMemoryBackend
from uc_policy import cli
from uc_policy.render import PLAN_COMMENT_MARKER

POLICIES = str(EXAMPLES / "policies")
STATE = str(EXAMPLES / "live_state.json")


def test_validate(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["validate", POLICIES]) == 0
    assert "ok: catalog finance" in capsys.readouterr().out


def test_validate_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text("catalog: c\ngrants:\n  - principal: g\n    privileges: [FLY]\n")
    assert cli.main(["validate", str(bad)]) == 1
    assert "FLY not valid on a catalog" in capsys.readouterr().err


def test_plan_text(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["plan", POLICIES, "--state-file", STATE]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Plan: 1 privilege(s) to grant, 2 to revoke")
    assert "- table finance.payments.transactions  contractors_tmp" in out


def test_plan_detailed_exitcode() -> None:
    assert cli.main(["plan", POLICIES, "--state-file", STATE, "--detailed-exitcode"]) == 2


def test_plan_markdown_for_pr_comment(tmp_path: Path) -> None:
    out = tmp_path / "plan.md"
    cli.main(["plan", POLICIES, "--state-file", STATE, "--format", "markdown", "--out", str(out)])
    body = out.read_text()
    assert body.startswith(PLAN_COMMENT_MARKER)
    assert "```diff" in body
    assert "REVOKE SELECT ON TABLE finance.payments.transactions FROM `contractors_tmp`;" in body
    assert "SET MASK `hr`.`core`.`mask_salary`;" in body


def test_plan_json(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["plan", POLICIES, "--state-file", STATE, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["changes"] == 6
    assert data["grant_changes"][0]["securable_type"] in {"CATALOG", "SCHEMA", "TABLE"}


def test_drift_exits_2_and_writes_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    json_out = tmp_path / "drift.json"
    code = cli.main(
        [
            "drift",
            POLICIES,
            "--state-file",
            STATE,
            "--resolve-principals",
            "--json-out",
            str(json_out),
        ]
    )
    assert code == 2
    assert "contractors_tmp" in capsys.readouterr().out
    assert json.loads(json_out.read_text())["has_drift"] is True


def test_apply_refuses_snapshot(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["apply", POLICIES, "--state-file", STATE, "--auto-approve"]) == 1
    assert "read-only" in capsys.readouterr().err


def test_apply_requires_approval_when_not_interactive(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["apply", POLICIES, "--state-file", STATE]) == 1
    assert "--auto-approve" in capsys.readouterr().err


def test_apply_then_no_drift(
    monkeypatch: pytest.MonkeyPatch,
    snapshot_data: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    backend = InMemoryBackend(snapshot_data)
    monkeypatch.setattr(cli, "_backend", lambda args: backend)

    assert cli.main(["apply", POLICIES, "--auto-approve"]) == 0
    assert "Apply complete: 6 change(s) applied." in capsys.readouterr().out
    assert cli.main(["drift", POLICIES]) == 0


def test_schema_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["schema"]) == 0
    assert json.loads(capsys.readouterr().out)["title"] == "CatalogPolicy"
