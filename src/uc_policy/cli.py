"""``ucpolicy`` command-line interface.

Exit codes: 0 success / no changes, 1 error, 2 drift found (``drift``) or
changes pending (``plan --detailed-exitcode``).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from databricks.sdk.errors.base import DatabricksError

from uc_policy import __version__
from uc_policy.backend import Backend, BackendError, DatabricksBackend, SnapshotBackend
from uc_policy.drift import detect_drift
from uc_policy.models import PolicyError, load_policies, policy_json_schema
from uc_policy.planner import apply_plan, build_plan
from uc_policy.render import drift_text, plan_markdown, plan_text, plan_to_dict, to_json

EXIT_OK, EXIT_ERROR, EXIT_CHANGES = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ucpolicy",
        description="Unity Catalog access governance as code.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_policies(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "policies",
            type=Path,
            nargs="?",
            default=Path("policies"),
            help="policy file or directory of *.yml files (default: policies/)",
        )

    def add_backend(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--state-file",
            type=Path,
            help="read live state from a JSON snapshot instead of a workspace",
        )
        p.add_argument("--profile", help="Databricks config profile (default: env auth)")
        p.add_argument(
            "--warehouse-id",
            default=os.environ.get("DATABRICKS_WAREHOUSE_ID"),
            help="SQL warehouse for row filter / mask DDL (env: DATABRICKS_WAREHOUSE_ID)",
        )

    def add_output(p: argparse.ArgumentParser, formats: list[str]) -> None:
        p.add_argument("--format", choices=formats, default="text")
        p.add_argument("--out", type=Path, help="also write the output to this file")

    p = sub.add_parser("validate", help="validate policy files (no workspace access)")
    add_policies(p)

    p = sub.add_parser("plan", help="show the changes apply would make; changes nothing")
    add_policies(p)
    add_backend(p)
    add_output(p, ["text", "json", "markdown"])
    p.add_argument(
        "--detailed-exitcode", action="store_true", help="exit 2 when there are pending changes"
    )

    p = sub.add_parser("apply", help="apply the policy to the workspace")
    add_policies(p)
    add_backend(p)
    p.add_argument("--auto-approve", action="store_true", help="do not ask for confirmation (CI)")
    p.add_argument(
        "--no-revoke", action="store_true", help="only add privileges; leave excess grants in place"
    )

    p = sub.add_parser("drift", help="report drift between workspace and policy")
    add_policies(p)
    add_backend(p)
    add_output(p, ["text", "json"])
    p.add_argument(
        "--resolve-principals",
        action="store_true",
        help="also check that principals exist in the workspace (SCIM lookups)",
    )
    p.add_argument(
        "--json-out", type=Path, help="also write the JSON report here, whatever --format is"
    )

    sub.add_parser("schema", help="print the JSON Schema for policy files")
    return parser


def _backend(args: argparse.Namespace) -> Backend:
    if args.state_file:
        return SnapshotBackend.from_file(args.state_file)
    from databricks.sdk import WorkspaceClient

    client = WorkspaceClient(profile=args.profile) if args.profile else WorkspaceClient()
    return DatabricksBackend(client, args.warehouse_id)


def _emit(text: str, out: Path | None) -> None:
    sys.stdout.write(text)
    if out:
        out.write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "schema":
        sys.stdout.write(to_json(policy_json_schema()))
        return EXIT_OK

    try:
        policies = load_policies(args.policies)
        if args.command == "validate":
            for policy in policies:
                n = sum(1 for _ in policy.securables())
                print(
                    f"ok: catalog {policy.catalog} ({n} securables, "
                    f"{len(policy.functions)} security functions)"
                )
            return EXIT_OK

        backend = _backend(args)

        if args.command == "plan":
            plan = build_plan(policies, backend)
            if args.format == "json":
                _emit(to_json(plan_to_dict(plan)), args.out)
            else:
                _emit(
                    plan_markdown(plan) if args.format == "markdown" else plan_text(plan), args.out
                )
            return EXIT_CHANGES if args.detailed_exitcode and not plan.is_empty else EXIT_OK

        if args.command == "apply":
            plan = build_plan(policies, backend)
            sys.stdout.write(plan_text(plan))
            if plan.is_empty:
                return EXIT_OK
            if not args.auto_approve:
                if not sys.stdin.isatty():
                    print(
                        "error: refusing to apply without --auto-approve "
                        "in a non-interactive shell",
                        file=sys.stderr,
                    )
                    return EXIT_ERROR
                if input("Apply these changes? Type 'yes' to continue: ").strip() != "yes":
                    print("Apply cancelled.")
                    return EXIT_OK
            result = apply_plan(plan, backend, revoke=not args.no_revoke, log=print)
            for skipped in result.skipped:
                print(f"skipped (--no-revoke): {skipped}")
            print(f"Apply complete: {len(result.applied)} change(s) applied.")
            return EXIT_OK

        if args.command == "drift":
            report = detect_drift(policies, backend, resolve_principals=args.resolve_principals)
            text = to_json(report.to_dict()) if args.format == "json" else drift_text(report)
            _emit(text, args.out)
            if args.json_out:
                args.json_out.write_text(to_json(report.to_dict()), encoding="utf-8")
            return EXIT_CHANGES if report.has_drift else EXIT_OK

    except (PolicyError, BackendError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except DatabricksError as exc:
        # Auth, permission and API errors from the SDK, without a traceback.
        print(f"error: Databricks API: {exc}", file=sys.stderr)
        return EXIT_ERROR
    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
