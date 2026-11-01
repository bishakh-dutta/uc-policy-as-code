# Live test on a real workspace (free)

This folder runs `ucpolicy` against a real Unity Catalog workspace, using a
sandbox catalog called `uc_policy_demo` that the scripts create and you can drop
afterwards. It is set up for **Databricks Free Edition** (free, no credit card),
and also works on an Azure Databricks 14-day Premium trial or any other workspace.

| File | Purpose |
|---|---|
| `setup.sql` | Creates `uc_policy_demo` with `sales.customers` (synthetic PII) and a `governance` schema |
| `policies/uc_policy_demo.yml` | The policy: grants, a row filter and two column masks |
| `teardown.sql` | `DROP CATALOG uc_policy_demo CASCADE` |
| `../tests/integration/test_live.py` | Opt-in end-to-end test (apply, check the effect, inject drift, revert) |

## Free Edition constraints this setup works around

From the [Free Edition limitations](https://docs.databricks.com/aws/en/getting-started/free-edition-limitations)
page: no account console or account-level APIs, no SCIM, serverless only, and one
2X-Small SQL warehouse. So:

- **No custom groups.** Unity Catalog only accepts account groups in `GRANT`s, and
  Free Edition has no account console to create them. The policy grants to the
  built-in `account users` group instead. The exempt groups named in the filter
  and masks (`uc_policy_admins`, `uc_policy_pii_readers`) don't need to exist; while
  they don't, nobody is exempt, so you see the filter and masks act on your own
  queries. (Row filters and masks apply to table owners too.)
- **No service principal with OAuth.** Use a personal access token, with a short
  lifetime, for local runs and for GitHub Actions.
- **System tables**: `system.access.audit` was readable on Free Edition in the
  run below. Events arrive with a delay, so grant changes from a fresh run may
  not show up for a while.

`CREATE CATALOG`, grants to `account users`, SQL UDFs, row filters and column
masks all worked on Free Edition in the run below. If something is refused in
your workspace, the Azure Databricks trial ("Trial (Premium - 14-Days Free DBUs)" pricing tier) has
the full feature set. It needs a pay-as-you-go Azure subscription, and Azure
infrastructure may still bill; set a budget alert and delete the resource group
when done.

## 1. Workspace

1. Sign up for Databricks Free Edition and open the workspace.
2. **SQL Warehouses**: open the warehouse and copy its ID (the part after
   `/sql/warehouses/` in the URL, or *Connection details*).
3. **Settings → Developer → Access tokens**: generate a token (e.g. 30 days).
4. Copy the workspace URL from the browser, e.g. `https://dbc-xxxx.cloud.databricks.com`.

## 2. Run locally

```bash
export DATABRICKS_HOST=https://dbc-xxxx.cloud.databricks.com
export DATABRICKS_TOKEN=dapi...
export DATABRICKS_WAREHOUSE_ID=...
```

(PowerShell: `$env:DATABRICKS_HOST = "..."` and so on.)

Run `live/setup.sql` in the SQL editor, then:

```bash
ucpolicy drift live/policies    # before: missing grants, no filter or masks yet
ucpolicy plan  live/policies
ucpolicy apply live/policies    # type "yes"
ucpolicy drift live/policies    # after: "No drift."
```

Check the effect in the SQL editor:

```sql
SELECT * FROM uc_policy_demo.sales.customers;
-- Only region IN rows, e-mails like ***@example.com, cards like XXXX-XXXX-XXXX-1111
```

Now make a change outside the process and watch it get caught:

```sql
GRANT MODIFY ON TABLE uc_policy_demo.sales.customers TO `account users`;
ALTER TABLE uc_policy_demo.sales.customers ALTER COLUMN email DROP MASK;
```

```bash
ucpolicy drift live/policies    # exit code 2: excess MODIFY, email mask missing
ucpolicy apply live/policies    # reverts both
```

Or run the whole sequence as a test:

```bash
UCPOLICY_LIVE_TEST=1 pytest tests/integration -v
```

## 3. Run it in GitHub Actions

1. In the repository: **Settings → Secrets and variables → Actions**.
   - Secrets: `DATABRICKS_HOST`, `DATABRICKS_TOKEN`, `DATABRICKS_WAREHOUSE_ID`.
   - Variables: `UCPOLICY_LIVE` = `true`.
2. **Settings → Environments**: create `databricks-prod`, optionally with yourself
   as a required reviewer.
3. **Actions → integration → Run workflow** runs the end-to-end test.
4. Open a PR that edits `live/policies/uc_policy_demo.yml` (for example, add
   `MODIFY` for `account users` on the table). `policy-plan` comments the plan on
   the PR. Merging it runs `policy-apply`; the daily `drift` job then keeps checking.

Keep the drift schedule at daily. Free Edition shuts compute down for the day
if you go over its usage quota.

## Verified run

Run on 2026-11-01 against a Databricks Free Edition workspace (serverless
2X-Small SQL warehouse), `databricks-sdk` 0.158, Python 3.13.

`ucpolicy drift live/policies` before apply (exit code 2):

```text
Missing grants (in policy, not in the workspace):
  + catalog uc_policy_demo                account users  USE_CATALOG
  + schema uc_policy_demo.sales           account users  USE_SCHEMA
  + table uc_policy_demo.sales.customers  account users  SELECT

Principals referenced by policy but not found in the workspace:
  ? uc_policy_admins
  ? uc_policy_pii_readers

Row filter / column mask drift:
  ~ create_function  uc_policy_demo.governance.region_filter     (function does not exist)
  ~ create_function  uc_policy_demo.governance.mask_email        (function does not exist)
  ~ create_function  uc_policy_demo.governance.mask_card_number  (function does not exist)
  ~ set_row_filter   uc_policy_demo.sales.customers              (currently unprotected)
  ~ set_mask         uc_policy_demo.sales.customers.card_number  (currently unprotected)
  ~ set_mask         uc_policy_demo.sales.customers.email        (currently unprotected)
```

`ucpolicy apply live/policies --auto-approve` applied 9 changes, after which
`ucpolicy drift` reported `No drift.` (exit code 0). The two groups are reported
because they do not exist on Free Edition, which is intended here (see above).

Querying the table afterwards as the catalog owner (4 rows in the table, 2 in
region `IN`):

```text
customer_id | name  | email           | card_number         | region
1           | Asha  | ***@example.com | XXXX-XXXX-XXXX-1111 | IN
2           | Rohan | ***@example.com | XXXX-XXXX-XXXX-0004 | IN
```

`UCPOLICY_LIVE_TEST=1 pytest tests/integration -v`:

```text
tests/integration/test_live.py::test_apply_converges PASSED
tests/integration/test_live.py::test_row_filter_and_masks_take_effect PASSED
tests/integration/test_live.py::test_manual_grant_is_detected_and_reverted PASSED
3 passed in 27.97s
```

## 4. Clean up

Run `live/teardown.sql`, delete the access token, and set `UCPOLICY_LIVE` to
`false` (or delete it) so the scheduled job stops.
