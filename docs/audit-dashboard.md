# Audit dashboard on `system.access.audit`

The queries in [`sql/audit/`](../sql/audit) answer the questions an access review
asks: who read which table and when, who changed which grant, which grant changes
bypassed the pull-request pipeline, and which requests were denied. This guide
turns them into a Databricks AI/BI dashboard. The same queries work as saved
queries in a legacy Databricks SQL dashboard.

## Prerequisites

1. **System tables enabled.** The `system.access` schema must be enabled for the
   metastore (an account admin does this once; see the Databricks docs on
   *Enable system table schemas*).
2. **Read access** for whoever runs the dashboard, for example a `governance_auditors`
   group:

   ```sql
   GRANT USE CATALOG ON CATALOG system TO `governance_auditors`;
   GRANT USE SCHEMA  ON SCHEMA  system.access TO `governance_auditors`;
   GRANT SELECT      ON TABLE   system.access.audit TO `governance_auditors`;
   ```
3. **A SQL warehouse** (serverless or pro) to run the dashboard.

## Build it

1. In the workspace, open **Dashboards → Create dashboard**.
2. On the **Data** tab, add one dataset per file in `sql/audit/` (paste the SQL,
   name the dataset after the file).
3. Each query uses the named parameter `:lookback_days`. When the editor detects
   it, set the type to *Integer* and the default to `30`. Query 03 also uses
   `:pipeline_principal`: set its default to the application ID of the service
   principal that runs `policy-apply` in GitHub Actions.
4. On the **Canvas**, add a filter widget bound to `lookback_days` across all
   datasets, then add:

   | Widget | Dataset | Visualization |
   |---|---|---|
   | Table reads / grant changes / denied requests / active principals | `06_daily_activity_summary` | Four counters (sum over the period) |
   | Activity over time | `06_daily_activity_summary` | Line chart, x = `event_date` |
   | Grant changes outside the pipeline | `03_grant_changes_outside_pipeline` | Table, sorted by `event_time` |
   | All grant changes | `02_grant_changes` | Table |
   | PII table access | `04_pii_table_access` | Stacked bar, x = `day`, colour = `table_full_name` |
   | Who accessed what | `01_table_access_by_user` | Table with a filter on `table_full_name` |
   | Denied requests | `05_denied_requests` | Table |

5. **Publish** the dashboard with *embedded credentials off* if every viewer should
   only see what their own grants allow, or on (using the publisher's access) for a
   shared audit view.
6. Optionally add a **schedule** to email a PDF snapshot to the data owners weekly.

## Reading it alongside drift detection

`ucpolicy drift` tells you *what* is different from the policy right now. The
"grant changes outside the pipeline" table tells you *who* made the change and
*when*: every excess grant reported by the drift job should have a matching row
there (for example a manual `GRANT SELECT ... TO contractors_tmp` from the
Catalog Explorer).

## Notes on the audit schema

- Audit rows usually land in `system.access.audit` within minutes, but delivery is
  not real time.
- `request_params` is a `MAP<STRING, STRING>` whose keys depend on `action_name`.
  The queries use `full_name_arg` / `table_full_name` for table access and
  `securable_type` / `securable_full_name` / `changes` for `updatePermissions`.
  If a widget is empty, inspect a few raw rows for your workspace
  (`SELECT action_name, request_params FROM system.access.audit WHERE service_name = 'unityCatalog' LIMIT 50`)
  and adjust the keys.
- Retention of system tables is set by Databricks (see the system tables
  documentation); copy rows to your own table if you need a longer history.
