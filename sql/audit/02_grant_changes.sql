-- Every GRANT / REVOKE on a Unity Catalog securable: who changed what, and when.
-- `changes` is the JSON list of {principal, add, remove} sent to the permissions API.
-- Parameter: :lookback_days (INT).
SELECT
  event_time,
  user_identity.email                    AS changed_by,
  request_params.securable_type          AS securable_type,
  request_params.securable_full_name     AS securable,
  request_params.changes                 AS changes,
  response.status_code                   AS status_code
FROM system.access.audit
WHERE service_name = 'unityCatalog'
  AND action_name = 'updatePermissions'
  AND event_date >= date_sub(current_date(), :lookback_days)
ORDER BY event_time DESC;
