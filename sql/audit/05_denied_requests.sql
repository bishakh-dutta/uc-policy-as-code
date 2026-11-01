-- Unity Catalog requests that were refused (e.g. PERMISSION_DENIED). A spike after a
-- policy change usually means a grant was removed that a job still needs.
-- Parameter: :lookback_days (INT).
SELECT
  event_time,
  user_identity.email                    AS principal,
  action_name,
  COALESCE(request_params.full_name_arg,
           request_params.table_full_name,
           request_params.securable_full_name) AS securable,
  response.status_code                   AS status_code,
  response.error_message                 AS error_message
FROM system.access.audit
WHERE service_name = 'unityCatalog'
  AND response.status_code IN (401, 403)
  AND event_date >= date_sub(current_date(), :lookback_days)
ORDER BY event_time DESC;
