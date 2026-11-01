-- Who accessed which Unity Catalog table, and when.
-- Source: system.access.audit (Unity Catalog service events).
-- Parameter: :lookback_days (INT), e.g. 30.
SELECT
  event_time,
  user_identity.email                                   AS principal,
  action_name,
  COALESCE(request_params.full_name_arg,
           request_params.table_full_name)              AS table_full_name,
  source_ip_address,
  response.status_code                                  AS status_code
FROM system.access.audit
WHERE service_name = 'unityCatalog'
  AND action_name IN ('getTable', 'generateTemporaryTableCredential')
  AND event_date >= date_sub(current_date(), :lookback_days)
  AND COALESCE(request_params.full_name_arg, request_params.table_full_name) IS NOT NULL
ORDER BY event_time DESC;
