-- Access to tables that carry row filters or column masks (the PII tables in the
-- example policy). Edit the list to match your policy files.
-- Parameter: :lookback_days (INT).
WITH pii_tables AS (
  SELECT explode(array(
    'finance.payments.transactions',
    'finance.crm.customers',
    'hr.core.employees'
  )) AS table_full_name
)
SELECT
  date_trunc('DAY', a.event_time)        AS day,
  p.table_full_name,
  a.user_identity.email                  AS principal,
  count(*)                               AS access_events
FROM system.access.audit a
JOIN pii_tables p
  ON COALESCE(a.request_params.full_name_arg, a.request_params.table_full_name) = p.table_full_name
WHERE a.service_name = 'unityCatalog'
  AND a.action_name IN ('getTable', 'generateTemporaryTableCredential')
  AND a.event_date >= date_sub(current_date(), :lookback_days)
GROUP BY ALL
ORDER BY day DESC, access_events DESC;
