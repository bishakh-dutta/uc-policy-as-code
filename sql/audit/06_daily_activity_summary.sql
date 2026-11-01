-- Daily counters for the dashboard header: table reads, grant changes, denied requests,
-- and distinct principals active in Unity Catalog.
-- Parameter: :lookback_days (INT).
SELECT
  event_date,
  count_if(action_name IN ('getTable', 'generateTemporaryTableCredential')) AS table_access_events,
  count_if(action_name = 'updatePermissions')                               AS grant_changes,
  count_if(response.status_code IN (401, 403))                             AS denied_requests,
  count(DISTINCT user_identity.email)                                       AS active_principals
FROM system.access.audit
WHERE service_name = 'unityCatalog'
  AND event_date >= date_sub(current_date(), :lookback_days)
GROUP BY event_date
ORDER BY event_date;
