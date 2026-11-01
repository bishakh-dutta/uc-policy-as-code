-- Grant changes NOT made by the CI/CD service principal, i.e. changes that bypassed
-- pull-request review. Each row is a likely source of drift reported by `ucpolicy drift`.
-- Parameters: :lookback_days (INT), :pipeline_principal (STRING, the service
-- principal's application ID as it appears in user_identity.email).
SELECT
  event_time,
  user_identity.email                    AS changed_by,
  request_params.securable_type          AS securable_type,
  request_params.securable_full_name     AS securable,
  request_params.changes                 AS changes
FROM system.access.audit
WHERE service_name = 'unityCatalog'
  AND action_name = 'updatePermissions'
  AND response.status_code = 200
  AND user_identity.email <> :pipeline_principal
  AND event_date >= date_sub(current_date(), :lookback_days)
ORDER BY event_time DESC;
