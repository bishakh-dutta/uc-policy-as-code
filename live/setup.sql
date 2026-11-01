-- Sample data for a live test of ucpolicy (Databricks Free Edition or any
-- Unity Catalog workspace). Idempotent: safe to run more than once.
-- Run it in the SQL editor, or let the integration test run it for you.
--
-- Everything lives in its own catalog, uc_policy_demo, so the demo policy never
-- touches the grants on your real catalogs (e.g. Free Edition's `workspace`).

CREATE CATALOG IF NOT EXISTS uc_policy_demo
  COMMENT 'Sandbox for uc-policy-as-code live tests. Safe to drop.';

CREATE SCHEMA IF NOT EXISTS uc_policy_demo.sales;
CREATE SCHEMA IF NOT EXISTS uc_policy_demo.governance
  COMMENT 'Row filter and column mask functions managed by ucpolicy.';

-- Synthetic customer data: the card numbers are public test numbers, the
-- e-mail addresses use the reserved example.com domain.
CREATE TABLE IF NOT EXISTS uc_policy_demo.sales.customers (
  customer_id INT,
  name        STRING,
  email       STRING,
  card_number STRING,
  region      STRING
);

-- Re-seed only when empty, so this never fights an applied row filter or mask.
INSERT INTO uc_policy_demo.sales.customers
SELECT * FROM VALUES
  (1, 'Asha',   'asha@example.com',   '4111111111111111', 'IN'),
  (2, 'Rohan',  'rohan@example.com',  '5500000000000004', 'IN'),
  (3, 'Lena',   'lena@example.com',   '4012888888881881', 'DE'),
  (4, 'Marta',  'marta@example.com',  '378282246310005',  'NL')
  AS v(customer_id, name, email, card_number, region)
WHERE NOT EXISTS (SELECT 1 FROM uc_policy_demo.sales.customers);
