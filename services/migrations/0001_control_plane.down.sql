BEGIN;
DROP FUNCTION IF EXISTS create_directory_draft(bigint, text);
DROP VIEW IF EXISTS directory_gateway_projection;
DROP TABLE IF EXISTS feature_flags;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS client_version_rules;
DROP TABLE IF EXISTS revocations;
DROP TABLE IF EXISTS directory_versions;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS health_samples;
DROP TABLE IF EXISTS gateway_roles;
DROP TABLE IF EXISTS gateways;
DROP TABLE IF EXISTS countries;
COMMIT;

