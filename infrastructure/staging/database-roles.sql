\set ON_ERROR_STOP on
\getenv directory_password OR_DIRECTORY_DB_PASSWORD
\getenv health_password OR_HEALTH_DB_PASSWORD
\getenv admin_password OR_ADMIN_DB_PASSWORD
\getenv revocation_password OR_REVOCATION_DB_PASSWORD

BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onionroute_directory') THEN
        CREATE ROLE onionroute_directory LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onionroute_health') THEN
        CREATE ROLE onionroute_health LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onionroute_admin') THEN
        CREATE ROLE onionroute_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'onionroute_revocation') THEN
        CREATE ROLE onionroute_revocation LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE onionroute_directory PASSWORD :'directory_password';
ALTER ROLE onionroute_health PASSWORD :'health_password';
ALTER ROLE onionroute_admin PASSWORD :'admin_password';
ALTER ROLE onionroute_revocation PASSWORD :'revocation_password';

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

GRANT CONNECT ON DATABASE onionroute TO
    onionroute_directory,
    onionroute_health,
    onionroute_admin,
    onionroute_revocation;
GRANT USAGE ON SCHEMA public TO
    onionroute_directory,
    onionroute_health,
    onionroute_admin,
    onionroute_revocation;

GRANT SELECT ON directory_versions TO onionroute_directory;

GRANT SELECT, INSERT ON health_samples TO onionroute_health;
GRANT SELECT, UPDATE (health, current_load_bucket, updated_at) ON gateways
    TO onionroute_health;

GRANT SELECT, INSERT, UPDATE ON
    countries,
    gateways,
    gateway_roles,
    feature_flags,
    client_version_rules,
    revocations,
    incidents,
    directory_versions
    TO onionroute_admin;
GRANT USAGE, SELECT ON SEQUENCE
    revocations_revocation_id_seq,
    incidents_incident_id_seq
    TO onionroute_admin;
GRANT EXECUTE ON FUNCTION create_directory_draft(bigint, text)
    TO onionroute_admin;

GRANT SELECT, INSERT ON revocations TO onionroute_revocation;
GRANT USAGE, SELECT ON SEQUENCE revocations_revocation_id_seq
    TO onionroute_revocation;

COMMIT;
