BEGIN;

CREATE TABLE countries (
    country_code text PRIMARY KEY CHECK (country_code ~ '^[A-Z]{2}$'),
    display_name_key text NOT NULL CHECK (length(display_name_key) BETWEEN 1 AND 96),
    enabled boolean NOT NULL DEFAULT false,
    supported_profiles text[] NOT NULL DEFAULT '{}',
    updated_by text NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (supported_profiles <@ ARRAY['standard','enhanced','maximum','direct_tor']::text[]),
    CHECK (cardinality(supported_profiles) > 0)
);

CREATE TABLE gateways (
    gateway_id text PRIMARY KEY CHECK (gateway_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    country_code text NOT NULL REFERENCES countries(country_code),
    city_label text NOT NULL CHECK (length(city_label) BETWEEN 1 AND 64),
    region text NOT NULL CHECK (region ~ '^[A-Za-z0-9._:-]{1,64}$'),
    provider_group text NOT NULL CHECK (provider_group ~ '^[A-Za-z0-9._:-]{1,64}$'),
    autonomous_system bigint NOT NULL CHECK (autonomous_system BETWEEN 1 AND 4294967295),
    onion_address text NOT NULL UNIQUE CHECK (onion_address ~ '^[a-z2-7]{56}\.onion$'),
    capabilities text[] NOT NULL CHECK (cardinality(capabilities) <= 32),
    supported_protocol_versions text[] NOT NULL CHECK (
        cardinality(supported_protocol_versions) BETWEEN 1 AND 16
    ),
    minimum_client_version text NOT NULL CHECK (length(minimum_client_version) BETWEEN 1 AND 32),
    current_load_bucket text NOT NULL DEFAULT 'unknown' CHECK (
        current_load_bucket IN ('unknown','low','medium','high','saturated')
    ),
    capacity_bucket text NOT NULL CHECK (capacity_bucket IN ('small','medium','large')),
    health text NOT NULL DEFAULT 'unknown' CHECK (
        health IN ('unknown','healthy','degraded','unhealthy')
    ),
    maintenance_state text NOT NULL DEFAULT 'maintenance' CHECK (
        maintenance_state IN ('active','draining','maintenance')
    ),
    abuse_state text NOT NULL DEFAULT 'active' CHECK (
        abuse_state IN ('active','restricted','blocked')
    ),
    public_signing_key text NOT NULL CHECK (
        public_signing_key ~ '^[A-Za-z0-9_-]{43}$'
    ),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    updated_by text NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (valid_until > valid_from)
);

COMMENT ON TABLE gateways IS
'Public gateway metadata plus internal audit timestamps. Management IPs, cloud accounts, exact capacity, and topology are forbidden.';

CREATE TABLE gateway_roles (
    gateway_id text PRIMARY KEY REFERENCES gateways(gateway_id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('entry','relay','exit')),
    UNIQUE (gateway_id, role)
);

CREATE TABLE health_samples (
    gateway_id text NOT NULL REFERENCES gateways(gateway_id) ON DELETE CASCADE,
    sample_sequence bigint NOT NULL CHECK (sample_sequence > 0),
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    health text NOT NULL CHECK (health IN ('unknown','healthy','degraded','unhealthy')),
    load_bucket text NOT NULL CHECK (load_bucket IN ('unknown','low','medium','high','saturated')),
    capacity_bucket text NOT NULL CHECK (capacity_bucket IN ('small','medium','large')),
    checks jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(checks) = 'array' AND octet_length(checks::text) <= 8192
    ),
    PRIMARY KEY (gateway_id, sample_sequence),
    CHECK (observed_at <= received_at + interval '5 minutes')
);

COMMENT ON TABLE health_samples IS
'Privacy-minimized gateway samples. Source IP, user IP, destination, flow, account, and device identifiers are prohibited.';
CREATE INDEX health_samples_recent_idx ON health_samples (gateway_id, observed_at DESC);

CREATE TABLE signing_keys (
    key_id text PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    key_role text NOT NULL CHECK (key_role IN ('offline_root','online_intermediate')),
    algorithm text NOT NULL CHECK (algorithm = 'ed25519'),
    public_key text NOT NULL CHECK (public_key ~ '^[A-Za-z0-9_-]{43}$'),
    parent_key_id text REFERENCES signing_keys(key_id),
    key_backend_reference text,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('staged','active','retired','revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (valid_until > valid_from),
    CHECK (
        (key_role = 'offline_root' AND parent_key_id IS NULL) OR
        (key_role = 'online_intermediate' AND parent_key_id IS NOT NULL)
    )
);

COMMENT ON COLUMN signing_keys.key_backend_reference IS
'Internal Vault/HSM object reference only. Private key bytes must never be stored in PostgreSQL.';

CREATE TABLE directory_versions (
    version bigint PRIMARY KEY CHECK (version > 0),
    trust_bundle_version bigint CHECK (trust_bundle_version > 0),
    signing_key_id text REFERENCES signing_keys(key_id),
    issued_at timestamptz,
    expires_at timestamptz,
    unsigned_document jsonb,
    signed_envelope bytea,
    publication_state text NOT NULL CHECK (
        publication_state IN ('draft','published','superseded','rejected')
    ),
    requested_validity_seconds integer NOT NULL CHECK (requested_validity_seconds BETWEEN 300 AND 21600),
    requested_by text NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    CHECK (expires_at IS NULL OR issued_at IS NOT NULL),
    CHECK (expires_at IS NULL OR expires_at > issued_at),
    CHECK (expires_at IS NULL OR expires_at - issued_at <= interval '6 hours'),
    CHECK (signed_envelope IS NULL OR octet_length(signed_envelope) <= 2097152),
    CHECK (
        publication_state <> 'published' OR
        (signing_key_id IS NOT NULL AND issued_at IS NOT NULL AND expires_at IS NOT NULL
         AND unsigned_document IS NOT NULL AND signed_envelope IS NOT NULL AND published_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX directory_one_current_published_idx
    ON directory_versions (publication_state)
    WHERE publication_state = 'published';

CREATE TABLE revocations (
    revocation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_type text NOT NULL CHECK (subject_type IN ('gateway','signing_key')),
    subject_id text NOT NULL CHECK (subject_id ~ '^[A-Za-z0-9._:-]{1,64}$'),
    reason_code text NOT NULL CHECK (reason_code ~ '^[A-Za-z0-9._:-]{1,64}$'),
    revoked_at timestamptz NOT NULL,
    expires_at timestamptz,
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at IS NULL OR expires_at > revoked_at),
    UNIQUE (subject_type, subject_id, revoked_at)
);
CREATE INDEX revocations_active_idx ON revocations (subject_type, subject_id, revoked_at, expires_at);

CREATE TABLE client_version_rules (
    platform text NOT NULL CHECK (platform IN ('windows','macos','linux','android','ios')),
    channel text NOT NULL CHECK (channel IN ('stable','beta')),
    minimum_supported_version text NOT NULL CHECK (length(minimum_supported_version) BETWEEN 1 AND 32),
    recommended_version text NOT NULL CHECK (length(recommended_version) BETWEEN 1 AND 32),
    latest_version text NOT NULL CHECK (length(latest_version) BETWEEN 1 AND 32),
    updated_by text NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (platform, channel)
);

CREATE TABLE incidents (
    incident_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    severity text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    summary text NOT NULL CHECK (length(summary) BETWEEN 1 AND 512),
    gateway_id text REFERENCES gateways(gateway_id),
    status text NOT NULL CHECK (status IN ('open','mitigated','closed')),
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE incidents IS
'Operational metadata only. Site history, traffic contents, destinations, user IPs, and account IDs are forbidden.';

CREATE TABLE feature_flags (
    flag_key text PRIMARY KEY CHECK (flag_key ~ '^[A-Za-z0-9._:-]{1,96}$'),
    enabled boolean NOT NULL DEFAULT false,
    platform text CHECK (platform IN ('windows','macos','linux','android','ios')),
    minimum_client_version text CHECK (length(minimum_client_version) BETWEEN 1 AND 32),
    maximum_client_version text CHECK (length(maximum_client_version) BETWEEN 1 AND 32),
    updated_by text NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- The directory publisher reads this allow-listed projection. Internal audit and
-- infrastructure fields cannot accidentally enter a serialized public record.
CREATE VIEW directory_gateway_projection AS
SELECT
    g.gateway_id,
    g.country_code,
    g.city_label,
    g.region,
    r.role,
    g.provider_group,
    g.autonomous_system,
    g.onion_address,
    g.capabilities,
    g.supported_protocol_versions,
    g.minimum_client_version,
    g.current_load_bucket,
    g.capacity_bucket,
    g.health,
    g.maintenance_state,
    g.abuse_state,
    g.public_signing_key,
    g.valid_from,
    g.valid_until
FROM gateways g
JOIN gateway_roles r USING (gateway_id);

CREATE OR REPLACE FUNCTION create_directory_draft(validity_seconds bigint, actor text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
DECLARE
    next_version bigint;
BEGIN
    IF validity_seconds < 300 OR validity_seconds > 21600 THEN
        RAISE EXCEPTION 'directory validity outside policy';
    END IF;
    IF actor IS NULL OR length(actor) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'invalid actor';
    END IF;
    PERFORM pg_advisory_xact_lock(73482901);
    SELECT COALESCE(MAX(version), 0) + 1 INTO next_version FROM directory_versions;
    INSERT INTO directory_versions (
        version, publication_state, requested_validity_seconds, requested_by
    )
    VALUES (next_version, 'draft', validity_seconds::integer, actor);
    RETURN next_version;
END;
$$;

COMMIT;
