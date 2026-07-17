//! Bounded PostgreSQL-to-public-document builder for the signing pipeline.

use onionroute_directory_client::{
    ClientVersionRule, CountryConfig, DirectoryDocument, FeatureFlag, GatewayRecord,
    GatewayRevocation, MAX_GATEWAYS,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::PgPool;
use thiserror::Error;

const MAX_COUNTRIES: usize = 256;
const MAX_REVOCATIONS: usize = 8_192;
const MAX_VERSION_RULES: usize = 128;
const MAX_FEATURE_FLAGS: usize = 512;

/// Directory draft construction failure without query or infrastructure details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DirectoryBuildError {
    /// No unsigned draft is awaiting publication.
    #[error("no directory draft is awaiting publication")]
    NoDraft,
    /// A database operation failed.
    #[error("directory source query failed")]
    Persistence,
    /// Source data cannot fit or decode into the public allow-listed contract.
    #[error("directory source violates public contract bounds")]
    InvalidSource,
}

/// Reads only explicit public projections and signed policy tables.
#[derive(Clone)]
pub struct PgDirectoryBuilder {
    pool: PgPool,
}

impl PgDirectoryBuilder {
    /// Creates a builder using a read-only directory-publisher pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Builds the oldest pending monotonic draft using `now_unix` as issue time.
    ///
    /// Concurrent workers may build the same draft, but only one signing-service
    /// conditional publication can transition it from `draft` to `published`.
    pub async fn build_next_draft(
        &self,
        now_unix: i64,
    ) -> Result<DirectoryDocument, DirectoryBuildError> {
        let (raw_version, validity_seconds) = sqlx::query_as::<_, (i64, i32)>(
            "SELECT version, requested_validity_seconds FROM directory_versions \
             WHERE publication_state='draft' ORDER BY version LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| DirectoryBuildError::Persistence)?
        .ok_or(DirectoryBuildError::NoDraft)?;
        let version = u64::try_from(raw_version).map_err(|_| DirectoryBuildError::InvalidSource)?;
        let validity = i64::from(validity_seconds);
        if !(300..=21_600).contains(&validity) {
            return Err(DirectoryBuildError::InvalidSource);
        }
        let expires_at = now_unix
            .checked_add(validity)
            .ok_or(DirectoryBuildError::InvalidSource)?;

        let gateways = decode_rows::<GatewayRecord>(
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object( \
                   'gateway_id', gateway_id, 'country_code', country_code, \
                   'city_label', city_label, 'region', region, 'role', role, \
                   'provider_group', provider_group, 'autonomous_system', autonomous_system, \
                   'onion_address', onion_address, 'capabilities', capabilities, \
                   'supported_protocol_versions', supported_protocol_versions, \
                   'minimum_client_version', minimum_client_version, \
                   'current_load_bucket', current_load_bucket, 'capacity_bucket', capacity_bucket, \
                   'health', health, 'maintenance_state', maintenance_state, \
                   'abuse_state', abuse_state, 'public_signing_key', public_signing_key, \
                   'valid_from', EXTRACT(EPOCH FROM valid_from)::bigint, \
                   'valid_until', EXTRACT(EPOCH FROM valid_until)::bigint) \
                 FROM directory_gateway_projection ORDER BY gateway_id, role",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|_| DirectoryBuildError::Persistence)?,
            MAX_GATEWAYS,
        )?;
        let countries = decode_rows::<CountryConfig>(
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object( \
                   'country_code', country_code, 'display_name_key', display_name_key, \
                   'enabled', enabled, 'supported_profiles', supported_profiles) \
                 FROM countries ORDER BY country_code",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|_| DirectoryBuildError::Persistence)?,
            MAX_COUNTRIES,
        )?;
        let revocations = decode_rows::<GatewayRevocation>(
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object( \
                   'gateway_id', subject_id, 'reason_code', reason_code, \
                   'revoked_at', EXTRACT(EPOCH FROM revoked_at)::bigint, \
                   'expires_at', CASE WHEN expires_at IS NULL THEN NULL \
                                      ELSE EXTRACT(EPOCH FROM expires_at)::bigint END) \
                 FROM revocations WHERE subject_type='gateway' AND revoked_at <= now() \
                 AND (expires_at IS NULL OR expires_at > now()) ORDER BY subject_id",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|_| DirectoryBuildError::Persistence)?,
            MAX_REVOCATIONS,
        )?;
        let client_version_rules = decode_rows::<ClientVersionRule>(
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object( \
                   'platform', platform, 'channel', channel, \
                   'minimum_supported_version', minimum_supported_version, \
                   'recommended_version', recommended_version, 'latest_version', latest_version) \
                 FROM client_version_rules ORDER BY platform, channel",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|_| DirectoryBuildError::Persistence)?,
            MAX_VERSION_RULES,
        )?;
        let feature_flags = decode_rows::<FeatureFlag>(
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object( \
                   'key', flag_key, 'enabled', enabled, 'platform', platform, \
                   'minimum_client_version', minimum_client_version, \
                   'maximum_client_version', maximum_client_version) \
                 FROM feature_flags ORDER BY flag_key",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|_| DirectoryBuildError::Persistence)?,
            MAX_FEATURE_FLAGS,
        )?;

        Ok(DirectoryDocument {
            format_version: "2.0".to_owned(),
            version,
            issued_at: now_unix,
            expires_at,
            gateways,
            countries,
            revocations,
            client_version_rules,
            feature_flags,
        })
    }
}

fn decode_rows<T: DeserializeOwned>(
    rows: Vec<Value>,
    maximum: usize,
) -> Result<Vec<T>, DirectoryBuildError> {
    if rows.len() > maximum {
        return Err(DirectoryBuildError::InvalidSource);
    }
    rows.into_iter()
        .map(|row| serde_json::from_value(row).map_err(|_| DirectoryBuildError::InvalidSource))
        .collect()
}
