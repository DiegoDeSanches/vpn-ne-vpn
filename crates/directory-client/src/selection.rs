//! Gateway selection over an already verified directory.

use std::collections::{HashMap, HashSet};

use semver::Version;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::format::{
    AbuseState, AnonymityProfile, CapacityBucket, DirectoryDocument, GatewayRecord, GatewayRole,
    HealthState, LoadBucket, MaintenanceState, SelectedGateway,
};

/// A recent connection failure stored only on the client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalFailure {
    /// Public gateway ID that failed.
    pub gateway_id: String,
    /// Bounded consecutive failure count.
    pub failure_count: u8,
    /// Unix time of the most recent failure.
    pub last_failure_at: i64,
}

/// Inputs for one selection. `session_seed` must be regenerated locally for each route attempt.
#[derive(Clone, Debug)]
pub struct SelectionInput<'a> {
    /// Signed, verified document.
    pub directory: &'a DirectoryDocument,
    /// Optional user-selected exit country.
    pub selected_country: Option<&'a str>,
    /// Requested anonymity profile.
    pub profile: AnonymityProfile,
    /// Local client semantic version.
    pub client_version: &'a str,
    /// Required gateway protocol version.
    pub protocol_version: &'a str,
    /// Required capability names.
    pub required_capabilities: &'a [&'a str],
    /// Recent local connection failures. This data is never uploaded.
    pub recent_failures: &'a [LocalFailure],
    /// Current Unix time.
    pub now_unix: i64,
    /// Ephemeral per-attempt seed; it is not persisted or sent to a service.
    pub session_seed: [u8; 32],
}

/// Fail-closed gateway-selection error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SelectionError {
    /// The local client version is malformed.
    #[error("client version is invalid")]
    InvalidClientVersion,
    /// The selected country is disabled or unavailable for the requested profile.
    #[error("selected country is unavailable")]
    CountryUnavailable,
    /// No gateway set satisfies role and safety constraints.
    #[error("no safe compatible gateway route is available")]
    NoCompatibleRoute,
}

/// Selects a role-correct route while preferring low load and provider/AS diversity.
///
/// Direct Tor returns an empty private-gateway plan. All other profiles fail closed
/// if any required role has no compatible candidate.
pub fn select_gateway_plan(
    input: &SelectionInput<'_>,
) -> Result<Vec<SelectedGateway>, SelectionError> {
    let client_version =
        Version::parse(input.client_version).map_err(|_| SelectionError::InvalidClientVersion)?;
    if input.profile == AnonymityProfile::DirectTor {
        return Ok(Vec::new());
    }
    if let Some(country) = input.selected_country {
        let available = input.directory.countries.iter().any(|configured| {
            configured.country_code == country
                && configured.enabled
                && configured.supported_profiles.contains(&input.profile)
        });
        if !available {
            return Err(SelectionError::CountryUnavailable);
        }
    }

    let requested_roles: &[GatewayRole] = match input.profile {
        AnonymityProfile::Standard => &[GatewayRole::Exit],
        AnonymityProfile::Enhanced => &[GatewayRole::Entry, GatewayRole::Exit],
        AnonymityProfile::Maximum => &[GatewayRole::Entry, GatewayRole::Relay, GatewayRole::Exit],
        AnonymityProfile::DirectTor => &[],
    };
    let selection_order: &[GatewayRole] = match input.profile {
        AnonymityProfile::Standard => &[GatewayRole::Exit],
        AnonymityProfile::Enhanced => &[GatewayRole::Exit, GatewayRole::Entry],
        AnonymityProfile::Maximum => &[GatewayRole::Exit, GatewayRole::Entry, GatewayRole::Relay],
        AnonymityProfile::DirectTor => &[],
    };
    let active_revocations: HashSet<&str> = input
        .directory
        .revocations
        .iter()
        .filter(|revocation| {
            revocation.revoked_at <= input.now_unix
                && revocation
                    .expires_at
                    .map_or(true, |expires| expires > input.now_unix)
        })
        .map(|revocation| revocation.gateway_id.as_str())
        .collect();
    let failures: HashMap<&str, &LocalFailure> = input
        .recent_failures
        .iter()
        .map(|failure| (failure.gateway_id.as_str(), failure))
        .collect();

    let mut selected: Vec<&GatewayRecord> = Vec::with_capacity(requested_roles.len());
    for role in selection_order {
        let candidate = input
            .directory
            .gateways
            .iter()
            .filter(|gateway| {
                is_eligible(gateway, *role, input, &client_version, &active_revocations)
                    && !selected
                        .iter()
                        .any(|existing| existing.gateway_id == gateway.gateway_id)
            })
            .min_by_key(|gateway| score(gateway, *role, &selected, &failures, input))
            .ok_or(SelectionError::NoCompatibleRoute)?;
        selected.push(candidate);
    }

    requested_roles
        .iter()
        .map(|role| {
            selected
                .iter()
                .find(|gateway| gateway.role == *role)
                .map(|gateway| SelectedGateway {
                    role: *role,
                    gateway: (*gateway).clone(),
                })
                .ok_or(SelectionError::NoCompatibleRoute)
        })
        .collect()
}

fn is_eligible(
    gateway: &GatewayRecord,
    role: GatewayRole,
    input: &SelectionInput<'_>,
    client_version: &Version,
    active_revocations: &HashSet<&str>,
) -> bool {
    let minimum_client = match Version::parse(&gateway.minimum_client_version) {
        Ok(version) => version,
        Err(_) => return false,
    };
    gateway.role == role
        && !active_revocations.contains(gateway.gateway_id.as_str())
        && gateway.valid_from <= input.now_unix
        && gateway.valid_until > input.now_unix
        && matches!(gateway.health, HealthState::Healthy | HealthState::Degraded)
        && gateway.maintenance_state == MaintenanceState::Active
        && gateway.abuse_state != AbuseState::Blocked
        && gateway.current_load_bucket != LoadBucket::Saturated
        && gateway
            .supported_protocol_versions
            .iter()
            .any(|version| version == input.protocol_version)
        && input.required_capabilities.iter().all(|required| {
            gateway
                .capabilities
                .iter()
                .any(|capability| capability == required)
        })
        && client_version >= &minimum_client
        && input.selected_country.map_or(true, |country| {
            role != GatewayRole::Exit || gateway.country_code == country
        })
}

fn score(
    gateway: &GatewayRecord,
    role: GatewayRole,
    selected: &[&GatewayRecord],
    failures: &HashMap<&str, &LocalFailure>,
    input: &SelectionInput<'_>,
) -> u64 {
    let load = match gateway.current_load_bucket {
        LoadBucket::Low => 0,
        LoadBucket::Medium => 100,
        LoadBucket::High => 300,
        LoadBucket::Unknown => 500,
        LoadBucket::Saturated => 100_000,
    };
    let health = match gateway.health {
        HealthState::Healthy => 0,
        HealthState::Degraded => 400,
        HealthState::Unhealthy | HealthState::Unknown => 100_000,
    };
    let capacity = match gateway.capacity_bucket {
        CapacityBucket::Large => 0,
        CapacityBucket::Medium => 20,
        CapacityBucket::Small => 40,
    };
    let provider_collision = selected
        .iter()
        .filter(|other| other.provider_group == gateway.provider_group)
        .count() as u64
        * 10_000;
    let as_collision = selected
        .iter()
        .filter(|other| other.autonomous_system == gateway.autonomous_system)
        .count() as u64
        * 8_000;
    let recent_failure = failures
        .get(gateway.gateway_id.as_str())
        .filter(|failure| input.now_unix.saturating_sub(failure.last_failure_at) <= 30 * 60)
        .map(|failure| u64::from(failure.failure_count.min(8)) * 750)
        .unwrap_or(0);
    load + health
        + capacity
        + provider_collision
        + as_collision
        + recent_failure
        + tie_breaker(gateway, role, &input.session_seed)
}

fn tie_breaker(gateway: &GatewayRecord, role: GatewayRole, session_seed: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(session_seed);
    hasher.update(gateway.gateway_id.as_bytes());
    hasher.update([match role {
        GatewayRole::Entry => 1,
        GatewayRole::Relay => 2,
        GatewayRole::Exit => 3,
    }]);
    let digest = hasher.finalize();
    u64::from(u16::from_be_bytes([digest[0], digest[1]])) % 17
}
