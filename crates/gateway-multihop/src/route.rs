//! Strict Enhanced route selection over an already authenticated directory adapter.

use std::cmp::Ordering;

use crate::{ErrorCode, Result};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GatewayRole {
    Entry,
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceState {
    Active,
    Draining,
    Maintenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LoadBucket {
    Low,
    Medium,
    High,
    Unknown,
    Saturated,
}

/// Public data-plane metadata. `management_identity` is only an opaque failure
/// domain label; no management address or credential is present.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDescriptor {
    pub gateway_id: String,
    pub role: GatewayRole,
    pub country_code: String,
    pub provider_id: String,
    pub autonomous_system: u32,
    pub management_identity: String,
    pub protocol_versions: Vec<ProtocolVersion>,
    pub maintenance: MaintenanceState,
    pub load: LoadBucket,
    pub revoked: bool,
}

#[derive(Clone, Debug)]
pub struct RoutePolicy {
    pub exit_country: String,
    pub required_version: ProtocolVersion,
    pub maximum_load: LoadBucket,
}

impl RoutePolicy {
    pub fn validate(&self) -> Result<()> {
        if self.exit_country.len() != 2
            || !self
                .exit_country
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
            || self.required_version.major == 0
            || self.maximum_load >= LoadBucket::Unknown
        {
            return Err(ErrorCode::InvalidConfiguration.into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecentFailure {
    pub gateway_id: String,
    pub consecutive_failures: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnhancedRoute {
    pub entry: GatewayDescriptor,
    pub exit: GatewayDescriptor,
    pub protocol_version: ProtocolVersion,
}

/// Selects an exit only when every diversity and availability requirement is
/// satisfied. Diversity constraints are hard filters, never score penalties.
pub fn select_enhanced_route(
    entry: &GatewayDescriptor,
    exits: &[GatewayDescriptor],
    policy: &RoutePolicy,
    recent_failures: &[RecentFailure],
) -> Result<EnhancedRoute> {
    policy.validate()?;
    validate_gateway(entry, GatewayRole::Entry, policy.maximum_load)?;
    if !supports(entry, policy.required_version) {
        return Err(ErrorCode::ProtocolIncompatible.into());
    }

    let selected = exits
        .iter()
        .filter(|exit| validate_gateway(exit, GatewayRole::Exit, policy.maximum_load).is_ok())
        .filter(|exit| exit.country_code == policy.exit_country)
        .filter(|exit| supports(exit, policy.required_version))
        .filter(|exit| exit.provider_id != entry.provider_id)
        .filter(|exit| exit.autonomous_system != entry.autonomous_system)
        .filter(|exit| exit.management_identity != entry.management_identity)
        .min_by(|left, right| compare_candidates(left, right, recent_failures))
        .cloned()
        .ok_or(ErrorCode::PolicyDenied)?;

    Ok(EnhancedRoute {
        entry: entry.clone(),
        exit: selected,
        protocol_version: policy.required_version,
    })
}

fn validate_gateway(
    gateway: &GatewayDescriptor,
    role: GatewayRole,
    maximum_load: LoadBucket,
) -> Result<()> {
    if gateway.role != role
        || gateway.gateway_id.is_empty()
        || gateway.provider_id.is_empty()
        || gateway.management_identity.is_empty()
        || gateway.autonomous_system == 0
        || gateway.revoked
        || gateway.maintenance != MaintenanceState::Active
        || gateway.load > maximum_load
    {
        return Err(ErrorCode::PolicyDenied.into());
    }
    Ok(())
}

fn supports(gateway: &GatewayDescriptor, required: ProtocolVersion) -> bool {
    gateway
        .protocol_versions
        .iter()
        .any(|value| *value == required)
}

fn compare_candidates(
    left: &GatewayDescriptor,
    right: &GatewayDescriptor,
    failures: &[RecentFailure],
) -> Ordering {
    candidate_score(left, failures)
        .cmp(&candidate_score(right, failures))
        .then_with(|| left.gateway_id.cmp(&right.gateway_id))
}

fn candidate_score(candidate: &GatewayDescriptor, failures: &[RecentFailure]) -> u32 {
    let load = match candidate.load {
        LoadBucket::Low => 0u32,
        LoadBucket::Medium => 100,
        LoadBucket::High => 300,
        LoadBucket::Unknown => 10_000,
        LoadBucket::Saturated => 100_000,
    };
    let failure = failures
        .iter()
        .find(|item| item.gateway_id == candidate.gateway_id)
        .map(|item| u32::from(item.consecutive_failures.min(8)) * 1_000)
        .unwrap_or(0);
    load.saturating_add(failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(
        id: &str,
        role: GatewayRole,
        provider: &str,
        asn: u32,
        management: &str,
    ) -> GatewayDescriptor {
        GatewayDescriptor {
            gateway_id: id.into(),
            role,
            country_code: "DE".into(),
            provider_id: provider.into(),
            autonomous_system: asn,
            management_identity: management.into(),
            protocol_versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            maintenance: MaintenanceState::Active,
            load: LoadBucket::Low,
            revoked: false,
        }
    }

    #[test]
    fn diversity_is_a_hard_requirement() {
        let entry = gateway("entry", GatewayRole::Entry, "provider-a", 64501, "ops-a");
        let exits = vec![
            gateway(
                "same-provider",
                GatewayRole::Exit,
                "provider-a",
                64502,
                "ops-b",
            ),
            gateway("same-as", GatewayRole::Exit, "provider-b", 64501, "ops-b"),
            gateway(
                "same-management",
                GatewayRole::Exit,
                "provider-b",
                64502,
                "ops-a",
            ),
        ];
        let error = select_enhanced_route(
            &entry,
            &exits,
            &RoutePolicy {
                exit_country: "DE".into(),
                required_version: ProtocolVersion { major: 1, minor: 0 },
                maximum_load: LoadBucket::High,
            },
            &[],
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyDenied);
    }
}
