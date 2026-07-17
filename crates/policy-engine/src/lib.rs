#![forbid(unsafe_code)]
//! Fail-closed MVP routing policy for OnionRoute.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use onionroute_common_types::contracts::v1::PolicyEngine;
use onionroute_common_types::error::{ErrorCode, ErrorDomain, RetryClass, SafetyImpact, Severity};
use onionroute_common_types::transport::BoxFuture;
use onionroute_common_types::types::{
    AnonymityMode, ApplicationTag, DnsPolicyContext, GatewayHop, GatewayPlan, GatewayRole,
    PolicyAction, PolicyDecision, RouteConstraints, TcpFlowRequest, TcpHost,
    VerifiedGatewayDirectory,
};
use onionroute_common_types::version::{ContractVersion, VersionedContract, CONTRACT_V1};
use onionroute_common_types::{OnionError, OnionResult};

/// Immutable policy configuration.
#[derive(Clone, Debug, Default)]
pub struct MvpPolicyConfig {
    /// Application tags explicitly excluded by a platform split-tunnel adapter.
    ///
    /// client-core never opens a direct socket for this result. If packets from
    /// such an app still enter the TUN, packet-engine rejects the bypass decision.
    pub bypass_applications: HashSet<ApplicationTag>,
}

/// Conservative policy engine for the TCP-only MVP.
pub struct MvpPolicyEngine {
    config: MvpPolicyConfig,
}

impl MvpPolicyEngine {
    /// Creates the MVP policy engine.
    pub fn new(config: MvpPolicyConfig) -> Self {
        Self { config }
    }
}

impl Default for MvpPolicyEngine {
    fn default() -> Self {
        Self::new(MvpPolicyConfig::default())
    }
}

impl VersionedContract for MvpPolicyEngine {
    fn contract_version(&self) -> ContractVersion {
        CONTRACT_V1
    }
}

impl PolicyEngine for MvpPolicyEngine {
    fn evaluate_tcp<'a>(
        &'a self,
        request: &'a TcpFlowRequest,
    ) -> BoxFuture<'a, OnionResult<PolicyDecision>> {
        Box::pin(async move {
            if request.port == 0 || request.port == 25 {
                return Ok(block("mvp.block.smtp-or-invalid-port.v1"));
            }
            if (6881..=6889).contains(&request.port) {
                return Ok(block("mvp.block.bittorrent-default-ports.v1"));
            }
            if forbidden_destination(&request.host) {
                return Ok(block("mvp.block.local-or-private-destination.v1"));
            }
            if request
                .application
                .as_ref()
                .is_some_and(|application| self.config.bypass_applications.contains(application))
            {
                return Ok(PolicyDecision {
                    action: PolicyAction::Bypass,
                    rule_id: "split.platform-exclusion-required.v1".to_owned(),
                });
            }
            Ok(PolicyDecision {
                action: PolicyAction::Tunnel,
                rule_id: "mvp.default.protected-tunnel.v1".to_owned(),
            })
        })
    }

    fn evaluate_dns<'a>(
        &'a self,
        _context: &'a DnsPolicyContext,
    ) -> BoxFuture<'a, OnionResult<PolicyDecision>> {
        Box::pin(async {
            Ok(PolicyDecision {
                action: PolicyAction::Tunnel,
                rule_id: "dns.protected-only.v1".to_owned(),
            })
        })
    }

    fn select_gateway_plan<'a>(
        &'a self,
        directory: &'a VerifiedGatewayDirectory,
        constraints: &'a RouteConstraints,
    ) -> BoxFuture<'a, OnionResult<GatewayPlan>> {
        Box::pin(async move { select_plan(directory, constraints) })
    }
}

fn select_plan(
    directory: &VerifiedGatewayDirectory,
    constraints: &RouteConstraints,
) -> OnionResult<GatewayPlan> {
    let roles: &[GatewayRole] = match constraints.mode {
        AnonymityMode::Standard => &[GatewayRole::Exit],
        AnonymityMode::Enhanced => &[GatewayRole::Entry, GatewayRole::Exit],
        AnonymityMode::Maximum => &[GatewayRole::Entry, GatewayRole::Relay, GatewayRole::Exit],
        AnonymityMode::DirectTor => &[],
    };
    let mut selected_ids = HashSet::new();
    let mut hops = Vec::with_capacity(roles.len());
    for role in roles {
        let descriptor = directory
            .gateways
            .iter()
            .find(|gateway| {
                gateway.roles.contains(role)
                    && !selected_ids.contains(&gateway.gateway_id.0)
                    && constraints.required_features.iter().all(|required| {
                        gateway
                            .capabilities
                            .iter()
                            .any(|capability| capability == required)
                    })
                    && constraints
                        .exit_country
                        .map(|country| *role != GatewayRole::Exit || gateway.country == country)
                        .unwrap_or(true)
            })
            .ok_or_else(gateway_unavailable)?;
        selected_ids.insert(descriptor.gateway_id.0.clone());
        hops.push(GatewayHop {
            gateway_id: descriptor.gateway_id.clone(),
            role: *role,
            onion_endpoint: descriptor.endpoint.clone(),
            tls_spki_sha256: descriptor.tls_spki_sha256,
        });
    }
    Ok(GatewayPlan {
        mode: constraints.mode,
        hops,
    })
}

fn forbidden_destination(host: &TcpHost) -> bool {
    match host {
        TcpHost::Hostname(hostname) => {
            hostname.is_empty()
                || hostname.len() > 253
                || hostname.eq_ignore_ascii_case("localhost")
                || hostname.to_ascii_lowercase().ends_with(".localhost")
                || hostname.to_ascii_lowercase().ends_with(".local")
        }
        TcpHost::Ip(IpAddr::V4(address)) => forbidden_ipv4(*address),
        TcpHost::Ip(IpAddr::V6(_)) => true,
    }
}

fn forbidden_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_unspecified()
        || address.is_multicast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || address == Ipv4Addr::new(100, 100, 100, 200)
        || (octets[0] == 169 && octets[1] == 254)
}

fn block(rule_id: &str) -> PolicyDecision {
    PolicyDecision {
        action: PolicyAction::Block,
        rule_id: rule_id.to_owned(),
    }
}

fn gateway_unavailable() -> OnionError {
    OnionError::new(
        ErrorDomain::Policy,
        ErrorCode::GatewayUnavailable,
        Severity::Error,
        RetryClass::AfterDirectoryRefresh,
        SafetyImpact::Protected,
        "no verified gateway satisfies route policy",
    )
}
