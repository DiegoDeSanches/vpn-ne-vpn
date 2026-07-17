use crate::{TokenError, TOKEN_BUCKET_SECONDS, TOKEN_TTL_SECONDS};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum PlanClass {
    Basic = 1,
    Plus = 2,
    Premium = 3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum GatewayRole {
    Entry = 1,
    Relay = 2,
    Exit = 3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum RegionSet {
    Europe = 1,
    Americas = 2,
    AsiaPacific = 3,
    Global = 4,
}

impl RegionSet {
    pub fn allows(self, gateway_region: Self) -> bool {
        self == Self::Global || self == gateway_region
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum DeviceSlotClass {
    Single = 1,
    Personal = 2,
    Family = 3,
}

impl DeviceSlotClass {
    pub fn slot_limit(self) -> usize {
        match self {
            Self::Single => 1,
            Self::Personal => 3,
            Self::Family => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i32)]
pub enum BandwidthClass {
    Standard = 1,
    Fast = 2,
    Priority = 3,
}

/// Values are deliberately selected from only three public profiles. The
/// verifier rejects arbitrary combinations so per-account limits cannot become
/// a high-cardinality fingerprint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionLimits {
    pub max_active_sessions: u16,
    pub max_concurrent_streams: u16,
    pub new_connections_per_minute: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityPolicy {
    pub plan_class: PlanClass,
    pub allowed_gateway_roles: Vec<GatewayRole>,
    pub region_set: RegionSet,
    pub device_slot_class: DeviceSlotClass,
    pub bandwidth_class: BandwidthClass,
    pub connection_limits: ConnectionLimits,
}

impl CapabilityPolicy {
    /// Builds a role-scoped allowlisted profile. A token is valid at exactly one
    /// hop so colluding entry/exit gateways cannot join a route by token ID.
    pub fn canonical(
        plan_class: PlanClass,
        region_set: RegionSet,
        gateway_role: GatewayRole,
    ) -> Result<Self, TokenError> {
        let (permitted_roles, device_slot_class, bandwidth_class, connection_limits) =
            match plan_class {
                PlanClass::Basic => (
                    &[GatewayRole::Exit][..],
                    DeviceSlotClass::Single,
                    BandwidthClass::Standard,
                    ConnectionLimits {
                        max_active_sessions: 2,
                        max_concurrent_streams: 64,
                        new_connections_per_minute: 120,
                    },
                ),
                PlanClass::Plus => (
                    &[GatewayRole::Entry, GatewayRole::Exit][..],
                    DeviceSlotClass::Personal,
                    BandwidthClass::Fast,
                    ConnectionLimits {
                        max_active_sessions: 4,
                        max_concurrent_streams: 128,
                        new_connections_per_minute: 240,
                    },
                ),
                PlanClass::Premium => (
                    &[GatewayRole::Entry, GatewayRole::Relay, GatewayRole::Exit][..],
                    DeviceSlotClass::Family,
                    BandwidthClass::Priority,
                    ConnectionLimits {
                        max_active_sessions: 6,
                        max_concurrent_streams: 256,
                        new_connections_per_minute: 480,
                    },
                ),
            };

        if !permitted_roles.contains(&gateway_role) {
            return Err(TokenError::RoleNotAllowed);
        }

        Ok(Self {
            plan_class,
            allowed_gateway_roles: vec![gateway_role],
            region_set,
            device_slot_class,
            bandwidth_class,
            connection_limits,
        })
    }

    pub fn validate_canonical(&self) -> Result<(), TokenError> {
        let role = self
            .allowed_gateway_roles
            .first()
            .copied()
            .ok_or(TokenError::NonCanonicalPolicy)?;
        let expected = Self::canonical(self.plan_class, self.region_set, role)
            .map_err(|_| TokenError::NonCanonicalPolicy)?;
        if *self == expected {
            Ok(())
        } else {
            Err(TokenError::NonCanonicalPolicy)
        }
    }

    pub fn role_allowed(&self, role: GatewayRole) -> bool {
        self.allowed_gateway_roles.binary_search(&role).is_ok()
    }

    pub(crate) fn validate_window(not_before: i64, expires_at: i64) -> Result<(), TokenError> {
        let duration = expires_at
            .checked_sub(not_before)
            .ok_or(TokenError::InvalidTimeWindow)?;
        if not_before < 0 || not_before % TOKEN_BUCKET_SECONDS != 0 || duration != TOKEN_TTL_SECONDS
        {
            return Err(TokenError::InvalidTimeWindow);
        }
        Ok(())
    }
}
