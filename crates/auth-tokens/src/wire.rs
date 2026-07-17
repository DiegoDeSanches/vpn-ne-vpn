#[derive(Clone, PartialEq, ::prost::Message)]
pub(crate) struct SignedTokenEnvelopeV1 {
    #[prost(uint32, tag = "1")]
    pub token_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub claims: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(crate) struct CapabilityClaimsV1 {
    #[prost(uint32, tag = "1")]
    pub token_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub token_id: Vec<u8>,
    #[prost(enumeration = "PlanClassV1", tag = "3")]
    pub plan_class: i32,
    #[prost(enumeration = "GatewayRoleV1", repeated, tag = "4")]
    pub allowed_gateway_roles: Vec<i32>,
    #[prost(enumeration = "RegionSetV1", tag = "5")]
    pub region_set: i32,
    #[prost(enumeration = "DeviceSlotClassV1", tag = "6")]
    pub device_slot_class: i32,
    #[prost(enumeration = "BandwidthClassV1", tag = "7")]
    pub bandwidth_class: i32,
    #[prost(message, optional, tag = "8")]
    pub connection_limits: Option<ConnectionLimitsV1>,
    #[prost(int64, tag = "9")]
    pub not_before: i64,
    #[prost(int64, tag = "10")]
    pub expires_at: i64,
    #[prost(string, tag = "11")]
    pub issuer_key_id: String,
    #[prost(bytes = "vec", optional, tag = "12")]
    pub proof_of_possession_public_key: Option<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub(crate) struct ConnectionLimitsV1 {
    #[prost(uint32, tag = "1")]
    pub max_active_sessions: u32,
    #[prost(uint32, tag = "2")]
    pub max_concurrent_streams: u32,
    #[prost(uint32, tag = "3")]
    pub new_connections_per_minute: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub(crate) enum PlanClassV1 {
    Unspecified = 0,
    Basic = 1,
    Plus = 2,
    Premium = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub(crate) enum GatewayRoleV1 {
    Unspecified = 0,
    Entry = 1,
    Relay = 2,
    Exit = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub(crate) enum RegionSetV1 {
    Unspecified = 0,
    Europe = 1,
    Americas = 2,
    AsiaPacific = 3,
    Global = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub(crate) enum DeviceSlotClassV1 {
    Unspecified = 0,
    Single = 1,
    Personal = 2,
    Family = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub(crate) enum BandwidthClassV1 {
    Unspecified = 0,
    Standard = 1,
    Fast = 2,
    Priority = 3,
}
