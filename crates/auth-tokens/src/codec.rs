use prost::Message;

use crate::wire::{
    BandwidthClassV1, CapabilityClaimsV1, ConnectionLimitsV1, DeviceSlotClassV1, GatewayRoleV1,
    PlanClassV1, RegionSetV1, SignedTokenEnvelopeV1,
};
use crate::{
    BandwidthClass, CapabilityClaims, CapabilityPolicy, ConnectionLimits, DeviceSlotClass,
    GatewayRole, PlanClass, RegionSet, TokenError, TokenId, MAX_TOKEN_BYTES, SIGNATURE_LENGTH,
    TOKEN_ID_LENGTH, TOKEN_VERSION_V1,
};

pub(crate) struct DecodedToken {
    pub claims: CapabilityClaims,
    pub claims_bytes: Vec<u8>,
    pub signature: [u8; SIGNATURE_LENGTH],
}

pub(crate) fn encode_token(
    claims: &CapabilityClaims,
    signature: [u8; SIGNATURE_LENGTH],
) -> Result<Vec<u8>, TokenError> {
    claims.validate_shape()?;
    let claims_bytes = claims_to_wire(claims).encode_to_vec();
    let envelope = SignedTokenEnvelopeV1 {
        token_version: TOKEN_VERSION_V1.into(),
        claims: claims_bytes,
        signature: signature.to_vec(),
    };
    let encoded = envelope.encode_to_vec();
    if encoded.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::InputTooLarge);
    }
    Ok(encoded)
}

pub(crate) fn claims_signing_bytes(claims: &CapabilityClaims) -> Result<Vec<u8>, TokenError> {
    claims.validate_shape()?;
    Ok(claims_to_wire(claims).encode_to_vec())
}

pub(crate) fn decode_token(encoded: &[u8]) -> Result<DecodedToken, TokenError> {
    if encoded.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::InputTooLarge);
    }
    let envelope =
        SignedTokenEnvelopeV1::decode(encoded).map_err(|_| TokenError::InvalidEncoding)?;
    if envelope.token_version != u32::from(TOKEN_VERSION_V1) {
        return Err(TokenError::UnsupportedVersion);
    }
    // Reject duplicate fields, unknown fields and other protobuf malleability.
    if envelope.encode_to_vec() != encoded {
        return Err(TokenError::InvalidEncoding);
    }
    if envelope.claims.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::InputTooLarge);
    }

    let wire_claims = CapabilityClaimsV1::decode(envelope.claims.as_slice())
        .map_err(|_| TokenError::InvalidEncoding)?;
    if wire_claims.encode_to_vec() != envelope.claims {
        return Err(TokenError::InvalidEncoding);
    }
    let claims = claims_from_wire(wire_claims)?;
    claims.validate_shape()?;
    let signature: [u8; SIGNATURE_LENGTH] = envelope
        .signature
        .try_into()
        .map_err(|_| TokenError::InvalidEncoding)?;
    Ok(DecodedToken {
        claims,
        claims_bytes: envelope.claims,
        signature,
    })
}

fn claims_to_wire(claims: &CapabilityClaims) -> CapabilityClaimsV1 {
    CapabilityClaimsV1 {
        token_version: claims.token_version.into(),
        token_id: claims.token_id.as_bytes().to_vec(),
        plan_class: plan_to_wire(claims.policy.plan_class) as i32,
        allowed_gateway_roles: claims
            .policy
            .allowed_gateway_roles
            .iter()
            .copied()
            .map(|role| role_to_wire(role) as i32)
            .collect(),
        region_set: region_to_wire(claims.policy.region_set) as i32,
        device_slot_class: device_to_wire(claims.policy.device_slot_class) as i32,
        bandwidth_class: bandwidth_to_wire(claims.policy.bandwidth_class) as i32,
        connection_limits: Some(ConnectionLimitsV1 {
            max_active_sessions: claims.policy.connection_limits.max_active_sessions.into(),
            max_concurrent_streams: claims
                .policy
                .connection_limits
                .max_concurrent_streams
                .into(),
            new_connections_per_minute: claims
                .policy
                .connection_limits
                .new_connections_per_minute
                .into(),
        }),
        not_before: claims.not_before,
        expires_at: claims.expires_at,
        issuer_key_id: claims.issuer_key_id.clone(),
        proof_of_possession_public_key: claims
            .proof_of_possession_public_key
            .map(|key| key.to_vec()),
    }
}

fn claims_from_wire(claims: CapabilityClaimsV1) -> Result<CapabilityClaims, TokenError> {
    let token_version =
        u16::try_from(claims.token_version).map_err(|_| TokenError::UnsupportedVersion)?;
    let token_id: [u8; TOKEN_ID_LENGTH] = claims
        .token_id
        .try_into()
        .map_err(|_| TokenError::InvalidEncoding)?;
    let roles = claims
        .allowed_gateway_roles
        .into_iter()
        .map(role_from_wire)
        .collect::<Result<Vec<_>, _>>()?;
    let limits = claims
        .connection_limits
        .ok_or(TokenError::InvalidEncoding)?;
    let max_active_sessions =
        u16::try_from(limits.max_active_sessions).map_err(|_| TokenError::InvalidEncoding)?;
    let max_concurrent_streams =
        u16::try_from(limits.max_concurrent_streams).map_err(|_| TokenError::InvalidEncoding)?;
    let new_connections_per_minute = u16::try_from(limits.new_connections_per_minute)
        .map_err(|_| TokenError::InvalidEncoding)?;
    let pop_key = claims
        .proof_of_possession_public_key
        .map(|key| key.try_into().map_err(|_| TokenError::InvalidEncoding))
        .transpose()?;

    Ok(CapabilityClaims {
        token_version,
        token_id: TokenId::from_bytes(token_id),
        policy: CapabilityPolicy {
            plan_class: plan_from_wire(claims.plan_class)?,
            allowed_gateway_roles: roles,
            region_set: region_from_wire(claims.region_set)?,
            device_slot_class: device_from_wire(claims.device_slot_class)?,
            bandwidth_class: bandwidth_from_wire(claims.bandwidth_class)?,
            connection_limits: ConnectionLimits {
                max_active_sessions,
                max_concurrent_streams,
                new_connections_per_minute,
            },
        },
        not_before: claims.not_before,
        expires_at: claims.expires_at,
        issuer_key_id: claims.issuer_key_id,
        proof_of_possession_public_key: pop_key,
    })
}

fn plan_to_wire(value: PlanClass) -> PlanClassV1 {
    match value {
        PlanClass::Basic => PlanClassV1::Basic,
        PlanClass::Plus => PlanClassV1::Plus,
        PlanClass::Premium => PlanClassV1::Premium,
    }
}

fn plan_from_wire(value: i32) -> Result<PlanClass, TokenError> {
    match PlanClassV1::try_from(value).map_err(|_| TokenError::InvalidEncoding)? {
        PlanClassV1::Basic => Ok(PlanClass::Basic),
        PlanClassV1::Plus => Ok(PlanClass::Plus),
        PlanClassV1::Premium => Ok(PlanClass::Premium),
        PlanClassV1::Unspecified => Err(TokenError::InvalidEncoding),
    }
}

fn role_to_wire(value: GatewayRole) -> GatewayRoleV1 {
    match value {
        GatewayRole::Entry => GatewayRoleV1::Entry,
        GatewayRole::Relay => GatewayRoleV1::Relay,
        GatewayRole::Exit => GatewayRoleV1::Exit,
    }
}

fn role_from_wire(value: i32) -> Result<GatewayRole, TokenError> {
    match GatewayRoleV1::try_from(value).map_err(|_| TokenError::InvalidEncoding)? {
        GatewayRoleV1::Entry => Ok(GatewayRole::Entry),
        GatewayRoleV1::Relay => Ok(GatewayRole::Relay),
        GatewayRoleV1::Exit => Ok(GatewayRole::Exit),
        GatewayRoleV1::Unspecified => Err(TokenError::InvalidEncoding),
    }
}

fn region_to_wire(value: RegionSet) -> RegionSetV1 {
    match value {
        RegionSet::Europe => RegionSetV1::Europe,
        RegionSet::Americas => RegionSetV1::Americas,
        RegionSet::AsiaPacific => RegionSetV1::AsiaPacific,
        RegionSet::Global => RegionSetV1::Global,
    }
}

fn region_from_wire(value: i32) -> Result<RegionSet, TokenError> {
    match RegionSetV1::try_from(value).map_err(|_| TokenError::InvalidEncoding)? {
        RegionSetV1::Europe => Ok(RegionSet::Europe),
        RegionSetV1::Americas => Ok(RegionSet::Americas),
        RegionSetV1::AsiaPacific => Ok(RegionSet::AsiaPacific),
        RegionSetV1::Global => Ok(RegionSet::Global),
        RegionSetV1::Unspecified => Err(TokenError::InvalidEncoding),
    }
}

fn device_to_wire(value: DeviceSlotClass) -> DeviceSlotClassV1 {
    match value {
        DeviceSlotClass::Single => DeviceSlotClassV1::Single,
        DeviceSlotClass::Personal => DeviceSlotClassV1::Personal,
        DeviceSlotClass::Family => DeviceSlotClassV1::Family,
    }
}

fn device_from_wire(value: i32) -> Result<DeviceSlotClass, TokenError> {
    match DeviceSlotClassV1::try_from(value).map_err(|_| TokenError::InvalidEncoding)? {
        DeviceSlotClassV1::Single => Ok(DeviceSlotClass::Single),
        DeviceSlotClassV1::Personal => Ok(DeviceSlotClass::Personal),
        DeviceSlotClassV1::Family => Ok(DeviceSlotClass::Family),
        DeviceSlotClassV1::Unspecified => Err(TokenError::InvalidEncoding),
    }
}

fn bandwidth_to_wire(value: BandwidthClass) -> BandwidthClassV1 {
    match value {
        BandwidthClass::Standard => BandwidthClassV1::Standard,
        BandwidthClass::Fast => BandwidthClassV1::Fast,
        BandwidthClass::Priority => BandwidthClassV1::Priority,
    }
}

fn bandwidth_from_wire(value: i32) -> Result<BandwidthClass, TokenError> {
    match BandwidthClassV1::try_from(value).map_err(|_| TokenError::InvalidEncoding)? {
        BandwidthClassV1::Standard => Ok(BandwidthClass::Standard),
        BandwidthClassV1::Fast => Ok(BandwidthClass::Fast),
        BandwidthClassV1::Priority => Ok(BandwidthClass::Priority),
        BandwidthClassV1::Unspecified => Err(TokenError::InvalidEncoding),
    }
}
