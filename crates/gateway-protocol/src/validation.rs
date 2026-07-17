use std::collections::BTreeSet;

use crate::limits::{
    ABSOLUTE_MAX_FRAME_SIZE, MAX_CAPABILITY_TOKEN, MAX_CONCURRENT_STREAMS, MAX_CONNECTION_WINDOW,
    MAX_DATA_PAYLOAD, MAX_DRAIN_TIMEOUT_MS, MAX_HOSTNAME, MAX_PROOF_OF_POSSESSION,
    MAX_RESOLVE_ADDRESSES, MAX_SESSION_TTL_SECONDS, MAX_STREAM_WINDOW, MAX_TIMEOUT_MS,
    MIN_NEGOTIABLE_FRAME_SIZE,
};
use crate::negotiation::{validate_capabilities, validate_version_range};
use crate::proto::destination::Value as DestinationValue;
use crate::proto::gateway_frame::Body;
use crate::proto::{
    AddressFamily, AnonymityMode, AuthenticationResult, ClientHello, CloseCode, Data, Error,
    ErrorCode, GatewayFrame, GoAway, OpenTcpStream, ResolveDomain, ResolveResult, RotateSession,
    RotationReason, ServerHello, SessionRotated, TcpStreamOpened, TcpStreamRejected, WindowUpdate,
};
use crate::wire::onionroute::common::v1::RetryHint;
use crate::{ProtocolError, Result};

pub fn validate_frame(
    frame: &GatewayFrame,
    enabled_critical_extensions: &BTreeSet<u32>,
) -> Result<()> {
    if frame.sequence == 0 {
        return Err(ProtocolError::InvalidSequence);
    }
    let version = frame
        .version
        .as_ref()
        .ok_or(ProtocolError::InvalidField("frame_version"))?;
    if version.major == 0 {
        return Err(ProtocolError::InvalidField("frame_version"));
    }
    let mut seen_extensions = BTreeSet::new();
    for extension in &frame.critical_extension_ids {
        if *extension == 0
            || !enabled_critical_extensions.contains(extension)
            || !seen_extensions.insert(*extension)
        {
            return Err(ProtocolError::ProtocolViolation(
                "unknown or duplicate critical extension",
            ));
        }
    }
    match frame.body.as_ref().ok_or(ProtocolError::MissingBody)? {
        Body::ClientHello(message) => validate_client_hello(message),
        Body::ServerHello(message) => validate_server_hello(message),
        Body::Authenticate(message) => {
            bounded_nonempty(
                &message.anonymous_capability_token,
                MAX_CAPABILITY_TOKEN,
                "token",
            )?;
            if message.proof_of_possession.len() > MAX_PROOF_OF_POSSESSION {
                return Err(ProtocolError::InvalidField("proof_of_possession"));
            }
            exact_length(&message.session_nonce_binding, 32, "session_nonce_binding")
        }
        Body::AuthenticationResult(message) => validate_authentication_result(message),
        Body::OpenTcpStream(message) => validate_open_tcp(message),
        Body::TcpStreamOpened(message) => validate_stream_opened(message),
        Body::TcpStreamRejected(message) => validate_stream_rejected(message),
        Body::Data(message) => validate_data(message),
        Body::WindowUpdate(message) => validate_window_update(message),
        Body::HalfClose(message) => validate_stream_id(message.stream_id),
        Body::CloseStream(message) => {
            validate_stream_id(message.stream_id)?;
            known_nonzero_enum::<CloseCode>(message.code, "close_code")?;
            Ok(())
        }
        Body::ResolveDomain(message) => validate_resolve_domain(message),
        Body::ResolveResult(message) => validate_resolve_result(message),
        Body::RotateSession(message) => validate_rotate_session(message),
        Body::SessionRotated(message) => validate_session_rotated(message),
        Body::Ping(message) => bounded_range(&message.nonce, 8, 32, "ping_nonce"),
        Body::Pong(message) => bounded_range(&message.nonce, 8, 32, "pong_nonce"),
        Body::Error(message) => validate_error(message),
        Body::GoAway(message) => validate_go_away(message),
    }
}

pub fn validate_client_hello(message: &ClientHello) -> Result<()> {
    validate_version_range(
        message
            .supported_versions
            .as_ref()
            .ok_or(ProtocolError::InvalidField("supported_versions"))?,
    )?;
    validate_capabilities(&message.client_capabilities)?;
    let mode = known_nonzero_enum::<AnonymityMode>(message.anonymity_mode, "anonymity_mode")?;
    if mode == AnonymityMode::DirectTor {
        return Err(ProtocolError::InvalidField("anonymity_mode"));
    }
    validate_country(&message.desired_country)?;
    exact_length(&message.session_nonce, 32, "session_nonce")?;
    validate_frame_limit(message.maximum_frame_size)?;
    validate_connection_window(message.initial_connection_receive_window)?;
    validate_stream_window(message.initial_stream_receive_window)
}

pub fn validate_server_hello(message: &ServerHello) -> Result<()> {
    validate_version_range(
        message
            .supported_versions
            .as_ref()
            .ok_or(ProtocolError::InvalidField("supported_versions"))?,
    )?;
    if match message.selected_version.as_ref() {
        Some(version) => version.major == 0,
        None => true,
    } {
        return Err(ProtocolError::InvalidField("selected_version"));
    }
    validate_capabilities(&message.enabled_capabilities)?;
    exact_length(&message.echoed_client_nonce, 32, "echoed_client_nonce")?;
    exact_length(&message.server_nonce, 32, "server_nonce")?;
    exact_length(&message.ephemeral_session_id, 16, "ephemeral_session_id")?;
    validate_frame_limit(message.maximum_frame_size)?;
    if message.maximum_concurrent_streams == 0
        || message.maximum_concurrent_streams as usize > MAX_CONCURRENT_STREAMS
    {
        return Err(ProtocolError::InvalidField("maximum_concurrent_streams"));
    }
    validate_connection_window(message.initial_connection_receive_window)?;
    validate_stream_window(message.initial_stream_receive_window)?;
    if message.idle_stream_timeout_ms == 0 || message.idle_stream_timeout_ms > 3_600_000 {
        return Err(ProtocolError::InvalidField("idle_stream_timeout_ms"));
    }
    if message.session_ttl_seconds == 0 || message.session_ttl_seconds > MAX_SESSION_TTL_SECONDS {
        return Err(ProtocolError::InvalidField("session_ttl_seconds"));
    }
    Ok(())
}

fn validate_authentication_result(message: &AuthenticationResult) -> Result<()> {
    validate_capabilities(&message.granted_capabilities)?;
    let error = ErrorCode::try_from(message.error_code)
        .map_err(|_| ProtocolError::InvalidField("authentication_error_code"))?;
    if message.accepted {
        if error != ErrorCode::Unspecified || message.expires_at_unix_seconds <= 0 {
            return Err(ProtocolError::InvalidField("authentication_result"));
        }
    } else if error == ErrorCode::Unspecified || message.expires_at_unix_seconds != 0 {
        return Err(ProtocolError::InvalidField("authentication_result"));
    }
    Ok(())
}

fn validate_open_tcp(message: &OpenTcpStream) -> Result<()> {
    validate_stream_id(message.stream_id)?;
    let destination = message
        .destination
        .as_ref()
        .and_then(|destination| destination.value.as_ref())
        .ok_or(ProtocolError::InvalidField("destination"))?;
    match destination {
        DestinationValue::Hostname(hostname) => validate_hostname(hostname)?,
        DestinationValue::IpAddress(address) => validate_ip_address(address)?,
    }
    if message.destination_port == 0 || message.destination_port > u16::MAX as u32 {
        return Err(ProtocolError::InvalidField("destination_port"));
    }
    validate_timeout(message.timeout_ms)?;
    if message.policy_flags & !0b11 != 0 || message.policy_flags == 0b11 {
        return Err(ProtocolError::InvalidField("policy_flags"));
    }
    validate_stream_window(message.initial_receive_window)
}

fn validate_stream_opened(message: &TcpStreamOpened) -> Result<()> {
    validate_stream_id(message.stream_id)?;
    validate_stream_window(message.initial_receive_window)
}

fn validate_stream_rejected(message: &TcpStreamRejected) -> Result<()> {
    validate_stream_id(message.stream_id)?;
    known_nonzero_enum::<ErrorCode>(message.error_code, "stream_error_code")?;
    known_enum::<RetryHint>(message.retry_hint, "retry_hint")?;
    Ok(())
}

fn validate_data(message: &Data) -> Result<()> {
    validate_stream_id(message.stream_id)?;
    bounded_nonempty(&message.payload, MAX_DATA_PAYLOAD, "data_payload")
}

fn validate_window_update(message: &WindowUpdate) -> Result<()> {
    if message.stream_id != 0 {
        validate_stream_id(message.stream_id)?;
    }
    if message.credit == 0 {
        return Err(ProtocolError::InvalidField("window_credit"));
    }
    Ok(())
}

fn validate_resolve_domain(message: &ResolveDomain) -> Result<()> {
    validate_stream_id(message.query_id)?;
    validate_hostname(&message.hostname)?;
    known_nonzero_enum::<AddressFamily>(message.address_family, "address_family")?;
    validate_timeout(message.timeout_ms)
}

fn validate_resolve_result(message: &ResolveResult) -> Result<()> {
    validate_stream_id(message.query_id)?;
    if message.ip_addresses.len() > MAX_RESOLVE_ADDRESSES {
        return Err(ProtocolError::InvalidField("resolve_addresses"));
    }
    let error = ErrorCode::try_from(message.error_code)
        .map_err(|_| ProtocolError::InvalidField("resolve_error_code"))?;
    if error == ErrorCode::Unspecified {
        if message.ip_addresses.is_empty() || message.minimum_ttl_seconds == 0 {
            return Err(ProtocolError::InvalidField("resolve_result"));
        }
        for address in &message.ip_addresses {
            validate_ip_address(address)?;
        }
    } else if !message.ip_addresses.is_empty() || message.minimum_ttl_seconds != 0 {
        return Err(ProtocolError::InvalidField("resolve_result"));
    }
    Ok(())
}

fn validate_rotate_session(message: &RotateSession) -> Result<()> {
    exact_length(&message.rotation_nonce, 16, "rotation_nonce")?;
    known_nonzero_enum::<RotationReason>(message.reason, "rotation_reason")?;
    validate_drain_timeout(message.drain_timeout_ms)
}

fn validate_session_rotated(message: &SessionRotated) -> Result<()> {
    exact_length(&message.rotation_nonce, 16, "rotation_nonce")?;
    let error = ErrorCode::try_from(message.error_code)
        .map_err(|_| ProtocolError::InvalidField("rotation_error_code"))?;
    if message.accepted {
        if error != ErrorCode::Unspecified || !message.replacement_transport_required {
            return Err(ProtocolError::InvalidField("session_rotated"));
        }
    } else if error == ErrorCode::Unspecified || message.replacement_transport_required {
        return Err(ProtocolError::InvalidField("session_rotated"));
    }
    Ok(())
}

fn validate_error(message: &Error) -> Result<()> {
    known_nonzero_enum::<ErrorCode>(message.code, "error_code")?;
    known_enum::<RetryHint>(message.retry_hint, "retry_hint")?;
    if message.fatal && message.stream_id != 0 {
        return Err(ProtocolError::InvalidField("fatal_error_scope"));
    }
    if message.stream_id != 0 {
        validate_stream_id(message.stream_id)?;
    }
    if message.retry_after_ms > MAX_TIMEOUT_MS {
        return Err(ProtocolError::InvalidField("retry_after_ms"));
    }
    exact_length(&message.correlation_id, 16, "correlation_id")
}

fn validate_go_away(message: &GoAway) -> Result<()> {
    if message.last_accepted_stream_id != 0 {
        validate_stream_id(message.last_accepted_stream_id)?;
    }
    known_enum::<ErrorCode>(message.code, "go_away_code")?;
    validate_drain_timeout(message.drain_timeout_ms)
}

pub fn validate_stream_id(stream_id: u64) -> Result<()> {
    if stream_id == 0 || stream_id & 1 == 0 {
        return Err(ProtocolError::InvalidStreamId);
    }
    Ok(())
}

pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty()
        || hostname.len() > MAX_HOSTNAME
        || !hostname.is_ascii()
        || hostname.ends_with('.')
    {
        return Err(ProtocolError::InvalidField("hostname"));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProtocolError::InvalidField("hostname"));
        }
    }
    Ok(())
}

fn validate_ip_address(address: &[u8]) -> Result<()> {
    if !matches!(address.len(), 4 | 16) {
        return Err(ProtocolError::InvalidField("ip_address"));
    }
    Ok(())
}

fn validate_country(country: &str) -> Result<()> {
    if !country.is_empty()
        && (country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        return Err(ProtocolError::InvalidField("desired_country"));
    }
    Ok(())
}

fn validate_frame_limit(value: u32) -> Result<()> {
    if !(MIN_NEGOTIABLE_FRAME_SIZE..=ABSOLUTE_MAX_FRAME_SIZE).contains(&(value as usize)) {
        return Err(ProtocolError::InvalidField("maximum_frame_size"));
    }
    Ok(())
}

fn validate_connection_window(value: u32) -> Result<()> {
    if value == 0 || u64::from(value) > MAX_CONNECTION_WINDOW {
        return Err(ProtocolError::InvalidField("connection_window"));
    }
    Ok(())
}

fn validate_stream_window(value: u32) -> Result<()> {
    if value == 0 || u64::from(value) > MAX_STREAM_WINDOW {
        return Err(ProtocolError::InvalidField("stream_window"));
    }
    Ok(())
}

fn validate_timeout(value: u32) -> Result<()> {
    if value == 0 || value > MAX_TIMEOUT_MS {
        return Err(ProtocolError::InvalidField("timeout_ms"));
    }
    Ok(())
}

fn validate_drain_timeout(value: u32) -> Result<()> {
    if value == 0 || value > MAX_DRAIN_TIMEOUT_MS {
        return Err(ProtocolError::InvalidField("drain_timeout_ms"));
    }
    Ok(())
}

fn exact_length(value: &[u8], expected: usize, field: &'static str) -> Result<()> {
    if value.len() != expected {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn bounded_nonempty(value: &[u8], maximum: usize, field: &'static str) -> Result<()> {
    bounded_range(value, 1, maximum, field)
}

fn bounded_range(value: &[u8], minimum: usize, maximum: usize, field: &'static str) -> Result<()> {
    if !(minimum..=maximum).contains(&value.len()) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn known_enum<T>(value: i32, field: &'static str) -> Result<T>
where
    T: TryFrom<i32>,
{
    T::try_from(value).map_err(|_| ProtocolError::InvalidField(field))
}

fn known_nonzero_enum<T>(value: i32, field: &'static str) -> Result<T>
where
    T: TryFrom<i32>,
{
    if value == 0 {
        return Err(ProtocolError::InvalidField(field));
    }
    known_enum::<T>(value, field)
}
