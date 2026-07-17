use std::collections::HashSet;

use thiserror::Error;

use crate::v1::{
    envelope, request, response, AnonymityMode, Envelope, EventTopic, KillSwitchState,
    LatencyBucket, PeerAuthMethod, ProtocolVersion, RotationKind, RouteRole, SplitRuleMode,
    TunnelPhase,
};

pub const IPC_V1: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
const MAX_TOPICS: usize = 16;
const MAX_SPLIT_RULES: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("required desktop IPC field is absent")]
    Missing,
    #[error("desktop IPC protocol version is unsupported")]
    UnsupportedVersion,
    #[error("desktop IPC field has invalid length")]
    InvalidLength,
    #[error("desktop IPC enum value is unknown")]
    UnknownEnum,
    #[error("desktop IPC collection exceeds its hard limit")]
    TooManyItems,
    #[error("desktop IPC field value is invalid")]
    InvalidValue,
}

pub fn validate_envelope(envelope: &Envelope) -> Result<(), ValidationError> {
    let body = envelope.body.as_ref().ok_or(ValidationError::Missing)?;
    let version = envelope.version.as_ref().ok_or(ValidationError::Missing)?;
    if version.major != IPC_V1.major || version.minor > IPC_V1.minor {
        return Err(ValidationError::UnsupportedVersion);
    }
    if envelope.request_id.len() != 16 || envelope.sequence == 0 {
        return Err(ValidationError::InvalidLength);
    }

    match body {
        envelope::Body::ClientHello(hello) => {
            let range = hello
                .supported_versions
                .as_ref()
                .ok_or(ValidationError::Missing)?;
            let minimum = range.minimum.as_ref().ok_or(ValidationError::Missing)?;
            let maximum = range.maximum.as_ref().ok_or(ValidationError::Missing)?;
            if minimum.major != 1
                || maximum.major != 1
                || minimum.minor > maximum.minor
                || minimum.minor > IPC_V1.minor
            {
                return Err(ValidationError::UnsupportedVersion);
            }
            if hello.process_nonce.len() != 32 {
                return Err(ValidationError::InvalidLength);
            }
            validate_topics(&hello.requested_topics)?;
            validate_window(hello.event_window)?;
        }
        envelope::Body::ServerHello(hello) => {
            validate_selected(hello.selected_version.as_ref())?;
            if hello.process_nonce.len() != 32 || hello.session_id.len() != 16 {
                return Err(ValidationError::InvalidLength);
            }
            PeerAuthMethod::try_from(hello.peer_auth_method)
                .ok()
                .filter(|value| *value != PeerAuthMethod::Unspecified)
                .ok_or(ValidationError::UnknownEnum)?;
            validate_window(hello.event_window)?;
        }
        envelope::Body::Request(request) => validate_request(request)?,
        envelope::Body::Response(response) => validate_response(response)?,
        envelope::Body::Event(event) => {
            EventTopic::try_from(event.topic)
                .ok()
                .filter(|topic| *topic != EventTopic::Unspecified)
                .ok_or(ValidationError::UnknownEnum)?;
            if event.event_sequence == 0 || event.payload.is_none() {
                return Err(ValidationError::InvalidValue);
            }
        }
    }
    Ok(())
}

fn validate_selected(version: Option<&ProtocolVersion>) -> Result<(), ValidationError> {
    let version = version.ok_or(ValidationError::Missing)?;
    if version.major != IPC_V1.major || version.minor > IPC_V1.minor {
        return Err(ValidationError::UnsupportedVersion);
    }
    Ok(())
}

fn validate_topics(topics: &[i32]) -> Result<(), ValidationError> {
    if topics.len() > MAX_TOPICS {
        return Err(ValidationError::TooManyItems);
    }
    let mut unique = HashSet::with_capacity(topics.len());
    for raw in topics {
        let topic = EventTopic::try_from(*raw)
            .ok()
            .filter(|topic| *topic != EventTopic::Unspecified)
            .ok_or(ValidationError::UnknownEnum)?;
        if !unique.insert(topic as i32) {
            return Err(ValidationError::InvalidValue);
        }
    }
    Ok(())
}

fn validate_window(window: u32) -> Result<(), ValidationError> {
    if !(1..=256).contains(&window) {
        return Err(ValidationError::InvalidValue);
    }
    Ok(())
}

fn validate_request(message: &crate::v1::Request) -> Result<(), ValidationError> {
    if !message.confirmation_id.is_empty() && message.confirmation_id.len() != 16 {
        return Err(ValidationError::InvalidLength);
    }
    let command = message.command.as_ref().ok_or(ValidationError::Missing)?;
    match command {
        request::Command::GetState(_) | request::Command::Connect(_) => {}
        request::Command::Disconnect(_) => {}
        request::Command::SetCountry(value) => {
            let country = value.country.as_ref().ok_or(ValidationError::Missing)?;
            match country.selection.as_ref().ok_or(ValidationError::Missing)? {
                crate::v1::country_selection::Selection::Automatic(value) if *value => {}
                crate::v1::country_selection::Selection::IsoCountryCode(code) => {
                    validate_country(code)?
                }
                _ => return Err(ValidationError::InvalidValue),
            }
        }
        request::Command::SetAnonymityMode(value) => {
            AnonymityMode::try_from(value.mode)
                .ok()
                .filter(|mode| *mode != AnonymityMode::Unspecified)
                .ok_or(ValidationError::UnknownEnum)?;
        }
        request::Command::Rotate(value) => {
            RotationKind::try_from(value.kind)
                .ok()
                .filter(|kind| *kind != RotationKind::Unspecified)
                .ok_or(ValidationError::UnknownEnum)?;
        }
        request::Command::UpdateSplitTunneling(value) => {
            if value.rules.len() > MAX_SPLIT_RULES {
                return Err(ValidationError::TooManyItems);
            }
            let mut apps = HashSet::with_capacity(value.rules.len());
            for rule in &value.rules {
                if rule.application_id.is_empty()
                    || rule.application_id.len() > 256
                    || rule.application_id.chars().any(char::is_control)
                    || !apps.insert(rule.application_id.as_str())
                {
                    return Err(ValidationError::InvalidValue);
                }
                SplitRuleMode::try_from(rule.mode)
                    .ok()
                    .filter(|mode| *mode != SplitRuleMode::Unspecified)
                    .ok_or(ValidationError::UnknownEnum)?;
            }
        }
        request::Command::SetKillSwitch(_) => {}
        request::Command::ExportDiagnostics(value) => {
            if !(1..=168).contains(&value.retention_hours) {
                return Err(ValidationError::InvalidValue);
            }
        }
        request::Command::UpdateSettings(value) => {
            if value.locale.is_empty()
                || value.locale.len() > 16
                || value.locale.chars().any(char::is_control)
                || !(5..=24 * 60).contains(&value.automatic_rotation_minutes)
            {
                return Err(ValidationError::InvalidValue);
            }
        }
        request::Command::Subscribe(value) => {
            validate_topics(&value.topics)?;
            validate_window(value.event_window)?;
        }
        request::Command::AcknowledgeEvents(value) => {
            if value.through_sequence == 0 {
                return Err(ValidationError::InvalidValue);
            }
        }
    }
    Ok(())
}

fn validate_response(message: &crate::v1::Response) -> Result<(), ValidationError> {
    crate::v1::ResponseStatus::try_from(message.status)
        .ok()
        .filter(|status| *status != crate::v1::ResponseStatus::Unspecified)
        .ok_or(ValidationError::UnknownEnum)?;
    crate::v1::ErrorCode::try_from(message.error_code).map_err(|_| ValidationError::UnknownEnum)?;
    if message.support_code.len() > 16
        || !message.support_code.is_ascii()
        || message.support_code.chars().any(char::is_control)
    {
        return Err(ValidationError::InvalidValue);
    }
    match message.payload.as_ref() {
        Some(response::Payload::State(state)) => validate_state(state)?,
        Some(response::Payload::Confirmation(value)) => {
            if value.confirmation_id.len() != 16 || !(1..=120).contains(&value.expires_in_seconds) {
                return Err(ValidationError::InvalidValue);
            }
        }
        Some(response::Payload::DiagnosticsExport(value)) => {
            if value.export_id.len() != 16
                || value.sha256.len() != 32
                || value.file_name.is_empty()
                || value.file_name.len() > 96
                || value.file_name.contains('/')
                || value.file_name.contains('\\')
                || value.file_name.contains("..")
            {
                return Err(ValidationError::InvalidValue);
            }
        }
        None => {}
    }
    Ok(())
}

fn validate_state(state: &crate::v1::StateSnapshot) -> Result<(), ValidationError> {
    TunnelPhase::try_from(state.phase)
        .ok()
        .filter(|value| *value != TunnelPhase::Unspecified)
        .ok_or(ValidationError::UnknownEnum)?;
    AnonymityMode::try_from(state.anonymity_mode)
        .ok()
        .filter(|value| *value != AnonymityMode::Unspecified)
        .ok_or(ValidationError::UnknownEnum)?;
    GatewayStatus::try_from(state.gateway_status).map_err(|_| ValidationError::UnknownEnum)?;
    LatencyBucket::try_from(state.latency_bucket)
        .ok()
        .filter(|value| *value != LatencyBucket::Unspecified)
        .ok_or(ValidationError::UnknownEnum)?;
    KillSwitchState::try_from(state.kill_switch)
        .ok()
        .filter(|value| *value != KillSwitchState::Unspecified)
        .ok_or(ValidationError::UnknownEnum)?;
    if state.tor_bootstrap_percent > 100 || state.state_revision == 0 {
        return Err(ValidationError::InvalidValue);
    }
    if !state.exit_country_code.is_empty() {
        validate_country(&state.exit_country_code)?;
    }
    if state.route_roles.len() > 4 {
        return Err(ValidationError::TooManyItems);
    }
    let mut roles = HashSet::with_capacity(state.route_roles.len());
    for raw in &state.route_roles {
        let role = RouteRole::try_from(*raw)
            .ok()
            .filter(|value| *value != RouteRole::Unspecified)
            .ok_or(ValidationError::UnknownEnum)?;
        if !roles.insert(role as i32) {
            return Err(ValidationError::InvalidValue);
        }
    }
    Ok(())
}

fn validate_country(value: &str) -> Result<(), ValidationError> {
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(ValidationError::InvalidValue);
    }
    Ok(())
}

use crate::v1::GatewayStatus;
