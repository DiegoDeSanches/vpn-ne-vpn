use std::collections::BTreeSet;

use crate::wire::onionroute::common::v1::{ProtocolVersion, ProtocolVersionRange};
use crate::{ProtocolError, Result};

pub const TCP_CONNECT_V1: &str = "tcp-connect-v1";
pub const FLOW_CONTROL_V1: &str = "flow-control-v1";
pub const RESOLVE_DOMAIN_V1: &str = "resolve-domain-v1";
pub const SESSION_ROTATION_V1: &str = "session-rotation-v1";

pub fn version(major: u32, minor: u32) -> ProtocolVersion {
    ProtocolVersion { major, minor }
}

pub fn version_range(major: u32, minimum_minor: u32, maximum_minor: u32) -> ProtocolVersionRange {
    ProtocolVersionRange {
        minimum: Some(version(major, minimum_minor)),
        maximum: Some(version(major, maximum_minor)),
    }
}

pub fn validate_version_range(range: &ProtocolVersionRange) -> Result<(u32, u32, u32)> {
    let minimum = range
        .minimum
        .as_ref()
        .ok_or(ProtocolError::InvalidField("minimum_version"))?;
    let maximum = range
        .maximum
        .as_ref()
        .ok_or(ProtocolError::InvalidField("maximum_version"))?;
    if minimum.major == 0 || minimum.major != maximum.major || minimum.minor > maximum.minor {
        return Err(ProtocolError::InvalidField("supported_versions"));
    }
    Ok((minimum.major, minimum.minor, maximum.minor))
}

/// Selects the highest common minor within one major.
pub fn select_version(
    client: &ProtocolVersionRange,
    server: &ProtocolVersionRange,
) -> Result<ProtocolVersion> {
    let (client_major, client_min, client_max) = validate_version_range(client)?;
    let (server_major, server_min, server_max) = validate_version_range(server)?;
    if client_major != server_major {
        return Err(ProtocolError::IncompatibleVersion);
    }
    let minimum = client_min.max(server_min);
    let maximum = client_max.min(server_max);
    if minimum > maximum {
        return Err(ProtocolError::IncompatibleVersion);
    }
    Ok(version(client_major, maximum))
}

/// Verifies both that the selected version is allowed and that the server did
/// not silently choose a lower minor than the advertised highest intersection.
pub fn verify_server_selection(
    client: &ProtocolVersionRange,
    server: &ProtocolVersionRange,
    selected: &ProtocolVersion,
) -> Result<()> {
    let expected = select_version(client, server)?;
    if &expected != selected {
        return Err(ProtocolError::SilentDowngrade);
    }
    Ok(())
}

pub fn negotiate_capabilities(
    requested: &[String],
    server_supported: &BTreeSet<String>,
) -> Result<Vec<String>> {
    validate_capabilities(requested)?;
    let mut names = BTreeSet::new();
    let mut enabled = Vec::new();
    for requested_name in requested {
        let (required, name) = requested_name
            .strip_prefix("required:")
            .map_or((false, requested_name.as_str()), |name| (true, name));
        if !names.insert(name) {
            return Err(ProtocolError::InvalidField("duplicate_capability"));
        }
        if server_supported.contains(name) {
            enabled.push(name.to_owned());
        } else if required {
            return Err(ProtocolError::IncompatibleVersion);
        }
    }
    Ok(enabled)
}

pub fn verify_enabled_capabilities(requested: &[String], enabled: &[String]) -> Result<()> {
    validate_capabilities(requested)?;
    validate_capabilities(enabled)?;
    let requested_names: BTreeSet<&str> = requested
        .iter()
        .map(|value| value.strip_prefix("required:").unwrap_or(value))
        .collect();
    let enabled_names: BTreeSet<&str> = enabled.iter().map(String::as_str).collect();
    if enabled_names.len() != enabled.len()
        || enabled_names
            .iter()
            .any(|name| !requested_names.contains(name))
    {
        return Err(ProtocolError::ProtocolViolation(
            "server enabled an unrequested capability",
        ));
    }
    for requested_name in requested {
        if let Some(required) = requested_name.strip_prefix("required:") {
            if !enabled_names.contains(required) {
                return Err(ProtocolError::IncompatibleVersion);
            }
        }
    }
    Ok(())
}

pub fn validate_capabilities(capabilities: &[String]) -> Result<()> {
    use crate::limits::{MAX_CAPABILITIES, MAX_CAPABILITY_NAME};

    if capabilities.len() > MAX_CAPABILITIES {
        return Err(ProtocolError::InvalidField("capabilities"));
    }
    for value in capabilities {
        if value.is_empty()
            || value.len() > MAX_CAPABILITY_NAME
            || !value.is_ascii()
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b':' | b'.')
            })
        {
            return Err(ProtocolError::InvalidField("capability_name"));
        }
        let name = value.strip_prefix("required:").unwrap_or(value);
        if name.is_empty() || name.starts_with('-') || name.ends_with('-') {
            return Err(ProtocolError::InvalidField("capability_name"));
        }
    }
    Ok(())
}
