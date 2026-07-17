use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_EVENTS: usize = 128;
const MAX_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticEventCode {
    DaemonStarted,
    RecoveredFailClosed,
    KillSwitchEngaged,
    KillSwitchVerificationFailed,
    TorBootstrapFailed,
    GatewayUnavailable,
    SoftRotationCompleted,
    HardRotationCompleted,
    LeakBlockedDns,
    LeakBlockedIpv6,
    LeakBlockedQuic,
    ProtocolRejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticSnapshot {
    pub app_version: String,
    pub daemon_version: String,
    pub os_family: String,
    pub tunnel_phase: String,
    pub tor_bootstrap_bucket: u8,
    pub gateway_status: String,
    pub latency_bucket: String,
    pub kill_switch_state: String,
    pub blocked_leak_count: u64,
    pub events: Vec<DiagnosticEventCode>,
}

impl DiagnosticSnapshot {
    fn validate(&self) -> Result<(), DiagnosticsError> {
        for value in [
            &self.app_version,
            &self.daemon_version,
            &self.os_family,
            &self.tunnel_phase,
            &self.gateway_status,
            &self.latency_bucket,
            &self.kill_switch_state,
        ] {
            if value.is_empty()
                || value.len() > 64
                || !value.is_ascii()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(DiagnosticsError::InvalidSnapshot);
            }
        }
        if self.events.len() > MAX_EVENTS
            || !matches!(self.tor_bootstrap_bucket, 0 | 25 | 50 | 75 | 100)
        {
            return Err(DiagnosticsError::InvalidSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportMetadata {
    pub export_id: [u8; 16],
    pub file_name: String,
    pub expires_at: SystemTime,
    pub sha256: [u8; 32],
}

#[derive(Debug, Error)]
pub enum DiagnosticsError {
    #[error("diagnostic snapshot contains a non-allowlisted value")]
    InvalidSnapshot,
    #[error("diagnostic retention is outside the allowed range")]
    InvalidRetention,
    #[error("secure random generation is unavailable")]
    RandomUnavailable,
    #[error("diagnostic export I/O failed")]
    Io(#[from] std::io::Error),
    #[error("diagnostic serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct StoredExport {
    schema: String,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    diagnostics: DiagnosticSnapshot,
}

/// Produces allowlist-only JSON. There is no API for arbitrary log files,
/// process output, hostnames, onion addresses, tokens, or packet metadata.
pub struct DiagnosticsExporter {
    directory: PathBuf,
}

impl DiagnosticsExporter {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn export(
        &self,
        snapshot: DiagnosticSnapshot,
        now: SystemTime,
        retention: Duration,
    ) -> Result<ExportMetadata, DiagnosticsError> {
        snapshot.validate()?;
        if retention.is_zero() || retention > MAX_RETENTION {
            return Err(DiagnosticsError::InvalidRetention);
        }
        fs::create_dir_all(&self.directory)?;
        let created = unix_seconds(now)?;
        let expires_at = now
            .checked_add(retention)
            .ok_or(DiagnosticsError::InvalidRetention)?;
        let expires = unix_seconds(expires_at)?;
        let mut export_id = [0_u8; 16];
        getrandom::getrandom(&mut export_id).map_err(|_| DiagnosticsError::RandomUnavailable)?;
        let id_hex = hex(&export_id);
        let file_name = format!("onionroute-diagnostics-{created}-{id_hex}.json");
        let target = self.directory.join(&file_name);
        let temporary = self.directory.join(format!(".{file_name}.tmp"));
        let export = StoredExport {
            schema: "onionroute.desktop.diagnostics.v1".into(),
            created_at_unix_seconds: created,
            expires_at_unix_seconds: expires,
            diagnostics: snapshot,
        };
        let bytes = serde_json::to_vec_pretty(&export)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &target)?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(ExportMetadata {
            export_id,
            file_name,
            expires_at,
            sha256: digest,
        })
    }

    /// Deletes only expired files created by this exporter inside its fixed
    /// directory. Unknown files and malformed exports are left untouched.
    pub fn prune_expired(&self, now: SystemTime) -> Result<usize, DiagnosticsError> {
        let now = unix_seconds(now)?;
        let mut removed = 0;
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with("onionroute-diagnostics-") || !name.ends_with(".json") {
                continue;
            }
            let bytes = match fs::read(entry.path()) {
                Ok(bytes) if bytes.len() <= 64 * 1024 => bytes,
                _ => continue,
            };
            let stored: StoredExport = match serde_json::from_slice(&bytes) {
                Ok(stored) => stored,
                Err(_) => continue,
            };
            if stored.schema == "onionroute.desktop.diagnostics.v1"
                && stored.expires_at_unix_seconds <= now
            {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

fn unix_seconds(value: SystemTime) -> Result<u64, DiagnosticsError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DiagnosticsError::InvalidRetention)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
