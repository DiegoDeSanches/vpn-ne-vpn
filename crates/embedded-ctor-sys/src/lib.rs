#![allow(unsafe_code)]
//! Narrow safe wrapper for the supported C Tor `tor_api.h` surface.
//!
//! No internal Tor symbol is declared here. The native feature is enabled only
//! for the final iOS static-library build, after the pinned archive is verified.

#[cfg(feature = "native")]
use std::ffi::CStr;
use std::ffi::CString;
use std::sync::atomic::{AtomicU8, Ordering};

const STATE_FRESH: u8 = 0;
const STATE_RUNNING: u8 = 1;
const STATE_TERMINAL: u8 = 2;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 4 * 1024;
#[cfg(feature = "native")]
const MAX_VERSION_BYTES: usize = 256;

static PROCESS_STATE: AtomicU8 = AtomicU8::new(STATE_FRESH);

/// Redacted embedding failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedTorError {
    /// A command-line value exceeded the fixed public boundary.
    InvalidArguments,
    /// C Tor has already run in this process and cannot be restarted safely.
    ProcessTerminal,
    /// The native configuration object could not be created.
    ConfigurationUnavailable,
    /// C Tor rejected its command-line configuration.
    ConfigurationRejected,
    /// The linked provider exposed an invalid version string.
    InvalidProviderVersion,
    /// This build does not contain the pinned native C Tor artifact.
    NativeFeatureDisabled,
}

/// Runs the one permitted in-process Tor instance on the current native thread.
///
/// The call blocks until Tor exits. Once it returns, this process is terminal for
/// embedded Tor even when the exit code is zero.
pub fn run(arguments: &[CString]) -> Result<i32, EmbeddedTorError> {
    validate_arguments(arguments)?;
    if PROCESS_STATE
        .compare_exchange(
            STATE_FRESH,
            STATE_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(EmbeddedTorError::ProcessTerminal);
    }
    let result = native_run(arguments);
    PROCESS_STATE.store(STATE_TERMINAL, Ordering::Release);
    result
}

/// Returns a bounded informational provider version without assuming its format.
pub fn provider_version() -> Result<String, EmbeddedTorError> {
    native_provider_version()
}

fn validate_arguments(arguments: &[CString]) -> Result<(), EmbeddedTorError> {
    if arguments.is_empty()
        || arguments.len() > MAX_ARGUMENTS
        || arguments.iter().any(|argument| {
            argument.as_bytes().is_empty() || argument.as_bytes().len() > MAX_ARGUMENT_BYTES
        })
    {
        return Err(EmbeddedTorError::InvalidArguments);
    }
    Ok(())
}

#[cfg(feature = "native")]
fn native_run(arguments: &[CString]) -> Result<i32, EmbeddedTorError> {
    let mut pointers: Vec<*mut std::ffi::c_char> = arguments
        .iter()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect();
    // SAFETY: All declarations are the stable public `tor_api.h` interface.
    // CString storage and the pointer vector outlive the blocking `tor_run_main`.
    unsafe {
        let configuration = tor_main_configuration_new();
        if configuration.is_null() {
            return Err(EmbeddedTorError::ConfigurationUnavailable);
        }
        let configured = tor_main_configuration_set_command_line(
            configuration,
            i32::try_from(pointers.len()).map_err(|_| EmbeddedTorError::InvalidArguments)?,
            pointers.as_mut_ptr(),
        );
        if configured != 0 {
            tor_main_configuration_free(configuration);
            return Err(EmbeddedTorError::ConfigurationRejected);
        }
        let exit_code = tor_run_main(configuration);
        tor_main_configuration_free(configuration);
        Ok(exit_code)
    }
}

#[cfg(not(feature = "native"))]
fn native_run(_arguments: &[CString]) -> Result<i32, EmbeddedTorError> {
    Err(EmbeddedTorError::NativeFeatureDisabled)
}

#[cfg(feature = "native")]
fn native_provider_version() -> Result<String, EmbeddedTorError> {
    // SAFETY: The public API returns a process-lifetime NUL-terminated string or
    // null. A fixed scan limit prevents an unbounded copy across the boundary.
    unsafe {
        let pointer = tor_api_get_provider_version();
        if pointer.is_null() {
            return Err(EmbeddedTorError::InvalidProviderVersion);
        }
        let bytes = CStr::from_ptr(pointer).to_bytes();
        if bytes.is_empty() || bytes.len() > MAX_VERSION_BYTES {
            return Err(EmbeddedTorError::InvalidProviderVersion);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| EmbeddedTorError::InvalidProviderVersion)
    }
}

#[cfg(not(feature = "native"))]
fn native_provider_version() -> Result<String, EmbeddedTorError> {
    Err(EmbeddedTorError::NativeFeatureDisabled)
}

#[cfg(feature = "native")]
#[repr(C)]
struct TorMainConfiguration {
    _private: [u8; 0],
}

#[cfg(feature = "native")]
extern "C" {
    fn tor_main_configuration_new() -> *mut TorMainConfiguration;
    fn tor_main_configuration_set_command_line(
        configuration: *mut TorMainConfiguration,
        argc: std::ffi::c_int,
        argv: *mut *mut std::ffi::c_char,
    ) -> std::ffi::c_int;
    fn tor_main_configuration_free(configuration: *mut TorMainConfiguration);
    fn tor_run_main(configuration: *const TorMainConfiguration) -> std::ffi::c_int;
    fn tor_api_get_provider_version() -> *const std::ffi::c_char;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_boundary_rejects_empty_and_oversized_inputs() {
        assert_eq!(
            validate_arguments(&[]),
            Err(EmbeddedTorError::InvalidArguments)
        );
        let oversized = CString::new(vec![b'a'; MAX_ARGUMENT_BYTES + 1]).unwrap();
        assert_eq!(
            validate_arguments(&[oversized]),
            Err(EmbeddedTorError::InvalidArguments)
        );
    }

    #[test]
    fn native_calls_are_unavailable_without_the_explicit_feature() {
        if !cfg!(feature = "native") {
            assert_eq!(
                provider_version(),
                Err(EmbeddedTorError::NativeFeatureDisabled)
            );
        }
    }
}
