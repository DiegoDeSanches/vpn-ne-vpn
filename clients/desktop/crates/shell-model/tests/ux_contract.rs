use onionroute_desktop_ipc::v1::{AnonymityMode, ErrorCode};
use onionroute_desktop_shell_model::{
    hard_rotation_request, mode_copy, set_kill_switch_request, SafeUiError, UiState,
};

#[test]
fn ui_disconnect_never_generates_a_tunnel_disconnect() {
    let mut state = UiState::default();
    state.daemon_connected = true;
    state.daemon_connection_lost();
    assert!(!state.daemon_connected);
}

#[test]
fn critical_commands_require_an_explicit_confirmation_value() {
    assert!(hard_rotation_request(None).confirmation_id.is_empty());
    assert_eq!(
        hard_rotation_request(Some([7; 16])).confirmation_id,
        vec![7; 16]
    );
    assert!(set_kill_switch_request(false, None)
        .confirmation_id
        .is_empty());
}

#[test]
fn all_supported_modes_have_distinct_copy() {
    let modes = [
        AnonymityMode::Standard,
        AnonymityMode::Enhanced,
        AnonymityMode::Maximum,
        AnonymityMode::DirectTor,
    ];
    let copy: std::collections::HashSet<_> = modes.into_iter().map(mode_copy).collect();
    assert_eq!(copy.len(), modes.len());
}

#[test]
fn daemon_errors_ignore_untrusted_or_sensitive_text() {
    let error = SafeUiError::from_ipc(ErrorCode::InternalRedacted, "token=secret.onion");
    assert!(error.support_code.is_none());
    assert_eq!(error.message.as_str(), "error.generic");
}
