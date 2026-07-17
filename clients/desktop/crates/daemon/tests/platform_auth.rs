use onionroute_desktop_daemon::platform::{
    linux::{UnixSocketAuthenticator, UnixTransportPeer},
    macos::{AppleNetworkExtensionAuthenticator, AppleTransportPeer},
    windows::{WindowsPipeAuthenticator, WindowsTransportPeer},
};
use onionroute_desktop_ipc::{PeerAuthenticator, PeerRole};

#[test]
fn windows_pipe_authentication_requires_every_os_proof() {
    let authenticator = WindowsPipeAuthenticator;
    let rejected = WindowsTransportPeer::Client {
        pipe_acl_matches: true,
        token_is_interactive_owner: true,
        image_signature_is_approved: false,
        channel_binding: [1; 32],
    };
    assert!(authenticator.authenticate_client(&rejected).is_err());
    let accepted = WindowsTransportPeer::Server {
        process_id_matches_scm: true,
        installed_path_matches: true,
        authenticode_publisher_matches: true,
        channel_binding: [2; 32],
    };
    assert_eq!(
        authenticator.authenticate_server(&accepted).unwrap().role(),
        PeerRole::PrivilegedDaemon
    );
}

#[test]
fn unix_and_apple_authentication_fail_when_identity_is_ambiguous() {
    let unix = UnixSocketAuthenticator;
    assert!(unix
        .authenticate_server(&UnixTransportPeer::Server {
            peercred_uid_is_root: true,
            executable_is_root_owned_and_fixed: false,
            socket_is_root_owned: true,
            channel_binding: [3; 32],
        })
        .is_err());

    let apple = AppleNetworkExtensionAuthenticator;
    assert!(apple
        .authenticate_client(&AppleTransportPeer::App {
            audit_token_matches_owning_app: true,
            app_group_matches: true,
            designated_requirement_matches: false,
            channel_binding: [4; 32],
        })
        .is_err());
}
