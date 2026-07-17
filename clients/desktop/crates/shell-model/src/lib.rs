//! Privilege-free desktop presentation model.
//!
//! This crate maps typed daemon state to localization identifiers. It cannot
//! open network sockets, alter routes, or call the Rust network core.

use onionroute_desktop_ipc::v1::{
    request, AnonymityMode, ConnectRequest, CriticalAction, DisconnectRequest, ErrorCode,
    GetStateRequest, Request, RotateRequest, RotationKind, SetKillSwitchRequest, StateSnapshot,
    TunnelPhase,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Screen {
    Home,
    Country,
    Anonymity,
    Route,
    Rotation,
    SplitTunneling,
    KillSwitch,
    Diagnostics,
    Subscription,
    Settings,
}

impl Screen {
    pub const ALL: [Self; 10] = [
        Self::Home,
        Self::Country,
        Self::Anonymity,
        Self::Route,
        Self::Rotation,
        Self::SplitTunneling,
        Self::KillSwitch,
        Self::Diagnostics,
        Self::Subscription,
        Self::Settings,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StringKey {
    AppName,
    NavHome,
    NavCountry,
    NavAnonymity,
    NavRoute,
    NavRotation,
    NavSplitTunneling,
    NavKillSwitch,
    NavDiagnostics,
    NavSubscription,
    NavSettings,
    ActionConnect,
    ActionDisconnect,
    ActionConfirm,
    ActionCancel,
    ActionNewIdentity,
    StatusDisconnected,
    StatusPreparing,
    StatusProtected,
    StatusRotating,
    StatusDegraded,
    StatusBlocked,
    StatusFatal,
    LabelExitCountry,
    LabelAnonymityMode,
    LabelTorBootstrap,
    LabelGatewayStatus,
    LabelLatencyBucket,
    LabelKillSwitch,
    LabelBlockedLeaks,
    WarningUdpBlocked,
    WarningHardRotation,
    WarningFailClosed,
    ModeStandardTitle,
    ModeStandardDescription,
    ModeEnhancedTitle,
    ModeEnhancedDescription,
    ModeMaximumTitle,
    ModeMaximumDescription,
    ModeDirectTorTitle,
    ModeDirectTorDescription,
    ErrorInvalidRequest,
    ErrorProtocolIncompatible,
    ErrorNotAuthorized,
    ErrorKillSwitchFailed,
    ErrorTorBootstrapFailed,
    ErrorGatewayUnavailable,
    ErrorRotationRateLimited,
    ErrorDaemonRecovering,
    ErrorGeneric,
    A11yMainStatus,
    A11yNavigation,
    A11yCriticalDialog,
}

impl StringKey {
    pub const ALL: [Self; 53] = [
        Self::AppName,
        Self::NavHome,
        Self::NavCountry,
        Self::NavAnonymity,
        Self::NavRoute,
        Self::NavRotation,
        Self::NavSplitTunneling,
        Self::NavKillSwitch,
        Self::NavDiagnostics,
        Self::NavSubscription,
        Self::NavSettings,
        Self::ActionConnect,
        Self::ActionDisconnect,
        Self::ActionConfirm,
        Self::ActionCancel,
        Self::ActionNewIdentity,
        Self::StatusDisconnected,
        Self::StatusPreparing,
        Self::StatusProtected,
        Self::StatusRotating,
        Self::StatusDegraded,
        Self::StatusBlocked,
        Self::StatusFatal,
        Self::LabelExitCountry,
        Self::LabelAnonymityMode,
        Self::LabelTorBootstrap,
        Self::LabelGatewayStatus,
        Self::LabelLatencyBucket,
        Self::LabelKillSwitch,
        Self::LabelBlockedLeaks,
        Self::WarningUdpBlocked,
        Self::WarningHardRotation,
        Self::WarningFailClosed,
        Self::ModeStandardTitle,
        Self::ModeStandardDescription,
        Self::ModeEnhancedTitle,
        Self::ModeEnhancedDescription,
        Self::ModeMaximumTitle,
        Self::ModeMaximumDescription,
        Self::ModeDirectTorTitle,
        Self::ModeDirectTorDescription,
        Self::ErrorInvalidRequest,
        Self::ErrorProtocolIncompatible,
        Self::ErrorNotAuthorized,
        Self::ErrorKillSwitchFailed,
        Self::ErrorTorBootstrapFailed,
        Self::ErrorGatewayUnavailable,
        Self::ErrorRotationRateLimited,
        Self::ErrorDaemonRecovering,
        Self::ErrorGeneric,
        Self::A11yMainStatus,
        Self::A11yNavigation,
        Self::A11yCriticalDialog,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppName => "app.name",
            Self::NavHome => "nav.home",
            Self::NavCountry => "nav.country",
            Self::NavAnonymity => "nav.anonymity",
            Self::NavRoute => "nav.route",
            Self::NavRotation => "nav.rotation",
            Self::NavSplitTunneling => "nav.splitTunneling",
            Self::NavKillSwitch => "nav.killSwitch",
            Self::NavDiagnostics => "nav.diagnostics",
            Self::NavSubscription => "nav.subscription",
            Self::NavSettings => "nav.settings",
            Self::ActionConnect => "action.connect",
            Self::ActionDisconnect => "action.disconnect",
            Self::ActionConfirm => "action.confirm",
            Self::ActionCancel => "action.cancel",
            Self::ActionNewIdentity => "action.newIdentity",
            Self::StatusDisconnected => "status.disconnected",
            Self::StatusPreparing => "status.preparing",
            Self::StatusProtected => "status.protected",
            Self::StatusRotating => "status.rotating",
            Self::StatusDegraded => "status.degraded",
            Self::StatusBlocked => "status.blocked",
            Self::StatusFatal => "status.fatal",
            Self::LabelExitCountry => "label.exitCountry",
            Self::LabelAnonymityMode => "label.anonymityMode",
            Self::LabelTorBootstrap => "label.torBootstrap",
            Self::LabelGatewayStatus => "label.gatewayStatus",
            Self::LabelLatencyBucket => "label.latencyBucket",
            Self::LabelKillSwitch => "label.killSwitch",
            Self::LabelBlockedLeaks => "label.blockedLeaks",
            Self::WarningUdpBlocked => "warning.udpBlocked",
            Self::WarningHardRotation => "warning.hardRotation",
            Self::WarningFailClosed => "warning.failClosed",
            Self::ModeStandardTitle => "mode.standard.title",
            Self::ModeStandardDescription => "mode.standard.description",
            Self::ModeEnhancedTitle => "mode.enhanced.title",
            Self::ModeEnhancedDescription => "mode.enhanced.description",
            Self::ModeMaximumTitle => "mode.maximum.title",
            Self::ModeMaximumDescription => "mode.maximum.description",
            Self::ModeDirectTorTitle => "mode.directTor.title",
            Self::ModeDirectTorDescription => "mode.directTor.description",
            Self::ErrorInvalidRequest => "error.invalidRequest",
            Self::ErrorProtocolIncompatible => "error.protocolIncompatible",
            Self::ErrorNotAuthorized => "error.notAuthorized",
            Self::ErrorKillSwitchFailed => "error.killSwitchFailed",
            Self::ErrorTorBootstrapFailed => "error.torBootstrapFailed",
            Self::ErrorGatewayUnavailable => "error.gatewayUnavailable",
            Self::ErrorRotationRateLimited => "error.rotationRateLimited",
            Self::ErrorDaemonRecovering => "error.daemonRecovering",
            Self::ErrorGeneric => "error.generic",
            Self::A11yMainStatus => "a11y.mainStatus",
            Self::A11yNavigation => "a11y.navigation",
            Self::A11yCriticalDialog => "a11y.criticalDialog",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlSpec {
    pub id: &'static str,
    pub label: StringKey,
    pub accessibility_label: StringKey,
    pub focus_order: u16,
    pub critical: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScreenSpec {
    pub screen: Screen,
    pub title: StringKey,
    pub controls: &'static [ControlSpec],
}

const HOME_CONTROLS: [ControlSpec; 2] = [
    ControlSpec {
        id: "connect",
        label: StringKey::ActionConnect,
        accessibility_label: StringKey::ActionConnect,
        focus_order: 1,
        critical: false,
    },
    ControlSpec {
        id: "disconnect",
        label: StringKey::ActionDisconnect,
        accessibility_label: StringKey::ActionDisconnect,
        focus_order: 2,
        critical: true,
    },
];
const ROTATION_CONTROLS: [ControlSpec; 1] = [ControlSpec {
    id: "new-identity",
    label: StringKey::ActionNewIdentity,
    accessibility_label: StringKey::ActionNewIdentity,
    focus_order: 1,
    critical: true,
}];
const NO_CONTROLS: [ControlSpec; 0] = [];

pub const SCREEN_SPECS: [ScreenSpec; 10] = [
    ScreenSpec {
        screen: Screen::Home,
        title: StringKey::NavHome,
        controls: &HOME_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Country,
        title: StringKey::NavCountry,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Anonymity,
        title: StringKey::NavAnonymity,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Route,
        title: StringKey::NavRoute,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Rotation,
        title: StringKey::NavRotation,
        controls: &ROTATION_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::SplitTunneling,
        title: StringKey::NavSplitTunneling,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::KillSwitch,
        title: StringKey::NavKillSwitch,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Diagnostics,
        title: StringKey::NavDiagnostics,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Subscription,
        title: StringKey::NavSubscription,
        controls: &NO_CONTROLS,
    },
    ScreenSpec {
        screen: Screen::Settings,
        title: StringKey::NavSettings,
        controls: &NO_CONTROLS,
    },
];

#[derive(Clone, Debug, PartialEq)]
pub struct UiState {
    pub screen: Screen,
    pub daemon_connected: bool,
    pub snapshot: Option<StateSnapshot>,
    pub pending_confirmation: Option<PendingConfirmation>,
    pub error: Option<SafeUiError>,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            screen: Screen::Home,
            daemon_connected: false,
            snapshot: None,
            pending_confirmation: None,
            error: None,
        }
    }
}

impl UiState {
    pub fn status_key(&self) -> StringKey {
        let Some(snapshot) = &self.snapshot else {
            return StringKey::StatusPreparing;
        };
        match TunnelPhase::try_from(snapshot.phase).ok() {
            Some(TunnelPhase::Disconnected) => StringKey::StatusDisconnected,
            Some(TunnelPhase::Connected) => StringKey::StatusProtected,
            Some(TunnelPhase::Rotating) => StringKey::StatusRotating,
            Some(TunnelPhase::Degraded) => StringKey::StatusDegraded,
            Some(TunnelPhase::Blocked) => StringKey::StatusBlocked,
            Some(TunnelPhase::FatalError) => StringKey::StatusFatal,
            _ => StringKey::StatusPreparing,
        }
    }

    pub fn apply_snapshot(&mut self, snapshot: StateSnapshot) {
        if self
            .snapshot
            .as_ref()
            .map(|current| current.state_revision < snapshot.state_revision)
            .unwrap_or(true)
        {
            self.snapshot = Some(snapshot);
        }
    }

    /// A closed UI connection changes presentation only. It never creates a
    /// disconnect command and therefore cannot release the daemon kill switch.
    pub fn daemon_connection_lost(&mut self) {
        self.daemon_connected = false;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConfirmation {
    pub action: CriticalAction,
    pub confirmation_id: [u8; 16],
    pub expires_in_seconds: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeUiError {
    pub message: StringKey,
    pub support_code: Option<String>,
}

impl SafeUiError {
    pub fn from_ipc(code: ErrorCode, support_code: &str) -> Self {
        let message = match code {
            ErrorCode::InvalidRequest => StringKey::ErrorInvalidRequest,
            ErrorCode::ProtocolIncompatible => StringKey::ErrorProtocolIncompatible,
            ErrorCode::NotAuthorized => StringKey::ErrorNotAuthorized,
            ErrorCode::KillSwitchFailed => StringKey::ErrorKillSwitchFailed,
            ErrorCode::TorBootstrapFailed => StringKey::ErrorTorBootstrapFailed,
            ErrorCode::GatewayUnavailable => StringKey::ErrorGatewayUnavailable,
            ErrorCode::RotationRateLimited => StringKey::ErrorRotationRateLimited,
            ErrorCode::DaemonRecovering => StringKey::ErrorDaemonRecovering,
            _ => StringKey::ErrorGeneric,
        };
        let support_code = (!support_code.is_empty()
            && support_code.len() <= 16
            && support_code.is_ascii()
            && support_code
                .chars()
                .all(|value| value.is_ascii_alphanumeric()))
        .then(|| support_code.to_owned());
        Self {
            message,
            support_code,
        }
    }
}

pub fn get_state_request() -> Request {
    Request {
        confirmation_id: Vec::new(),
        command: Some(request::Command::GetState(GetStateRequest {})),
    }
}

pub fn connect_request() -> Request {
    Request {
        confirmation_id: Vec::new(),
        command: Some(request::Command::Connect(ConnectRequest {})),
    }
}

pub fn disconnect_request(keep_kill_switch: bool, confirmation: Option<[u8; 16]>) -> Request {
    Request {
        confirmation_id: confirmation.map(Vec::from).unwrap_or_default(),
        command: Some(request::Command::Disconnect(DisconnectRequest {
            keep_kill_switch,
        })),
    }
}

pub fn hard_rotation_request(confirmation: Option<[u8; 16]>) -> Request {
    Request {
        confirmation_id: confirmation.map(Vec::from).unwrap_or_default(),
        command: Some(request::Command::Rotate(RotateRequest {
            kind: RotationKind::HardNewIdentity as i32,
        })),
    }
}

pub fn set_kill_switch_request(enabled: bool, confirmation: Option<[u8; 16]>) -> Request {
    Request {
        confirmation_id: confirmation.map(Vec::from).unwrap_or_default(),
        command: Some(request::Command::SetKillSwitch(SetKillSwitchRequest {
            enabled,
        })),
    }
}

pub fn mode_copy(mode: AnonymityMode) -> (StringKey, StringKey) {
    match mode {
        AnonymityMode::Standard => (
            StringKey::ModeStandardTitle,
            StringKey::ModeStandardDescription,
        ),
        AnonymityMode::Enhanced => (
            StringKey::ModeEnhancedTitle,
            StringKey::ModeEnhancedDescription,
        ),
        AnonymityMode::Maximum => (
            StringKey::ModeMaximumTitle,
            StringKey::ModeMaximumDescription,
        ),
        AnonymityMode::DirectTor => (
            StringKey::ModeDirectTorTitle,
            StringKey::ModeDirectTorDescription,
        ),
        AnonymityMode::Unspecified => (StringKey::ErrorGeneric, StringKey::ErrorGeneric),
    }
}
