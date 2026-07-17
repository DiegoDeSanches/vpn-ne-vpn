#![cfg(target_os = "linux")]

use std::{
    os::{fd::{AsRawFd, OwnedFd}, unix::fs::MetadataExt},
    path::Path,
    sync::{Arc, Mutex},
};

use gtk::prelude::*;
use nix::sys::socket::{
    connect, getsockopt, recv, send, socket, sockopt::PeerCredentials, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use onionroute_desktop_ipc::{
    decode_frame, encode_frame,
    v1::{
        envelope, request, ClientHello, ConnectRequest, Envelope, EventTopic, GetStateRequest,
        ProtocolVersion, ProtocolVersionRange, Request, SubscribeRequest,
    },
    IPC_V1,
};

const SOCKET_PATH: &str = "/run/onionroute/control-v1.sock";
const DAEMON_PATH: &str = "/usr/libexec/onionroute-desktop-daemon";

fn main() {
    let application = gtk::Application::builder()
        .application_id("com.onionroute.desktop")
        .flags(gtk::gio::ApplicationFlags::NON_UNIQUE)
        .build();
    application.connect_activate(build_ui);
    application.run();
}

fn build_ui(application: &gtk::Application) {
    let builder = gtk::Builder::from_string(include_str!("../ui/main.ui"));
    let window: gtk::ApplicationWindow = builder.object("window").expect("window exists");
    window.set_application(Some(application));

    let client: Arc<Mutex<Option<IpcClient>>> = Arc::new(Mutex::new(None));
    let reconnect_client = client.clone();
    std::thread::spawn(move || {
        // The reconnect owner never sends Disconnect when the GTK window exits.
        let mut delay = std::time::Duration::from_millis(250);
        loop {
            if let Ok(mut connection) = IpcClient::connect_and_authenticate() {
                if connection.hello_and_subscribe().is_ok() {
                    *reconnect_client.lock().expect("IPC mutex") = Some(connection);
                    break;
                }
            }
            std::thread::sleep(delay);
            delay = std::cmp::min(delay.saturating_mul(2), std::time::Duration::from_secs(5));
        }
    });

    let connect_button: gtk::Button = builder.object("connect_button").expect("connect button");
    connect_button.connect_clicked(move |_| {
        if let Some(connection) = client.lock().expect("IPC mutex").as_mut() {
            let _ = connection.command(request::Command::Connect(ConnectRequest {}));
        }
    });
    window.present();
}

struct IpcClient {
    socket: OwnedFd,
    sequence: u64,
}

impl IpcClient {
    fn connect_and_authenticate() -> Result<Self, String> {
        let socket = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|_| "local IPC unavailable")?;
        let address = UnixAddr::new(Path::new(SOCKET_PATH)).map_err(|_| "invalid IPC address")?;
        connect(socket.as_raw_fd(), &address).map_err(|_| "local IPC unavailable")?;
        let credentials = getsockopt(&socket, PeerCredentials).map_err(|_| "peer credentials unavailable")?;
        if credentials.uid() != 0 || credentials.pid() <= 0 {
            return Err("daemon is not root-owned".into());
        }
        let executable = std::fs::read_link(format!("/proc/{}/exe", credentials.pid()))
            .map_err(|_| "daemon executable unavailable")?;
        let metadata = std::fs::metadata(&executable).map_err(|_| "daemon metadata unavailable")?;
        if executable != Path::new(DAEMON_PATH)
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("daemon executable identity rejected".into());
        }
        Ok(Self { socket, sequence: 0 })
    }

    fn hello_and_subscribe(&mut self) -> Result<(), String> {
        let mut nonce = vec![0_u8; 32];
        getrandom(&mut nonce)?;
        self.exchange(envelope::Body::ClientHello(ClientHello {
            supported_versions: Some(ProtocolVersionRange {
                minimum: Some(IPC_V1),
                maximum: Some(IPC_V1),
            }),
            process_nonce: nonce,
            requested_topics: vec![
                EventTopic::TunnelState as i32,
                EventTopic::LeakProtection as i32,
                EventTopic::Diagnostics as i32,
            ],
            event_window: 64,
        }))?;
        self.command(request::Command::Subscribe(SubscribeRequest {
            topics: vec![EventTopic::TunnelState as i32, EventTopic::LeakProtection as i32],
            event_window: 64,
        }))?;
        self.command(request::Command::GetState(GetStateRequest {}))?;
        Ok(())
    }

    fn command(&mut self, command: request::Command) -> Result<Envelope, String> {
        self.exchange(envelope::Body::Request(Request {
            confirmation_id: Vec::new(),
            command: Some(command),
        }))
    }

    fn exchange(&mut self, body: envelope::Body) -> Result<Envelope, String> {
        self.sequence = self.sequence.checked_add(1).ok_or("IPC sequence exhausted")?;
        let mut request_id = vec![0_u8; 16];
        getrandom(&mut request_id)?;
        let frame = encode_frame(&Envelope {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            request_id,
            sequence: self.sequence,
            body: Some(body),
        })
        .map_err(|_| "invalid IPC request")?;
        send(self.socket.as_raw_fd(), &frame, MsgFlags::MSG_NOSIGNAL)
            .map_err(|_| "IPC write failed")?;
        let mut response = vec![0_u8; 65_540];
        let length = recv(self.socket.as_raw_fd(), &mut response, MsgFlags::empty())
            .map_err(|_| "IPC read failed")?;
        response.truncate(length);
        decode_frame(&response).map_err(|_| "invalid IPC response".into())
    }
}

fn getrandom(bytes: &mut [u8]) -> Result<(), String> {
    let mut source = std::fs::File::open("/dev/urandom").map_err(|_| "OS randomness unavailable")?;
    std::io::Read::read_exact(&mut source, bytes).map_err(|_| "OS randomness unavailable")
}
