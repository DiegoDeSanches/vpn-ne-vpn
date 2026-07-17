//! Prost adapter for `proto/common/v1` and `proto/gateway/v1`.
//!
//! This file mirrors the protected contract because build-time code generation
//! would pull an Edition 2024 dependency incompatible with the repository MSRV.

pub mod onionroute {
    pub mod common {
        pub mod v1 {
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ProtocolVersion {
                #[prost(uint32, tag = "1")]
                pub major: u32,
                #[prost(uint32, tag = "2")]
                pub minor: u32,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ProtocolVersionRange {
                #[prost(message, optional, tag = "1")]
                pub minimum: Option<ProtocolVersion>,
                #[prost(message, optional, tag = "2")]
                pub maximum: Option<ProtocolVersion>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct UnixTimestamp {
                #[prost(int64, tag = "1")]
                pub seconds: i64,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ErrorStatus {
                #[prost(string, tag = "1")]
                pub code: String,
                #[prost(enumeration = "ErrorCategory", tag = "2")]
                pub category: i32,
                #[prost(enumeration = "RetryHint", tag = "3")]
                pub retry_hint: i32,
                #[prost(bytes = "vec", tag = "4")]
                pub correlation_id: Vec<u8>,
            }

            #[derive(
                Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
            )]
            #[repr(i32)]
            pub enum ErrorCategory {
                Unspecified = 0,
                InvalidInput = 1,
                Unsupported = 2,
                Unavailable = 3,
                Authentication = 4,
                Policy = 5,
                Protocol = 6,
                ResourceExhausted = 7,
                Internal = 8,
            }

            #[derive(
                Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
            )]
            #[repr(i32)]
            pub enum RetryHint {
                Unspecified = 0,
                Never = 1,
                Immediate = 2,
                Backoff = 3,
                AfterDirectoryRefresh = 4,
                AfterTokenRefresh = 5,
                UserActionRequired = 6,
            }
        }
    }

    pub mod gateway {
        pub mod v1 {
            use super::super::common::v1::{
                ErrorStatus, ProtocolVersion, ProtocolVersionRange, UnixTimestamp,
            };

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct GatewayFrame {
                #[prost(message, optional, tag = "1")]
                pub version: Option<ProtocolVersion>,
                #[prost(bytes = "vec", tag = "2")]
                pub session_id: Vec<u8>,
                #[prost(uint64, tag = "3")]
                pub sequence: u64,
                #[prost(
                    oneof = "gateway_frame::Body",
                    tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27"
                )]
                pub body: Option<gateway_frame::Body>,
            }

            pub mod gateway_frame {
                #[derive(Clone, PartialEq, ::prost::Oneof)]
                pub enum Body {
                    #[prost(message, tag = "10")]
                    ClientHello(super::ClientHello),
                    #[prost(message, tag = "11")]
                    ServerHello(super::ServerHello),
                    #[prost(message, tag = "12")]
                    AuthenticateRequest(super::AuthenticateRequest),
                    #[prost(message, tag = "13")]
                    AuthenticateResponse(super::AuthenticateResponse),
                    #[prost(message, tag = "14")]
                    OpenTcpRequest(super::OpenTcpRequest),
                    #[prost(message, tag = "15")]
                    OpenTcpResponse(super::OpenTcpResponse),
                    #[prost(message, tag = "16")]
                    DnsQuery(super::DnsQuery),
                    #[prost(message, tag = "17")]
                    DnsResponse(super::DnsResponse),
                    #[prost(message, tag = "18")]
                    Data(super::Data),
                    #[prost(message, tag = "19")]
                    WindowUpdate(super::WindowUpdate),
                    #[prost(message, tag = "20")]
                    HalfClose(super::HalfClose),
                    #[prost(message, tag = "21")]
                    ResetStream(super::ResetStream),
                    #[prost(message, tag = "22")]
                    Ping(super::Ping),
                    #[prost(message, tag = "23")]
                    Pong(super::Pong),
                    #[prost(message, tag = "24")]
                    GoAway(super::GoAway),
                    #[prost(message, tag = "25")]
                    Error(super::ErrorStatus),
                    #[prost(message, tag = "26")]
                    OpenRelayRequest(super::OpenRelayRequest),
                    #[prost(message, tag = "27")]
                    OpenRelayResponse(super::OpenRelayResponse),
                }
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ClientHello {
                #[prost(message, optional, tag = "1")]
                pub supported_versions: Option<ProtocolVersionRange>,
                #[prost(bytes = "vec", tag = "2")]
                pub client_nonce: Vec<u8>,
                #[prost(enumeration = "RouteMode", tag = "3")]
                pub route_mode: i32,
                #[prost(string, repeated, tag = "4")]
                pub requested_features: Vec<String>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ServerHello {
                #[prost(message, optional, tag = "1")]
                pub selected_version: Option<ProtocolVersion>,
                #[prost(bytes = "vec", tag = "2")]
                pub server_nonce: Vec<u8>,
                #[prost(bytes = "vec", tag = "3")]
                pub ephemeral_session_id: Vec<u8>,
                #[prost(string, repeated, tag = "4")]
                pub enabled_features: Vec<String>,
                #[prost(uint32, tag = "5")]
                pub initial_stream_window: u32,
                #[prost(uint32, tag = "6")]
                pub max_concurrent_streams: u32,
                #[prost(uint32, tag = "7")]
                pub session_ttl_seconds: u32,
                #[prost(string, tag = "8")]
                pub gateway_id: String,
                #[prost(enumeration = "SessionRole", tag = "9")]
                pub session_role: i32,
            }

            #[derive(
                Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
            )]
            #[repr(i32)]
            pub enum SessionRole {
                Unspecified = 0,
                Entry = 1,
                Relay = 2,
                Exit = 3,
            }

            #[derive(
                Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
            )]
            #[repr(i32)]
            pub enum RouteMode {
                Unspecified = 0,
                Standard = 1,
                Enhanced = 2,
                Maximum = 3,
                DirectTor = 4,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct AuthenticateRequest {
                #[prost(bytes = "vec", tag = "1")]
                pub capability_token: Vec<u8>,
                #[prost(bytes = "vec", tag = "2")]
                pub proof_of_possession: Vec<u8>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct AuthenticateResponse {
                #[prost(bool, tag = "1")]
                pub accepted: bool,
                #[prost(message, optional, tag = "2")]
                pub expires_at: Option<UnixTimestamp>,
                #[prost(string, repeated, tag = "3")]
                pub granted_capabilities: Vec<String>,
                #[prost(message, optional, tag = "4")]
                pub error: Option<ErrorStatus>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct OpenTcpRequest {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(message, optional, tag = "2")]
                pub destination: Option<Destination>,
                #[prost(uint32, tag = "3")]
                pub port: u32,
                #[prost(uint32, tag = "4")]
                pub initial_window: u32,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Destination {
                #[prost(oneof = "destination::Value", tags = "1, 2")]
                pub value: Option<destination::Value>,
            }

            pub mod destination {
                #[derive(Clone, PartialEq, ::prost::Oneof)]
                pub enum Value {
                    #[prost(string, tag = "1")]
                    Hostname(String),
                    #[prost(bytes, tag = "2")]
                    IpAddress(Vec<u8>),
                }
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct OpenTcpResponse {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(bool, tag = "2")]
                pub opened: bool,
                #[prost(message, optional, tag = "3")]
                pub error: Option<ErrorStatus>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct OpenRelayRequest {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(string, tag = "2")]
                pub next_gateway_id: String,
                #[prost(enumeration = "NextHopRole", tag = "3")]
                pub next_hop_role: i32,
                #[prost(uint32, tag = "4")]
                pub initial_window: u32,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct OpenRelayResponse {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(bool, tag = "2")]
                pub opened: bool,
                #[prost(message, optional, tag = "3")]
                pub error: Option<ErrorStatus>,
            }

            #[derive(
                Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration,
            )]
            #[repr(i32)]
            pub enum NextHopRole {
                Unspecified = 0,
                Relay = 1,
                Exit = 2,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct DnsQuery {
                #[prost(uint64, tag = "1")]
                pub query_id: u64,
                #[prost(bytes = "vec", tag = "2")]
                pub wire_query: Vec<u8>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct DnsResponse {
                #[prost(uint64, tag = "1")]
                pub query_id: u64,
                #[prost(bytes = "vec", tag = "2")]
                pub wire_response: Vec<u8>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Data {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(bytes = "vec", tag = "2")]
                pub payload: Vec<u8>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct WindowUpdate {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(uint32, tag = "2")]
                pub credit: u32,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct HalfClose {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ResetStream {
                #[prost(uint64, tag = "1")]
                pub stream_id: u64,
                #[prost(message, optional, tag = "2")]
                pub reason: Option<ErrorStatus>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Ping {
                #[prost(bytes = "vec", tag = "1")]
                pub nonce: Vec<u8>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Pong {
                #[prost(bytes = "vec", tag = "1")]
                pub nonce: Vec<u8>,
            }

            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct GoAway {
                #[prost(uint64, tag = "1")]
                pub last_accepted_stream_id: u64,
                #[prost(message, optional, tag = "2")]
                pub reason: Option<ErrorStatus>,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::onionroute::common::v1::ProtocolVersion;
    use super::onionroute::gateway::v1::gateway_frame::Body;
    use super::onionroute::gateway::v1::{GatewayFrame, Ping};

    #[test]
    fn gateway_frame_tags_match_v1_golden_bytes() {
        let frame = GatewayFrame {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            session_id: Vec::new(),
            sequence: 1,
            body: Some(Body::Ping(Ping { nonce: vec![0xaa] })),
        };
        assert_eq!(
            frame.encode_to_vec(),
            vec![0x0a, 0x02, 0x08, 0x01, 0x18, 0x01, 0xb2, 0x01, 0x03, 0x0a, 0x01, 0xaa,]
        );
    }
}
