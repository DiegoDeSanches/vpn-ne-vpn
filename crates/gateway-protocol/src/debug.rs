use std::fmt;

use crate::framing::FrameDecoder;
use crate::proto::destination::Value as DestinationValue;
use crate::proto::gateway_frame::Body;
use crate::proto::GatewayFrame;
use crate::Result;

/// Payload-safe, destination-safe equivalent of a Wireshark packet-list row.
/// It stores lengths and coarse kinds only, never bytes, hostnames, addresses,
/// tokens, nonces, session IDs, or correlation IDs.
#[derive(Clone, Eq, PartialEq)]
pub struct FrameSummary {
    pub sequence: u64,
    pub message: &'static str,
    pub stream_id: Option<u64>,
    pub sensitive_length: Option<usize>,
    pub detail: &'static str,
}

impl fmt::Debug for FrameSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameSummary")
            .field("sequence", &self.sequence)
            .field("message", &self.message)
            .field("stream_id", &self.stream_id)
            .field("sensitive_length", &self.sensitive_length)
            .field("detail", &self.detail)
            .finish()
    }
}

impl fmt::Display for FrameSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "seq={} type={}", self.sequence, self.message)?;
        if let Some(stream_id) = self.stream_id {
            write!(formatter, " stream={stream_id}")?;
        }
        if let Some(length) = self.sensitive_length {
            write!(formatter, " sensitive_bytes={length}")?;
        }
        if !self.detail.is_empty() {
            write!(formatter, " detail={}", self.detail)?;
        }
        Ok(())
    }
}

impl FrameSummary {
    pub fn from_frame(frame: &GatewayFrame) -> Self {
        let (message, stream_id, sensitive_length, detail) = match frame.body.as_ref() {
            Some(Body::ClientHello(message)) => (
                "ClientHello",
                None,
                Some(message.session_nonce.len()),
                "values-redacted",
            ),
            Some(Body::ServerHello(message)) => (
                "ServerHello",
                None,
                Some(
                    message
                        .server_nonce
                        .len()
                        .saturating_add(message.ephemeral_session_id.len()),
                ),
                "values-redacted",
            ),
            Some(Body::Authenticate(message)) => (
                "Authenticate",
                None,
                Some(
                    message
                        .anonymous_capability_token
                        .len()
                        .saturating_add(message.proof_of_possession.len()),
                ),
                "credentials-redacted",
            ),
            Some(Body::AuthenticationResult(_)) => {
                ("AuthenticationResult", None, None, "values-redacted")
            }
            Some(Body::OpenTcpStream(message)) => {
                let detail = match message
                    .destination
                    .as_ref()
                    .and_then(|destination| destination.value.as_ref())
                {
                    Some(DestinationValue::Hostname(_)) => "hostname-redacted",
                    Some(DestinationValue::IpAddress(_)) => "ip-redacted",
                    None => "destination-missing",
                };
                ("OpenTcpStream", Some(message.stream_id), None, detail)
            }
            Some(Body::TcpStreamOpened(message)) => {
                ("TcpStreamOpened", Some(message.stream_id), None, "")
            }
            Some(Body::TcpStreamRejected(message)) => {
                ("TcpStreamRejected", Some(message.stream_id), None, "")
            }
            Some(Body::Data(message)) => (
                "Data",
                Some(message.stream_id),
                Some(message.payload.len()),
                "payload-redacted",
            ),
            Some(Body::WindowUpdate(message)) => (
                "WindowUpdate",
                (message.stream_id != 0).then_some(message.stream_id),
                None,
                if message.stream_id == 0 {
                    "connection"
                } else {
                    "stream"
                },
            ),
            Some(Body::HalfClose(message)) => ("HalfClose", Some(message.stream_id), None, ""),
            Some(Body::CloseStream(message)) => ("CloseStream", Some(message.stream_id), None, ""),
            Some(Body::ResolveDomain(_)) => ("ResolveDomain", None, None, "hostname-redacted"),
            Some(Body::ResolveResult(message)) => (
                "ResolveResult",
                None,
                Some(message.ip_addresses.iter().map(Vec::len).sum()),
                "addresses-redacted",
            ),
            Some(Body::RotateSession(_)) => ("RotateSession", None, None, "nonce-redacted"),
            Some(Body::SessionRotated(_)) => ("SessionRotated", None, None, "nonce-redacted"),
            Some(Body::Ping(_)) => ("Ping", None, None, "nonce-redacted"),
            Some(Body::Pong(_)) => ("Pong", None, None, "nonce-redacted"),
            Some(Body::Error(message)) => (
                "Error",
                (message.stream_id != 0).then_some(message.stream_id),
                None,
                "correlation-redacted",
            ),
            Some(Body::GoAway(_)) => ("GoAway", None, None, ""),
            None => ("Unknown", None, None, "body-missing"),
        };
        Self {
            sequence: frame.sequence,
            message,
            stream_id,
            sensitive_length,
            detail,
        }
    }
}

/// Incremental debug decoder that immediately discards the decoded wire value
/// after producing a redacted summary.
pub struct DebugDecoder {
    inner: FrameDecoder,
}

impl DebugDecoder {
    pub fn new(maximum_frame_size: usize) -> Result<Self> {
        Ok(Self {
            inner: FrameDecoder::new(maximum_frame_size)?,
        })
    }

    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<FrameSummary>)> {
        let progress = self.inner.push(input)?;
        Ok((
            progress.consumed,
            progress.frame.as_ref().map(FrameSummary::from_frame),
        ))
    }
}
