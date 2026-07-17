use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Stable, redacted errors. No variant stores a destination, credential,
/// session payload, source address, account identifier, or peer-supplied text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    InvalidConfiguration,
    InvalidIdentity,
    WrongRole,
    Revoked,
    ProtocolIncompatible,
    ProtocolViolation,
    ReplayDetected,
    AuthenticationRejected,
    PolicyDenied,
    ResourceExhausted,
    Backpressure,
    Draining,
    Timeout,
    TransportFailure,
    Closed,
    Internal,
}

#[derive(Debug, Error)]
#[error("enhanced transport failed: {code:?}")]
pub struct Error {
    pub code: ErrorCode,
}

impl Error {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::new(ErrorCode::TransportFailure)
    }
}

impl From<prost::EncodeError> for Error {
    fn from(_: prost::EncodeError) -> Self {
        Self::new(ErrorCode::ProtocolViolation)
    }
}

impl From<prost::DecodeError> for Error {
    fn from(_: prost::DecodeError) -> Self {
        Self::new(ErrorCode::ProtocolViolation)
    }
}

impl From<rustls::Error> for Error {
    fn from(_: rustls::Error) -> Self {
        Self::new(ErrorCode::InvalidIdentity)
    }
}

impl From<onionroute_gateway_protocol::ProtocolError> for Error {
    fn from(error: onionroute_gateway_protocol::ProtocolError) -> Self {
        use onionroute_gateway_protocol::ProtocolError;
        let code = match error {
            ProtocolError::Backpressure => ErrorCode::Backpressure,
            ProtocolError::StreamLimit => ErrorCode::ResourceExhausted,
            ProtocolError::IncompatibleVersion | ProtocolError::SilentDowngrade => {
                ErrorCode::ProtocolIncompatible
            }
            ProtocolError::HandshakeTimeout | ProtocolError::IdleTimeout => ErrorCode::Timeout,
            ProtocolError::Closed => ErrorCode::Closed,
            ProtocolError::Io(_) => ErrorCode::TransportFailure,
            _ => ErrorCode::ProtocolViolation,
        };
        Self::new(code)
    }
}
