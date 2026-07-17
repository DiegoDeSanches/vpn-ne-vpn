use thiserror::Error;

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Redacted protocol errors. Variants never retain payloads, destinations,
/// tokens, session IDs, or peer-supplied free-form strings.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("transport I/O failed")]
    Io(#[source] std::io::Error),
    #[error("protobuf encoding failed")]
    Encode(#[from] prost::EncodeError),
    #[error("protobuf decoding failed")]
    Decode(#[from] prost::DecodeError),
    #[error("announced frame length {announced} exceeds limit {maximum}")]
    FrameTooLarge { announced: usize, maximum: usize },
    #[error("zero-length frame is forbidden")]
    EmptyFrame,
    #[error("invalid or overflowing length prefix")]
    InvalidLengthPrefix,
    #[error("non-canonical varint encoding")]
    NonCanonicalVarint,
    #[error("truncated protobuf wire value")]
    TruncatedWireValue,
    #[error("duplicate singular protobuf field {0}")]
    DuplicateField(u32),
    #[error("unknown gateway message tag {0}")]
    UnknownMessageTag(u32),
    #[error("gateway frame body is missing")]
    MissingBody,
    #[error("required field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("protocol invariant violated: {0}")]
    ProtocolViolation(&'static str),
    #[error("peers have no permitted common protocol version")]
    IncompatibleVersion,
    #[error("server attempted a silent or non-maximal downgrade")]
    SilentDowngrade,
    #[error("frame sequence is invalid")]
    InvalidSequence,
    #[error("ephemeral session binding is invalid")]
    InvalidSession,
    #[error("bounded outbound queue is full")]
    Backpressure,
    #[error("maximum concurrent stream count reached")]
    StreamLimit,
    #[error("logical stream ID is invalid or reused")]
    InvalidStreamId,
    #[error("flow-control credit was exceeded")]
    FlowControlViolation,
    #[error("integer overflow was prevented")]
    IntegerOverflow,
    #[error("gateway handshake timed out")]
    HandshakeTimeout,
    #[error("logical stream idle timeout expired")]
    IdleTimeout,
    #[error("anonymous authentication was rejected")]
    AuthenticationRejected,
    #[error("session is closing or closed")]
    Closed,
    #[error("operating-system entropy unavailable")]
    EntropyUnavailable,
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
