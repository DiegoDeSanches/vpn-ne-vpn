use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use thiserror::Error;

use crate::{v1::Envelope, validate_envelope, ValidationError};

/// Maximum encoded protobuf payload. The four-byte prefix is not included.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("incomplete frame")]
    Incomplete,
    #[error("desktop IPC frame exceeds the hard limit")]
    TooLarge,
    #[error("desktop IPC frame has trailing bytes")]
    TrailingBytes,
    #[error("desktop IPC protobuf is malformed")]
    Decode,
    #[error(transparent)]
    Invalid(#[from] ValidationError),
}

pub fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, FrameError> {
    validate_envelope(envelope)?;
    let encoded_len = envelope.encoded_len();
    if encoded_len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut output = BytesMut::with_capacity(4 + encoded_len);
    output.put_u32(encoded_len as u32);
    envelope
        .encode(&mut output)
        .map_err(|_| FrameError::Decode)?;
    Ok(output.to_vec())
}

/// Decodes exactly one length-prefixed frame. The prefix is checked before any
/// protobuf allocation and extra bytes are rejected.
pub fn decode_frame(input: &[u8]) -> Result<Envelope, FrameError> {
    if input.len() < 4 {
        return Err(FrameError::Incomplete);
    }
    let mut prefix = &input[..4];
    let len = prefix.get_u32() as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let total = 4usize.checked_add(len).ok_or(FrameError::TooLarge)?;
    if input.len() < total {
        return Err(FrameError::Incomplete);
    }
    if input.len() != total {
        return Err(FrameError::TrailingBytes);
    }
    let envelope = Envelope::decode(&input[4..]).map_err(|_| FrameError::Decode)?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}
