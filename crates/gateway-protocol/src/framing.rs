use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::ABSOLUTE_MAX_FRAME_SIZE;
use crate::proto::GatewayFrame;
use crate::{ProtocolError, Result};

const MAX_U32_VARINT_BYTES: usize = 5;
const FIRST_MESSAGE_TAG: u32 = 10;
const LAST_V1_MESSAGE_TAG: u32 = 28;
const LAST_RESERVED_MESSAGE_TAG: u32 = 63;

#[derive(Debug)]
pub struct DecodeProgress {
    pub consumed: usize,
    pub frame: Option<GatewayFrame>,
}

/// Incremental, single-frame decoder. It never buffers more than the negotiated
/// frame maximum and never queues decoded frames internally.
#[derive(Debug)]
pub struct FrameDecoder {
    maximum_frame_size: usize,
    prefix: [u8; MAX_U32_VARINT_BYTES],
    prefix_len: usize,
    expected_body: Option<usize>,
    body: Vec<u8>,
}

impl FrameDecoder {
    pub fn new(maximum_frame_size: usize) -> Result<Self> {
        validate_maximum(maximum_frame_size)?;
        Ok(Self {
            maximum_frame_size,
            prefix: [0; MAX_U32_VARINT_BYTES],
            prefix_len: 0,
            expected_body: None,
            body: Vec::new(),
        })
    }

    pub fn set_maximum_frame_size(&mut self, maximum_frame_size: usize) -> Result<()> {
        validate_maximum(maximum_frame_size)?;
        if let Some(expected) = self.expected_body {
            if expected > maximum_frame_size {
                return Err(ProtocolError::FrameTooLarge {
                    announced: expected,
                    maximum: maximum_frame_size,
                });
            }
        }
        self.maximum_frame_size = maximum_frame_size;
        Ok(())
    }

    pub fn buffered_bytes(&self) -> usize {
        self.prefix_len.saturating_add(self.body.len())
    }

    pub fn push(&mut self, input: &[u8]) -> Result<DecodeProgress> {
        let mut consumed = 0usize;

        while self.expected_body.is_none() && consumed < input.len() {
            if self.prefix_len == MAX_U32_VARINT_BYTES {
                self.reset();
                return Err(ProtocolError::InvalidLengthPrefix);
            }
            let byte = input[consumed];
            self.prefix[self.prefix_len] = byte;
            self.prefix_len += 1;
            consumed += 1;
            if byte & 0x80 == 0 {
                let length = match decode_canonical_u32_varint(&self.prefix[..self.prefix_len]) {
                    Ok(length) => length as usize,
                    Err(error) => {
                        self.reset();
                        return Err(error);
                    }
                };
                if length == 0 {
                    self.reset();
                    return Err(ProtocolError::EmptyFrame);
                }
                if length > self.maximum_frame_size {
                    self.reset();
                    return Err(ProtocolError::FrameTooLarge {
                        announced: length,
                        maximum: self.maximum_frame_size,
                    });
                }
                self.body = Vec::with_capacity(length);
                self.expected_body = Some(length);
            }
        }

        if let Some(expected) = self.expected_body {
            let remaining = expected.saturating_sub(self.body.len());
            let available = input.len().saturating_sub(consumed);
            let take = remaining.min(available);
            self.body
                .extend_from_slice(&input[consumed..consumed + take]);
            consumed += take;

            if self.body.len() == expected {
                let bytes = std::mem::take(&mut self.body);
                self.reset();
                let frame = decode_frame_bytes(&bytes)?;
                return Ok(DecodeProgress {
                    consumed,
                    frame: Some(frame),
                });
            }
        }

        Ok(DecodeProgress {
            consumed,
            frame: None,
        })
    }

    fn reset(&mut self) {
        self.prefix = [0; MAX_U32_VARINT_BYTES];
        self.prefix_len = 0;
        self.expected_body = None;
        self.body.clear();
    }
}

pub fn encode_frame(frame: &GatewayFrame, maximum_frame_size: usize) -> Result<Vec<u8>> {
    validate_maximum(maximum_frame_size)?;
    let length = frame.encoded_len();
    if length == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if length > maximum_frame_size {
        return Err(ProtocolError::FrameTooLarge {
            announced: length,
            maximum: maximum_frame_size,
        });
    }
    let length_u32 = u32::try_from(length).map_err(|_| ProtocolError::IntegerOverflow)?;
    let mut encoded = Vec::with_capacity(length.saturating_add(MAX_U32_VARINT_BYTES));
    encode_u32_varint(length_u32, &mut encoded);
    frame.encode(&mut encoded)?;
    Ok(encoded)
}

pub async fn write_frame<W>(
    writer: &mut W,
    frame: &GatewayFrame,
    maximum_frame_size: usize,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame(frame, maximum_frame_size)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R, maximum_frame_size: usize) -> Result<GatewayFrame>
where
    R: AsyncRead + Unpin,
{
    validate_maximum(maximum_frame_size)?;
    let mut prefix = [0u8; MAX_U32_VARINT_BYTES];
    let mut prefix_len = 0usize;
    loop {
        if prefix_len == prefix.len() {
            return Err(ProtocolError::InvalidLengthPrefix);
        }
        reader
            .read_exact(&mut prefix[prefix_len..prefix_len + 1])
            .await?;
        let byte = prefix[prefix_len];
        prefix_len += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let length = decode_canonical_u32_varint(&prefix[..prefix_len])? as usize;
    if length == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if length > maximum_frame_size {
        return Err(ProtocolError::FrameTooLarge {
            announced: length,
            maximum: maximum_frame_size,
        });
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    decode_frame_bytes(&body)
}

pub fn decode_frame_bytes(bytes: &[u8]) -> Result<GatewayFrame> {
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if bytes.len() > ABSOLUTE_MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            announced: bytes.len(),
            maximum: ABSOLUTE_MAX_FRAME_SIZE,
        });
    }
    scan_gateway_envelope(bytes)?;
    let frame = GatewayFrame::decode(bytes)?;
    if frame.body.is_none() {
        return Err(ProtocolError::MissingBody);
    }
    Ok(frame)
}

fn validate_maximum(maximum_frame_size: usize) -> Result<()> {
    if maximum_frame_size == 0 || maximum_frame_size > ABSOLUTE_MAX_FRAME_SIZE {
        return Err(ProtocolError::InvalidField("maximum_frame_size"));
    }
    Ok(())
}

fn encode_u32_varint(mut value: u32, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_canonical_u32_varint(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() || bytes.len() > MAX_U32_VARINT_BYTES {
        return Err(ProtocolError::InvalidLengthPrefix);
    }
    let mut value = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let bits = u32::from(byte & 0x7f);
        if index == 4 && bits > 0x0f {
            return Err(ProtocolError::InvalidLengthPrefix);
        }
        value |= bits << (index * 7);
        if byte & 0x80 == 0 {
            if index + 1 != bytes.len() {
                return Err(ProtocolError::InvalidLengthPrefix);
            }
            let minimum = if index == 0 { 0 } else { 1u32 << (index * 7) };
            if value < minimum {
                return Err(ProtocolError::NonCanonicalVarint);
            }
            return Ok(value);
        }
    }
    Err(ProtocolError::InvalidLengthPrefix)
}

fn scan_gateway_envelope(bytes: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    let mut seen = [false; (LAST_V1_MESSAGE_TAG as usize) + 1];
    let mut body_tag = None;

    while offset < bytes.len() {
        let key = read_wire_varint(bytes, &mut offset)?;
        let tag = u32::try_from(key >> 3).map_err(|_| ProtocolError::IntegerOverflow)?;
        let wire_type = (key & 0x07) as u8;
        if tag == 0 {
            return Err(ProtocolError::ProtocolViolation("protobuf tag zero"));
        }

        let expected_wire_type = match tag {
            1 => Some(0),
            2 | 4 | FIRST_MESSAGE_TAG..=LAST_V1_MESSAGE_TAG => Some(2),
            3 => None,
            5..=9 => return Err(ProtocolError::ProtocolViolation("reserved envelope field")),
            29..=LAST_RESERVED_MESSAGE_TAG => {
                return Err(ProtocolError::UnknownMessageTag(tag));
            }
            _ => None,
        };
        if let Some(expected) = expected_wire_type {
            if wire_type != expected {
                return Err(ProtocolError::ProtocolViolation(
                    "invalid envelope wire type",
                ));
            }
        }

        if tag <= LAST_V1_MESSAGE_TAG && tag != 3 {
            let slot = &mut seen[tag as usize];
            if *slot {
                return Err(ProtocolError::DuplicateField(tag));
            }
            *slot = true;
        }
        if (FIRST_MESSAGE_TAG..=LAST_V1_MESSAGE_TAG).contains(&tag)
            && body_tag.replace(tag).is_some()
        {
            return Err(ProtocolError::ProtocolViolation("multiple frame bodies"));
        }
        skip_wire_value(bytes, &mut offset, wire_type)?;
    }
    Ok(())
}

fn read_wire_varint(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let start = *offset;
    let mut value = 0u64;
    for index in 0..10usize {
        let byte = *bytes
            .get(*offset)
            .ok_or(ProtocolError::TruncatedWireValue)?;
        *offset = (*offset)
            .checked_add(1)
            .ok_or(ProtocolError::IntegerOverflow)?;
        let bits = u64::from(byte & 0x7f);
        if index == 9 && bits > 1 {
            return Err(ProtocolError::ProtocolViolation("protobuf varint overflow"));
        }
        value |= bits << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && value < (1u64 << (index * 7)) {
                return Err(ProtocolError::NonCanonicalVarint);
            }
            return Ok(value);
        }
    }
    *offset = start;
    Err(ProtocolError::ProtocolViolation("protobuf varint overflow"))
}

fn skip_wire_value(bytes: &[u8], offset: &mut usize, wire_type: u8) -> Result<()> {
    let length = match wire_type {
        0 => {
            read_wire_varint(bytes, offset)?;
            return Ok(());
        }
        1 => 8usize,
        2 => usize::try_from(read_wire_varint(bytes, offset)?)
            .map_err(|_| ProtocolError::IntegerOverflow)?,
        5 => 4usize,
        _ => {
            return Err(ProtocolError::ProtocolViolation(
                "unsupported protobuf wire type",
            ))
        }
    };
    let end = (*offset)
        .checked_add(length)
        .ok_or(ProtocolError::IntegerOverflow)?;
    if end > bytes.len() {
        return Err(ProtocolError::TruncatedWireValue);
    }
    *offset = end;
    Ok(())
}
