//! Bounded runtime-neutral packet reader and writer.

use onionroute_common_types::transport::BoxPacketTunnel;
use onionroute_common_types::types::MAX_PACKET_BYTES;
use onionroute_common_types::OnionResult;

/// Packet reader abstraction used by the core run loop.
pub trait PacketReader {
    /// Reads one complete packet; `None` means the tunnel closed.
    fn read_packet(
        &mut self,
    ) -> impl std::future::Future<Output = OnionResult<Option<Vec<u8>>>> + Send;
}

/// Packet writer abstraction used for synthetic local responses.
pub trait PacketWriter {
    /// Writes one bounded complete packet back to the local tunnel.
    fn write_packet<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> impl std::future::Future<Output = OnionResult<()>> + Send + 'a;
}

/// Single-owner adapter around the platform-neutral packet tunnel.
pub struct TunnelPacketIo {
    tunnel: BoxPacketTunnel,
    max_packet_bytes: usize,
}

impl TunnelPacketIo {
    /// Creates an adapter with a bound no larger than the shared contract limit.
    pub fn new(tunnel: BoxPacketTunnel, max_packet_bytes: usize) -> Option<Self> {
        (max_packet_bytes > 0 && max_packet_bytes <= MAX_PACKET_BYTES).then_some(Self {
            tunnel,
            max_packet_bytes,
        })
    }

    /// Closes the packet tunnel after higher layers have shut down fail-closed.
    pub async fn close(&mut self) -> OnionResult<()> {
        self.tunnel.close().await
    }
}

impl PacketReader for TunnelPacketIo {
    async fn read_packet(&mut self) -> OnionResult<Option<Vec<u8>>> {
        let mut packet = vec![0u8; self.max_packet_bytes];
        let read = self.tunnel.receive(&mut packet).await?;
        if read == 0 {
            return Ok(None);
        }
        if read > packet.len() {
            return Err(crate::core::core_error(
                onionroute_common_types::error::ErrorCode::MessageTooLarge,
                "packet tunnel returned an invalid packet length",
            ));
        }
        packet.truncate(read);
        Ok(Some(packet))
    }
}

impl PacketWriter for TunnelPacketIo {
    async fn write_packet<'a>(&'a mut self, packet: &'a [u8]) -> OnionResult<()> {
        if packet.is_empty() || packet.len() > self.max_packet_bytes {
            return Err(crate::core::core_error(
                onionroute_common_types::error::ErrorCode::MessageTooLarge,
                "synthetic packet exceeds tunnel bound",
            ));
        }
        self.tunnel.send(packet).await
    }
}
