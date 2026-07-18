import Foundation

struct PacketBatchBudget: Sendable {
    static let standard = PacketBatchBudget(
        maxPackets: 32,
        maxBatchBytes: 256 * 1024,
        maxPacketBytes: 128 * 1024
    )

    let maxPackets: Int
    let maxBatchBytes: Int
    let maxPacketBytes: Int

    func endIndex(in packets: [Data], from startIndex: Int) -> Int {
        guard
            maxPackets > 0,
            maxBatchBytes > 0,
            maxPacketBytes > 0,
            packets.indices.contains(startIndex)
        else { return startIndex }

        var index = startIndex
        var examined = 0
        var acceptedBytes = 0
        while index < packets.count && examined < maxPackets {
            let packetBytes = packets[index].count
            let valid = packetBytes > 0 && packetBytes <= maxPacketBytes
            if valid && acceptedBytes > 0 && acceptedBytes + packetBytes > maxBatchBytes {
                break
            }
            if valid { acceptedBytes += packetBytes }
            index += 1
            examined += 1
        }
        return max(index, min(startIndex + 1, packets.count))
    }
}
