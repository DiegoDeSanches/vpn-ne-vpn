import XCTest
@testable import OnionRouteApp

final class PacketBatchBudgetTests: XCTestCase {
    func testEveryPacketIndexIsEventuallyCovered() {
        let packets = (0..<81).map { _ in Data(repeating: 0x45, count: 1_024) }
        var start = 0
        var covered: [Int] = []

        while start < packets.count {
            let end = PacketBatchBudget.standard.endIndex(in: packets, from: start)
            XCTAssertGreaterThan(end, start)
            covered.append(contentsOf: start..<end)
            start = end
        }

        XCTAssertEqual(covered, Array(packets.indices))
    }

    func testByteAndPacketLimitsAreBounded() {
        let budget = PacketBatchBudget(maxPackets: 3, maxBatchBytes: 100, maxPacketBytes: 80)
        let packets = [
            Data(repeating: 1, count: 60),
            Data(repeating: 2, count: 60),
            Data(repeating: 3, count: 10),
        ]

        XCTAssertEqual(budget.endIndex(in: packets, from: 0), 1)
        XCTAssertEqual(budget.endIndex(in: packets, from: 1), 3)
    }

    func testInvalidPacketStillMakesProgress() {
        let budget = PacketBatchBudget(maxPackets: 2, maxBatchBytes: 100, maxPacketBytes: 80)
        let packets = [Data(), Data(repeating: 1, count: 81), Data(repeating: 2, count: 20)]

        XCTAssertEqual(budget.endIndex(in: packets, from: 0), 2)
        XCTAssertEqual(budget.endIndex(in: packets, from: 2), 3)
    }
}
