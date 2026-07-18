import XCTest
@testable import OnionRouteApp

final class SharedStateTests: XCTestCase {
    func testDesiredConnectionRoundTrip() {
        let state = SharedState()
        state.setDesiredConnection(true)
        XCTAssertTrue(state.desiredConnection())
        state.setDesiredConnection(false)
        XCTAssertFalse(state.desiredConnection())
    }

    func testExtensionStateAcceptsOnlyClosedSchemaPrefixes() {
        let state = SharedState()
        state.setExtensionState("blocked-packet-core-unavailable")
        XCTAssertEqual(state.extensionState(), "blocked-packet-core-unavailable")

        state.setExtensionState("destination-example.invalid")
        XCTAssertEqual(state.extensionState(), "blocked-packet-core-unavailable")
    }
}
