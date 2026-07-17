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
}

