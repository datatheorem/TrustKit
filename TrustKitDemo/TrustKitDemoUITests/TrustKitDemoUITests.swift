import XCTest

final class TrustKitDemoUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testValidPinsConnect() {
        visit("Visit Data Theorem [good pins]", expecting: "Connected")
    }

    @MainActor
    func testInvalidPinsAreBlocked() {
        visit("Visit Google [bad pins]", expecting: "Blocked")
    }

    @MainActor
    func testUnpinnedDomainConnects() {
        visit("Visit Yahoo [no pins]", expecting: "Connected")
    }

    @MainActor
    private func visit(_ button: String, expecting outcome: String) {
        let app = XCUIApplication()
        app.launch()
        app.buttons[button].tap()

        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 30), "No result after tapping \(button)")
        let details = alert.staticTexts.allElementsBoundByIndex.map(\.label).joined(separator: "\n")
        XCTAssertEqual(alert.label, outcome, details)
        alert.buttons["OK"].tap()
    }
}
