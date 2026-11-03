import XCTest

final class TrustKitDemoUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testValidPinsConnect() {
        visit("urlSessionGoodPins", expecting: "Connected")
    }

    @MainActor
    func testInvalidPinsAreBlocked() {
        visit("urlSessionBadPins", expecting: "Blocked")
    }

    @MainActor
    func testUnpinnedDomainConnects() {
        visit("urlSessionNoPins", expecting: "Connected")
    }

    @MainActor
    func testWebViewWithValidPinsLoads() {
        let app = XCUIApplication()
        app.launch()
        app.buttons["webViewGoodPins"].tap()

        let link = app.webViews.firstMatch.links.firstMatch
        XCTAssertTrue(link.waitForExistence(timeout: 30), "The page didn't load\n\(app.debugDescription)")
    }

    @MainActor
    func testWebViewWithInvalidPinsIsBlocked() {
        visit("webViewBadPins", expecting: "Blocked")
    }

    @MainActor
    private func visit(_ button: String, expecting outcome: String) {
        let app = XCUIApplication()
        app.launch()
        app.buttons[button].tap()

        let alert = app.alerts.firstMatch
        XCTAssertTrue(alert.waitForExistence(timeout: 30), "No result after tapping \(button)\n\(app.debugDescription)")
        XCTAssertEqual(alert.label, outcome, alert.debugDescription)
        alert.buttons["OK"].tap()
    }
}
