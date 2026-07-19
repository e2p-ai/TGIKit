import XCTest
@testable import TGIKit

final class MobileTokenTests: XCTestCase {
    private func token(expMs: Int) -> String {
        let data = try! JSONSerialization.data(withJSONObject: ["sub": "u", "exp": expMs])
        let payload = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return payload + ".sig"
    }

    func testUsableUnexpired() {
        let expMs = Int(Date().timeIntervalSince1970 * 1000) + 86_400_000
        XCTAssertTrue(MobileToken.isUsable(token(expMs: expMs)))
    }

    func testExpiredUnusable() {
        let expMs = Int(Date().timeIntervalSince1970 * 1000) - 120_000
        XCTAssertFalse(MobileToken.isUsable(token(expMs: expMs)))
    }
}
