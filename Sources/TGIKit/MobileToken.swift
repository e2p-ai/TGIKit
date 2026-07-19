import Foundation

/// Pure helpers for the mobile ecp.token format (no UIKit / Keychain).
/// Format: base64url(JSON {sub,exp}).hmac — exp is milliseconds (mobile-auth.ts).
public enum MobileToken {
    /// True when the bearer is still within server leeway (60s past exp allowed).
    public static func isUsable(_ token: String, now: Date = Date()) -> Bool {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        let payloadSegment: String?
        if parts.count == 2 {
            payloadSegment = String(parts[0])
        } else if parts.count == 3 {
            payloadSegment = String(parts[1])
        } else {
            payloadSegment = nil
        }
        guard let payloadSegment,
              let data = decodeBase64URL(payloadSegment),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        let expRaw: Double
        if let d = json["exp"] as? Double {
            expRaw = d
        } else if let i = json["exp"] as? Int {
            expRaw = Double(i)
        } else {
            return false
        }
        // ms if > 1e12, else seconds (JWT access tokens).
        let expMs = expRaw > 1_000_000_000_000 ? expRaw : expRaw * 1000.0
        return expMs >= (now.timeIntervalSince1970 * 1000.0) - 60_000
    }

    public static func decodeBase64URL(_ segment: String) -> Data? {
        var base64 = segment
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64.append(String(repeating: "=", count: 4 - remainder))
        }
        return Data(base64Encoded: base64)
    }
}
