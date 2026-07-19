import Foundation
import Security

/// Tiny Keychain wrapper for the bearer token. Items are written into the
/// shared identity access group so the widget / App Intents extension reads
/// the same session; get() has no group filter, so pre-1.8 app-private items
/// still resolve, and migrateToSharedGroup() moves them forward on launch.
public enum Keychain {
    /// Same group TokenVault uses — entitled on both the app and widget targets.
    private static let accessGroup = "864RZF6VB9.com.tiedemannglobe.identity"

    public static func set(_ key: String, _ value: String) {
        // A group-less delete matches every copy the app can see (legacy
        // app-private AND shared-group), so no stale duplicate survives.
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ] as CFDictionary)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrAccessGroup as String: accessGroup,
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemAdd(add as CFDictionary, nil)
    }

    public static func get(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func delete(_ key: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ] as CFDictionary)
    }

    /// Move a pre-1.8 app-private item into the shared group (idempotent).
    public static func migrateToSharedGroup(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let attrs = out as? [String: Any],
              let data = attrs[kSecValueData as String] as? Data,
              let value = String(data: data, encoding: .utf8) else { return }
        let group = attrs[kSecAttrAccessGroup as String] as? String
        if group != accessGroup { set(key, value) }
    }
}
