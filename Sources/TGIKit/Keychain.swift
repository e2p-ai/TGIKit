import Foundation
import Security

/// Tiny Keychain wrapper for the bearer token.
///
/// Prefer the shared identity access group so widgets / sibling apps see the
/// same session. **Always fall back to app-private storage** when the shared
/// group write is rejected (missing entitlement expansion, profile drift,
/// automatic signing drop). Silent SecItemAdd failure was the root of
/// "Session expired" storms: exchange returned 200, Keychain.set dropped the
/// token, every API call went without Authorization.
public enum Keychain {
    /// Same group TokenVault uses — entitled on app + widget when signing is healthy.
    private static let accessGroup = "864RZF6VB9.com.tiedemannglobe.identity"

    /// Persist `value` under `key`. Returns true when at least one write succeeded.
    @discardableResult
    public static func set(_ key: String, _ value: String) -> Bool {
        let data = Data(value.utf8)
        // Wipe every copy the app can see (shared + private) so we never leave
        // a stale duplicate that a group-less get() could resurface.
        delete(key)
        if writeItem(data, key: key, group: accessGroup) { return true }
        // Fallback: app-private item — same pattern as TokenVault.write.
        return writeItem(data, key: key, group: nil)
    }

    public static func get(_ key: String) -> String? {
        // Prefer shared group (current), then app-private (fallback / pre-1.8).
        readItem(key, group: accessGroup) ?? readItem(key, group: nil)
    }

    public static func delete(_ key: String) {
        for group in [accessGroup, nil] as [String?] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key
            ]
            if let group { query[kSecAttrAccessGroup as String] = group }
            SecItemDelete(query as CFDictionary)
        }
        // Belt-and-suspenders: group-less delete (matches any group the app can see).
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ] as CFDictionary)
    }

    /// Move a pre-1.8 app-private item into the shared group (idempotent).
    public static func migrateToSharedGroup(_ key: String) {
        guard let value = readItem(key, group: nil) else { return }
        // Already readable via shared? Nothing to do.
        if readItem(key, group: accessGroup) != nil { return }
        _ = set(key, value)
    }

    // MARK: - Private

    @discardableResult
    private static func writeItem(_ data: Data, key: String, group: String?) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            // AfterFirstUnlock so background refresh / 401 retry can read tokens
            // before the user unlocks the phone again.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        if let group { query[kSecAttrAccessGroup as String] = group }
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    private static func readItem(_ key: String, group: String?) -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let group { query[kSecAttrAccessGroup as String] = group }
        var out: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data,
              let value = String(data: data, encoding: .utf8) else { return nil }
        return value
    }
}
