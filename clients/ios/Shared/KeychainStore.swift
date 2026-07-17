import Foundation
import Security

struct KeychainStore: Sendable {
    static let accessGroup = "group.org.onionroute.mobile"
    private let service = "org.onionroute.mobile.tokens.v1"

    func put(account: String, value: Data) throws {
        guard !value.isEmpty && value.count <= 256 * 1024 else {
            throw KeychainError.invalidSize
        }
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessGroup: Self.accessGroup,
        ]
        let attributes: [CFString: Any] = [
            kSecValueData: value,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            attributes.forEach { item[$0.key] = $0.value }
            try checkKeychain(SecItemAdd(item as CFDictionary, nil))
        } else {
            try checkKeychain(status)
        }
    }

    func get(account: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            kSecAttrAccessGroup: Self.accessGroup,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try checkKeychain(status)
        return result as? Data
    }
}

enum KeychainError: Error {
    case invalidSize
    case status(OSStatus)
}

private func checkKeychain(_ status: OSStatus) throws {
    guard status == errSecSuccess else { throw KeychainError.status(status) }
}

