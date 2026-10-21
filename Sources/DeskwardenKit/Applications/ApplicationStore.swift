import Foundation
import Security

public protocol ApplicationStore: Sendable {
    func load() throws -> [ExternalApplication]
    func save(_ applications: [ExternalApplication]) throws
}

public struct ApplicationStoreError: Error, CustomStringConvertible {
    public let status: OSStatus
    public var description: String {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
        return "Keychain error \(status): \(message)"
    }
}

/// Keeps all external applications in a single login-keychain item.
///
/// The server needs the raw secrets to configure TLS, so they can't be stored
/// as hashes. One item holding a JSON array avoids the file-based keychain's
/// refusal to return data for multi-item queries.
public struct KeychainApplicationStore: ApplicationStore {
    let service: String
    // The item's original name, kept so existing applications keep their keys.
    let account = "socket-keys"

    public init(service: String = "io.github.grievouz.deskwarden") {
        self.service = service
    }

    private var baseQuery: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
    }

    public func load() throws -> [ExternalApplication] {
        var query = baseQuery
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let data = result as? Data else {
            throw ApplicationStoreError(status: status)
        }
        return try JSONDecoder().decode([ExternalApplication].self, from: data)
    }

    public func save(_ applications: [ExternalApplication]) throws {
        let data = try JSONEncoder().encode(applications)
        let status = SecItemUpdate(baseQuery as CFDictionary, [kSecValueData: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = baseQuery
            item[kSecValueData] = data
            item[kSecAttrLabel] = "Deskwarden external applications"
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw ApplicationStoreError(status: addStatus) }
        } else if status != errSecSuccess {
            throw ApplicationStoreError(status: status)
        }
    }
}
