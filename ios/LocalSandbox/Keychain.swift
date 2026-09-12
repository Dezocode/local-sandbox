import Foundation
import Security

struct KeychainWriter: @unchecked Sendable {
    let update: (CFDictionary, CFDictionary) -> OSStatus
    let add: (CFDictionary) -> OSStatus

    static let live = KeychainWriter(
        update: { SecItemUpdate($0, $1) },
        add: { SecItemAdd($0, nil) }
    )
}

struct KeychainDeleter: @unchecked Sendable {
    let delete: (CFDictionary) -> OSStatus

    static let live = KeychainDeleter(delete: { SecItemDelete($0) })
}

struct KeychainReader: @unchecked Sendable {
    let copyMatching: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus

    static let live = KeychainReader(copyMatching: { SecItemCopyMatching($0, $1) })
}

enum Keychain {
    private static let service = "LocalSandbox"
    private static let recoveryRegistrationService = "LocalSandbox.WorkspaceRecoveryRegistration.v2"
    static func set(_ value: String, for key: String, writer: KeychainWriter = .live) throws {
        try set(value, for: key, synchronizable: false, writer: writer)
    }
    static func setSynchronizable(_ value: String, for key: String, writer: KeychainWriter = .live) throws {
        try set(value, for: key, synchronizable: true, writer: writer)
    }
    private static func set(_ value: String, for key: String, synchronizable: Bool, writer: KeychainWriter) throws {
        try set(value, for: key, synchronizable: synchronizable, service: service, writer: writer)
    }
    private static func set(_ value: String, for key: String, synchronizable: Bool, service: String, writer: KeychainWriter) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        query[kSecAttrSynchronizable as String] = synchronizable ? kCFBooleanTrue : kCFBooleanFalse
        let attributes: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: synchronizable ? kSecAttrAccessibleWhenUnlocked : kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = writer.update(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED") }

        var insert = query
        for (key, value) in attributes { insert[key] = value }
        let addStatus = writer.add(insert as CFDictionary)
        if addStatus == errSecSuccess { return }
        if addStatus == errSecDuplicateItem,
           writer.update(query as CFDictionary, attributes as CFDictionary) == errSecSuccess { return }
        throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED")
    }
    static func get(_ key: String) -> String? {
        get(key, synchronizable: false)
    }
    static func getSynchronizable(_ key: String) -> String? {
        get(key, synchronizable: true)
    }
    private static func get(_ key: String, synchronizable: Bool) -> String? {
        get(key, synchronizable: synchronizable, service: service)
    }
    private static func get(_ key: String, synchronizable: Bool, service: String) -> String? {
        try? getChecked(key, synchronizable: synchronizable, service: service, reader: .live)
    }
    static func getChecked(
        _ key: String,
        reader: KeychainReader = .live
    ) throws -> String? {
        try getChecked(key, synchronizable: false, service: service, reader: reader)
    }
    static func getSynchronizableChecked(
        _ key: String,
        reader: KeychainReader = .live
    ) throws -> String? {
        try getChecked(key, synchronizable: true, service: service, reader: reader)
    }
    private static func getChecked(
        _ key: String,
        synchronizable: Bool,
        service: String,
        reader: KeychainReader
    ) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: synchronizable ? kCFBooleanTrue as Any : kCFBooleanFalse as Any,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var value: CFTypeRef?
        let status = reader.copyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess,
              let data = value as? Data,
              let result = String(data: data, encoding: .utf8) else {
            throw SandboxError.blocked("KEYCHAIN_READ_FAILED")
        }
        return result
    }
    static func delete(_ key: String) { try? deleteChecked(key) }
    static func deleteSynchronizable(_ key: String) { try? deleteSynchronizableChecked(key) }
    static func deleteChecked(_ key: String, deleter: KeychainDeleter = .live) throws {
        try deleteChecked(key, synchronizable: false, deleter: deleter)
    }
    static func deleteSynchronizableChecked(_ key: String, deleter: KeychainDeleter = .live) throws {
        try deleteChecked(key, synchronizable: true, deleter: deleter)
    }
    private static func deleteChecked(_ key: String, synchronizable: Bool, deleter: KeychainDeleter) throws {
        try deleteChecked(key, synchronizable: synchronizable, service: service, deleter: deleter)
    }
    private static func deleteChecked(_ key: String, synchronizable: Bool, service: String, deleter: KeychainDeleter) throws {
        let status = deleter.delete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: synchronizable ? kCFBooleanTrue as Any : kCFBooleanFalse as Any,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
    }

    static func setSynchronizableRecoveryRegistration(
        _ value: String,
        workspaceId: String,
        writer: KeychainWriter = .live
    ) throws {
        try set(value, for: workspaceId, synchronizable: true, service: recoveryRegistrationService, writer: writer)
    }

    static func getSynchronizableRecoveryRegistrationChecked(
        _ workspaceId: String,
        reader: KeychainReader = .live
    ) throws -> String? {
        try getChecked(
            workspaceId,
            synchronizable: true,
            service: recoveryRegistrationService,
            reader: reader
        )
    }

    static func deleteSynchronizableRecoveryRegistrationChecked(
        _ workspaceId: String,
        deleter: KeychainDeleter = .live
    ) throws {
        try deleteChecked(workspaceId, synchronizable: true, service: recoveryRegistrationService, deleter: deleter)
    }

    static func synchronizableRecoveryRegistrations(
        maximumItems: Int,
        maximumValueBytes: Int,
        reader: KeychainReader = .live
    ) throws -> [String: String] {
        guard (1...512).contains(maximumItems), (1...4_096).contains(maximumValueBytes) else {
            throw SandboxError.invalid("ICLOUD_RECOVERY_REGISTRY_LIMIT_INVALID")
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: recoveryRegistrationService,
            kSecAttrSynchronizable as String: kCFBooleanTrue as Any,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var value: CFTypeRef?
        let status = reader.copyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return [:] }
        guard status == errSecSuccess else { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") }
        let rows: [[String: Any]]
        if let values = value as? [[String: Any]] {
            rows = values
        } else if let single = value as? [String: Any] {
            rows = [single]
        } else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
        }
        guard rows.count <= maximumItems else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_FULL")
        }
        var result: [String: String] = [:]
        for row in rows {
            guard let workspaceId = row[kSecAttrAccount as String] as? String,
                  let data = row[kSecValueData as String] as? Data,
                  data.count <= maximumValueBytes,
                  let registration = String(data: data, encoding: .utf8),
                  result[workspaceId] == nil else {
                throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
            }
            result[workspaceId] = registration
        }
        return result
    }
}
