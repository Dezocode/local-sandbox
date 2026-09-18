import Foundation

enum ProviderSharingCodec {
    static var encoder: JSONEncoder { let value = JSONEncoder(); value.outputFormatting = [.sortedKeys]; return value }
}

/// Missing is the only storage error that can mean there is no withdrawal marker.
/// Keep this boundary separate from grant storage so unreadable denial state blocks.
enum ProviderSharingDenialMarker {
    static let bytes = Data("denied-v1".utf8)
    static func isDenied(read: () throws -> Data) throws -> Bool {
        do {
            guard try read() == bytes else { throw SandboxError.blocked("PROVIDER_SHARING_DENIAL_UNREADABLE") }
            return true
        } catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == CocoaError.fileReadNoSuchFile.rawValue {
            return false
        }
    }
    static func clear(remove: () throws -> Void) throws {
        do { try remove() }
        catch let error as NSError where error.domain == NSCocoaErrorDomain && error.code == CocoaError.fileNoSuchFile.rawValue {}
    }
}

struct ProviderSharingConfiguration: Codable, Equatable {
    let provider: AppProvider
    let name: String
    let mode: String
    let installURL: String

    init(provider: AppProvider, adapter: ShortcutAdapter) throws {
        guard provider != .apple, !adapter.name.isEmpty, adapter.name.count <= 80,
              !adapter.name.contains("\n"), !adapter.name.contains("\r"),
              ["action", "manual"].contains(adapter.mode) else {
            throw SandboxError.blocked("PROVIDER_SHARING_CONFIGURATION_INVALID")
        }
        if !adapter.installURL.isEmpty {
            guard let url = URL(string: adapter.installURL), url.scheme == "https", url.host == "www.icloud.com",
                  url.query == nil, url.fragment == nil,
                  url.path.range(of: "^/shortcuts/[a-fA-F0-9]{32}$", options: .regularExpression) != nil else {
                throw SandboxError.blocked("PROVIDER_SHARING_CONFIGURATION_INVALID")
            }
        }
        self.provider = provider; name = adapter.name; mode = adapter.mode; installURL = adapter.installURL
    }
    var digest: String { get throws { NativeDigest.sha256(try ProviderSharingCodec.encoder.encode(self)) } }
}

struct ProviderSharingBinding: Codable, Equatable {
    let id: String
    let contextSHA256: String
    let stateSHA256: String
}

struct ProviderSharingRecord: Codable, Equatable {
    enum State: String, Codable { case active, withdrawalPending, withdrawn }
    static let disclosureVersion = 1
    static let categories = ["task-and-verification", "run-context-and-instructions", "authorized-tool-results", "synthetic-provider-checks"]
    var recordType = "provider-sharing-consent"
    var schemaVersion = 1
    let ownerSHA256: String
    let configuration: ProviderSharingConfiguration
    let disclosureVersion: Int
    let categories: [String]
    let grantID: String
    let grantedAt: Int
    var state: State
    var session: ProviderSharingBinding?
    var qualification: ProviderSharingBinding?
}

/// Main-actor ownership serializes permission changes with app/Intent dispatch.
/// Storage operations are injected so failure and restart behavior execute in tests.
@MainActor
final class ProviderSharingConsentVault {
    struct Operations {
        let read: (AppProvider) throws -> String?
        let write: (AppProvider, String) throws -> Void
        let delete: (AppProvider) throws -> Void
        let isDenied: (AppProvider) throws -> Bool
        let deny: (AppProvider) throws -> Void
        let clearDenial: (AppProvider) throws -> Void
    }
    let operations: Operations
    private var blocked = Set<AppProvider>()
    init(operations: Operations) { self.operations = operations }

    func load(_ provider: AppProvider) throws -> ProviderSharingRecord? {
        guard let raw = try operations.read(provider) else { return nil }
        do {
            let data = Data(raw.utf8)
            try StrictJSON.validate(data, limits: .init(maximumBytes: 16_000, maximumDepth: 8, maximumMembers: 64))
            let record = try JSONDecoder().decode(ProviderSharingRecord.self, from: data)
            let encoded = try ProviderSharingCodec.encoder.encode(record)
            guard let original = try JSONSerialization.jsonObject(with: data) as? NSDictionary,
                  let canonical = try JSONSerialization.jsonObject(with: encoded) as? NSDictionary,
                  original == canonical,
                  record.recordType == "provider-sharing-consent", record.schemaVersion == 1,
                  record.configuration.provider == provider, provider != .apple,
                  record.disclosureVersion == ProviderSharingRecord.disclosureVersion,
                  record.categories == ProviderSharingRecord.categories,
                  record.ownerSHA256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                  UUID(uuidString: record.grantID) != nil, record.grantedAt > 0,
                  record.grantedAt <= Int(Date().timeIntervalSince1970) + 300 else { throw SandboxError.invalid("Invalid consent") }
            _ = try ProviderSharingConfiguration(provider: provider, adapter: ShortcutAdapter(name: record.configuration.name, installURL: record.configuration.installURL, mode: record.configuration.mode))
            for binding in [record.session, record.qualification].compactMap({ $0 }) {
                guard !binding.id.isEmpty, binding.id.count <= 100,
                      binding.contextSHA256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                      binding.stateSHA256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw SandboxError.invalid("Invalid binding") }
            }
            return record
        } catch { throw SandboxError.blocked("PROVIDER_SHARING_RECORD_UNREADABLE: Permission was kept blocked. Review provider sharing in Settings.") }
    }
    private func save(_ record: ProviderSharingRecord) throws {
        let value = String(decoding: try ProviderSharingCodec.encoder.encode(record), as: UTF8.self)
        do {
            try operations.write(record.configuration.provider, value)
            guard try load(record.configuration.provider) == record else { throw SandboxError.blocked("PROVIDER_SHARING_READBACK_FAILED") }
        } catch {
            blocked.insert(record.configuration.provider)
            try operations.deny(record.configuration.provider)
            throw error
        }
    }
    func reconcile(_ configuration: ProviderSharingConfiguration) throws {
        if let record = try load(configuration.provider), record.state == .active, record.configuration != configuration {
            try withdraw(configuration.provider)
        }
    }
    func approve(_ configuration: ProviderSharingConfiguration, owner: String) throws {
        guard !owner.isEmpty else { throw SandboxError.blocked("SIGN_IN_BEFORE_PROVIDER_SHARING") }
        blocked.insert(configuration.provider)
        try operations.deny(configuration.provider)
        guard try operations.isDenied(configuration.provider) else { throw SandboxError.blocked("PROVIDER_SHARING_APPROVAL_NOT_SAVED") }
        // Malformed or unreadable prior authority is retained, never silently replaced.
        _ = try load(configuration.provider)
        let record = ProviderSharingRecord(ownerSHA256: NativeDigest.sha256(owner), configuration: configuration,
            disclosureVersion: ProviderSharingRecord.disclosureVersion, categories: ProviderSharingRecord.categories,
            grantID: UUID().uuidString, grantedAt: Int(Date().timeIntervalSince1970), state: .active)
        try save(record)
        do {
            try operations.clearDenial(configuration.provider)
            guard try !operations.isDenied(configuration.provider) else { throw SandboxError.blocked("PROVIDER_SHARING_WITHDRAWAL_PENDING") }
        } catch {
            // A failed final approval must restore durable denial after marker removal.
            try operations.deny(configuration.provider)
            throw error
        }
        blocked.remove(configuration.provider)
    }
    func require(_ configuration: ProviderSharingConfiguration, owner: String) throws -> ProviderSharingRecord {
        try reconcile(configuration)
        guard !blocked.contains(configuration.provider), try !operations.isDenied(configuration.provider),
              let record = try load(configuration.provider), record.state == .active,
              record.ownerSHA256 == NativeDigest.sha256(owner), !owner.isEmpty,
              record.configuration == configuration else {
            throw SandboxError.blocked("PROVIDER_SHARING_PERMISSION_REQUIRED: Open this provider in Apps & Shortcuts to review and allow its exact handoffs on this iPhone.")
        }
        return record
    }
    func withdraw(_ provider: AppProvider) throws {
        blocked.insert(provider)
        // Independent deny-only device state survives a later Keychain failure.
        try operations.deny(provider)
        guard try operations.isDenied(provider) else { throw SandboxError.blocked("PROVIDER_SHARING_WITHDRAWAL_NOT_SAVED") }
        if var record = try load(provider) {
            record.state = .withdrawalPending
            try save(record)
            record.session = nil; record.qualification = nil; record.state = .withdrawn
            try save(record)
        }
    }
    func reset(_ provider: AppProvider) throws {
        blocked.insert(provider)
        try operations.deny(provider)
        guard try operations.isDenied(provider) else { throw SandboxError.blocked("PROVIDER_SHARING_WITHDRAWAL_NOT_SAVED") }
        try operations.delete(provider)
        guard try operations.read(provider) == nil else { throw SandboxError.blocked("PROVIDER_SHARING_DELETE_FAILED") }
    }
    func clear() throws {
        for provider in AppProvider.allCases where provider != .apple { try reset(provider) }
    }
    func bind(_ binding: ProviderSharingBinding, kind: Bool, configuration: ProviderSharingConfiguration, owner: String, previous: ProviderSharingBinding? = nil) throws {
        var record = try require(configuration, owner: owner)
        let retained = kind ? record.qualification : record.session
        if let previous {
            guard retained == previous else { throw SandboxError.blocked("PROVIDER_SHARING_CONTEXT_CHANGED") }
        } else if retained?.id == binding.id {
            throw SandboxError.blocked("PROVIDER_SHARING_CONTEXT_REPLAY")
        }
        if kind { record.qualification = binding } else { record.session = binding }
        try save(record)
    }
    func requireBinding(_ binding: ProviderSharingBinding, kind: Bool, configuration: ProviderSharingConfiguration, owner: String) throws {
        let record = try require(configuration, owner: owner)
        guard (kind ? record.qualification : record.session) == binding else {
            throw SandboxError.blocked("PROVIDER_SHARING_CONTEXT_CHANGED: Start a new task or provider check. Imported or changed pending state cannot grant permission.")
        }
    }
}
