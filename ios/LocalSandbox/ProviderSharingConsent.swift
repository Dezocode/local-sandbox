import Foundation

@MainActor
enum ProviderSharingConsent {
    static var vault = ProviderSharingConsentVault(operations: .init(
        read: { try Keychain.getChecked("providerSharingConsent.v1.\($0.rawValue)") },
        write: { try Keychain.set($1, for: "providerSharingConsent.v1.\($0.rawValue)") },
        delete: { try Keychain.deleteChecked("providerSharingConsent.v1.\($0.rawValue)") },
        isDenied: { provider in
            let path = try denialPath(provider)
            return try ProviderSharingDenialMarker.isDenied { try Data(contentsOf: path) }
        },
        deny: { provider in
            let path = try denialPath(provider)
            try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
            try Data("denied-v1".utf8).write(to: path, options: [.atomic, .completeFileProtection])
            guard try Data(contentsOf: path) == Data("denied-v1".utf8) else { throw SandboxError.blocked("PROVIDER_SHARING_WITHDRAWAL_NOT_SAVED") }
        },
        clearDenial: { provider in
            let path = try denialPath(provider)
            try ProviderSharingDenialMarker.clear { try FileManager.default.removeItem(at: path) }
        }
    ))
    private static func denialPath(_ provider: AppProvider) throws -> URL {
        try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("ProviderSharingDenials", isDirectory: true).appendingPathComponent(provider.rawValue)
    }
    static func owner() throws -> String {
        guard let owner = try Keychain.getChecked("appleUser"), !owner.isEmpty else { throw SandboxError.blocked("SIGN_IN_BEFORE_PROVIDER_SHARING") }
        return owner
    }
    static func configuration(_ provider: AppProvider) throws -> ProviderSharingConfiguration {
        do {
            let configuration = try ProviderSharingConfiguration(provider: provider, adapter: AdapterSettings.get(provider))
            try vault.reconcile(configuration)
            return configuration
        } catch {
            try vault.withdraw(provider)
            throw error
        }
    }
    @discardableResult static func require(_ provider: AppProvider) throws -> ProviderSharingRecord {
        let policy = try SavedExecutionAuthorization.load()
        guard !provider.usesCloud || policy.cloudAllowed else { throw SandboxError.blocked("Authorize cloud app handoffs in Settings first.") }
        return try vault.require(configuration(provider), owner: owner())
    }
    static func sessionBinding(_ session: ShortcutSession) throws -> ProviderSharingBinding {
        struct Context: Encodable {
            let id: String; let goal: String; let policy: ResourcePolicy; let authorization: ResourcePolicy
            let contract: GoalContract?; let providerSelection: ProviderSelection; let origin: ProviderTaskOrigin
            let adapter: String; let route: ProviderRoutingEvidence; let started: Date
        }
        let context = Context(id: session.id, goal: session.goal, policy: session.policy, authorization: session.authorizationPolicy,
            contract: session.contract, providerSelection: session.providerSelection, origin: session.taskOrigin,
            adapter: session.shortcutAdapterName, route: session.routingEvidence, started: session.started)
        return ProviderSharingBinding(id: session.id, contextSHA256: NativeDigest.sha256(try ProviderSharingCodec.encoder.encode(context)), stateSHA256: NativeDigest.sha256(try ProviderSharingCodec.encoder.encode(session)))
    }
    static func requireSession(_ session: ShortcutSession) throws {
        guard let provider = AppProvider(rawValue: session.policy.provider), provider != .apple else { throw SandboxError.blocked("PROVIDER_SHARING_CONFIGURATION_INVALID") }
        _ = try require(provider)
        try vault.requireBinding(sessionBinding(session), kind: false, configuration: configuration(provider), owner: owner())
    }
    static func bindSession(_ session: ShortcutSession, previous: ShortcutSession? = nil) throws {
        guard let provider = AppProvider(rawValue: session.policy.provider), provider != .apple else { throw SandboxError.blocked("PROVIDER_SHARING_CONFIGURATION_INVALID") }
        _ = try require(provider)
        let binding = try sessionBinding(session)
        let old = try previous.map(sessionBinding)
        if let old { guard old.id == binding.id, old.contextSHA256 == binding.contextSHA256 else { throw SandboxError.blocked("PROVIDER_SHARING_CONTEXT_CHANGED") } }
        try vault.bind(binding, kind: false, configuration: configuration(provider), owner: owner(), previous: old)
    }
    static func qualificationBinding(_ challenge: ProviderQualificationChallenge) -> ProviderSharingBinding {
        let digest = NativeDigest.sha256(challenge.prompt)
        return ProviderSharingBinding(id: challenge.attemptID, contextSHA256: digest, stateSHA256: digest)
    }
    static func bindQualification(_ challenge: ProviderQualificationChallenge) throws {
        _ = try require(challenge.provider)
        try vault.bind(qualificationBinding(challenge), kind: true, configuration: configuration(challenge.provider), owner: owner())
    }
    static func requireQualification(_ challenge: ProviderQualificationChallenge) throws {
        _ = try require(challenge.provider)
        try vault.requireBinding(qualificationBinding(challenge), kind: true, configuration: configuration(challenge.provider), owner: owner())
    }
}
