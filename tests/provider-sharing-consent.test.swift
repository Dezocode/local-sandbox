import Foundation

@MainActor
enum ProviderSharingConsentContracts {
    enum Failure: Error { case injected, accepted }
    @MainActor final class Storage {
        var values: [AppProvider: String] = [:]
        var denied = Set<AppProvider>()
        var failWrite = false
        var failRead = false
        var failDelete = false
        var failDeny = false
        var wrongReadback = false
        var failReadAfterWrite = false
        var failDeniedRead = false
        var failDeniedReadAfterClear = false
        var failClearAfterRemoval = false
        func vault() -> ProviderSharingConsentVault {
            ProviderSharingConsentVault(operations: .init(
                read: { if self.failRead { throw Failure.injected }; return self.values[$0] },
                write: { if self.failWrite { throw Failure.injected }; if !self.wrongReadback { self.values[$0] = $1 }; if self.failReadAfterWrite { self.failRead = true } },
                delete: { if self.failDelete { throw Failure.injected }; self.values[$0] = nil },
                isDenied: { if self.failDeniedRead { throw Failure.injected }; return self.denied.contains($0) },
                deny: { if self.failDeny { throw Failure.injected }; self.denied.insert($0) },
                clearDenial: { self.denied.remove($0); if self.failDeniedReadAfterClear { self.failDeniedRead = true }; if self.failClearAfterRemoval { throw Failure.injected } }
            ))
        }
    }
    static func check(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "ProviderSharingConsentContracts", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    static func denies(_ action: () throws -> Void) throws {
        do { try action(); throw Failure.accepted } catch Failure.accepted { throw Failure.accepted } catch {}
    }
    static func run() throws {
        try check(try ProviderSharingDenialMarker.isDenied { ProviderSharingDenialMarker.bytes }, "valid marker ignored")
        try check(try !ProviderSharingDenialMarker.isDenied { throw CocoaError(.fileReadNoSuchFile) }, "missing marker denied")
        try denies { _ = try ProviderSharingDenialMarker.isDenied { Data("corrupt".utf8) } }
        for code in [CocoaError.fileReadNoPermission, .fileReadUnknown] {
            try denies { _ = try ProviderSharingDenialMarker.isDenied { throw CocoaError(code) } }
        }
        try denies { _ = try ProviderSharingDenialMarker.isDenied { throw NSError(domain: NSPOSIXErrorDomain, code: 5) } }
        try denies { _ = try ProviderSharingDenialMarker.isDenied { throw NSError(domain: NSPOSIXErrorDomain, code: 20) } }
        try denies { try ProviderSharingDenialMarker.clear { throw NSError(domain: NSPOSIXErrorDomain, code: 20) } }
        try ProviderSharingDenialMarker.clear { throw CocoaError(.fileNoSuchFile) }
        try denies { try ProviderSharingDenialMarker.clear { throw CocoaError(.fileWriteNoPermission) } }
        try denies { try ProviderSharingDenialMarker.clear { throw CocoaError(.fileReadNoSuchFile) } }
        let storage = Storage(); let vault = storage.vault()
        let a = try ProviderSharingConfiguration(provider: .local, adapter: .init(name: "Reviewed local"))
        let b = try ProviderSharingConfiguration(provider: .local, adapter: .init(name: "Imported other"))
        try denies { _ = try vault.require(a, owner: "owner") }
        try check(storage.values.isEmpty, "cancel/missing admission wrote a grant")
        try vault.approve(a, owner: "owner")
        let first = try vault.require(a, owner: "owner")
        try denies { _ = try vault.require(a, owner: "other owner") }
        var measured = ShortcutAdapter(name: a.name); measured.tested = true
        try check(try ProviderSharingConfiguration(provider: .local, adapter: measured) == a, "measurement revoked consent")
        let binding = ProviderSharingBinding(id: UUID().uuidString, contextSHA256: NativeDigest.sha256("task + policy + contract"), stateSHA256: NativeDigest.sha256("pending state"))
        try vault.bind(binding, kind: false, configuration: a, owner: "owner")
        try vault.requireBinding(binding, kind: false, configuration: a, owner: "owner")
        for changed in [
            ProviderSharingBinding(id: UUID().uuidString, contextSHA256: binding.contextSHA256, stateSHA256: binding.stateSHA256),
            ProviderSharingBinding(id: binding.id, contextSHA256: NativeDigest.sha256("changed goal"), stateSHA256: binding.stateSHA256),
            ProviderSharingBinding(id: binding.id, contextSHA256: binding.contextSHA256, stateSHA256: NativeDigest.sha256("edited latest result")),
        ] { try denies { try vault.requireBinding(changed, kind: false, configuration: a, owner: "owner") } }
        let next = ProviderSharingBinding(id: binding.id, contextSHA256: binding.contextSHA256, stateSHA256: NativeDigest.sha256("next state"))
        try vault.bind(next, kind: false, configuration: a, owner: "owner", previous: binding)
        try denies { try vault.requireBinding(binding, kind: false, configuration: a, owner: "owner") }
        try denies { try vault.bind(binding, kind: false, configuration: a, owner: "owner", previous: binding) }
        try vault.bind(binding, kind: true, configuration: a, owner: "owner")
        try vault.withdraw(.local)
        try denies { try storage.vault().requireBinding(next, kind: false, configuration: a, owner: "owner") }
        try vault.approve(a, owner: "owner")
        try check(try vault.require(a, owner: "owner").grantID != first.grantID, "reapproval reused authority")
        try denies { try vault.requireBinding(binding, kind: true, configuration: a, owner: "owner") }
        try denies { try vault.requireBinding(next, kind: false, configuration: a, owner: "owner") }
        // Effective workspace import A→B→A retires authority even with no save call.
        try vault.reconcile(b)
        try denies { _ = try storage.vault().require(a, owner: "owner") }
        try vault.approve(a, owner: "owner")
        storage.failWrite = true
        try denies { try vault.reconcile(b) }
        storage.failWrite = false
        try check(storage.denied.contains(.local), "failed invalidation lost durable deny")
        try denies { _ = try storage.vault().require(a, owner: "owner") }
        try vault.approve(a, owner: "owner")
        storage.failReadAfterWrite = true
        try denies { try vault.approve(a, owner: "owner") }
        storage.failReadAfterWrite = false; storage.failRead = false
        try denies { _ = try storage.vault().require(a, owner: "owner") }
        try vault.approve(a, owner: "owner")
        storage.failReadAfterWrite = true
        try denies { try vault.bind(binding, kind: false, configuration: a, owner: "owner") }
        storage.failReadAfterWrite = false; storage.failRead = false
        try denies { try storage.vault().requireBinding(binding, kind: false, configuration: a, owner: "owner") }
        try vault.approve(a, owner: "owner")
        storage.failRead = true
        try denies { _ = try vault.require(a, owner: "owner") }
        storage.failRead = false
        let raw = storage.values[.local]!
        for malformed in ["{}", raw.dropLast() + ",\"extra\":true}", raw.replacingOccurrences(of: "\"schemaVersion\":1", with: "\"schemaVersion\":2"), raw.dropLast() + ",\"schemaVersion\":1}", String(repeating: "x", count: 16_001)] {
            storage.values[.local] = String(malformed)
            try denies { _ = try vault.require(a, owner: "owner") }
            try denies { try vault.approve(a, owner: "owner") }
            try check(storage.values[.local] == malformed, "invalid authority was silently replaced")
        }
        storage.values[.local] = raw
        storage.wrongReadback = true
        try denies { try vault.approve(a, owner: "owner") }
        storage.wrongReadback = false
        storage.failDelete = true
        try denies { try vault.clear() }
        try check(storage.values[.local] != nil, "failed scrub discarded authority evidence")
        storage.failDelete = false
        try vault.clear()
        try denies { _ = try storage.vault().require(a, owner: "owner") }
        // Failed final approval removal/readback restores denial before restart.
        storage.failDeniedReadAfterClear = true
        try denies { try vault.approve(a, owner: "owner") }
        storage.failDeniedReadAfterClear = false; storage.failDeniedRead = false
        try denies { _ = try storage.vault().require(a, owner: "owner") }
        storage.failClearAfterRemoval = true
        try denies { try vault.approve(a, owner: "owner") }
        storage.failClearAfterRemoval = false
        try denies { _ = try storage.vault().require(a, owner: "owner") }
        // Initial deny persistence failure must never report completed withdrawal.
        try vault.approve(a, owner: "owner")
        storage.failDeny = true
        try denies { try vault.withdraw(.local) }
        try denies { _ = try vault.require(a, owner: "owner") }
        print("Provider sharing core passed: strict grants, ownership, protected context, replay, import reconciliation, checked persistence and withdrawal restart failures")
    }
}
