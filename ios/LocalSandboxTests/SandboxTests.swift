import XCTest
import Security
@testable import LocalSandbox

private actor HeldWorkspaceMutationTransport: NativeHTTPPerforming {
    private var heldRequest: URLRequest?
    private var heldContinuation: CheckedContinuation<NativeHTTPResult, Never>?
    private var readinessWaiters: [CheckedContinuation<Void, Never>] = []
    private var requests = 0
    private var cancellationObservedAfterRelease = false

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        requests += 1
        guard requests == 1, maximumResponseBytes == NativeServiceLimits.syncResponseBytes else {
            throw SandboxError.blocked("UNEXPECTED_POST_LOCK_CLIENT_OPERATION")
        }
        heldRequest = request
        let result = await withCheckedContinuation { continuation in
            heldContinuation = continuation
            let waiters = readinessWaiters
            readinessWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
        cancellationObservedAfterRelease = Task.isCancelled
        return result
    }

    func waitUntilHeld() async {
        if heldContinuation != nil { return }
        await withCheckedContinuation { readinessWaiters.append($0) }
    }

    func releaseAsCommitted() throws {
        guard let request = heldRequest,
              let continuation = heldContinuation,
              let url = request.url,
              let body = request.httpBody,
              let enrollment = try JSONSerialization.jsonObject(with: body) as? [String: Any],
              let workspaceId = enrollment["workspaceId"] as? String,
              let epoch = enrollment["epoch"] as? String,
              let recovery = enrollment["recovery"] as? [String: Any],
              let response = HTTPURLResponse(
                  url: url,
                  statusCode: 200,
                  httpVersion: "HTTP/1.1",
                  headerFields: ["Content-Type": "application/json"]
              ) else {
            throw SandboxError.blocked("HELD_MUTATION_FIXTURE_INVALID")
        }
        let responseData = try JSONSerialization.data(withJSONObject: [
            "workspaceId": workspaceId,
            "epoch": epoch,
            "recovery": recovery,
            "created": true,
        ])
        heldContinuation = nil
        heldRequest = nil
        continuation.resume(returning: NativeHTTPResult(data: responseData, response: response))
    }

    func requestCount() -> Int { requests }
    func observedCancellationAfterRelease() -> Bool { cancellationObservedAfterRelease }
}

private actor HeldNativeRevocationTransport: NativeHTTPPerforming {
    private var heldRequest: URLRequest?
    private var heldContinuation: CheckedContinuation<NativeHTTPResult, Never>?
    private var readinessWaiters: [CheckedContinuation<Void, Never>] = []

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        guard request.url?.path == "/api/auth/apple/native/revoke",
              maximumResponseBytes == NativeServiceLimits.exchangeResponseBytes else {
            throw SandboxError.blocked("UNEXPECTED_NATIVE_REVOCATION_REQUEST")
        }
        heldRequest = request
        return await withCheckedContinuation { continuation in
            heldContinuation = continuation
            let waiters = readinessWaiters
            readinessWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
    }

    func waitUntilHeld() async {
        if heldContinuation != nil { return }
        await withCheckedContinuation { readinessWaiters.append($0) }
    }

    func release() throws {
        guard let request = heldRequest,
              let continuation = heldContinuation,
              let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json", "Cache-Control": "no-store"]
              ) else {
            throw SandboxError.blocked("HELD_REVOCATION_FIXTURE_INVALID")
        }
        heldRequest = nil
        heldContinuation = nil
        continuation.resume(returning: NativeHTTPResult(data: Data("{\"revoked\":true}".utf8), response: response))
    }
}

private actor SequencedNativeTransport: NativeHTTPPerforming {
    struct Response: Sendable {
        let status: Int
        let data: Data
    }

    private var responses: [Response]

    init(_ responses: [Response]) {
        self.responses = responses
    }

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        guard !responses.isEmpty, maximumResponseBytes > 0, let url = request.url else {
            throw SandboxError.blocked("UNEXPECTED_NATIVE_TRANSPORT_REQUEST")
        }
        let next = responses.removeFirst()
        guard let response = HTTPURLResponse(
            url: url,
            statusCode: next.status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json", "Cache-Control": "no-store"]
        ) else {
            throw SandboxError.blocked("NATIVE_TEST_RESPONSE_INVALID")
        }
        return NativeHTTPResult(data: next.data, response: response)
    }
}

private struct UnexpectedNativeTransport: NativeHTTPPerforming {
    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        throw SandboxError.blocked("UNEXPECTED_NATIVE_TRANSPORT_REQUEST")
    }
}

private actor CountingUnexpectedNativeTransport: NativeHTTPPerforming {
    private var requests = 0

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        requests += 1
        throw SandboxError.blocked("UNEXPECTED_NATIVE_TRANSPORT_REQUEST")
    }

    func requestCount() -> Int { requests }
}

private final class ProfileMutationProbe: @unchecked Sendable {
    var count = 0
}

final class SandboxTests:XCTestCase {
    @MainActor
    func testShortcutDistributionApprovalClearFailsClosedOnReadbackError() {
        var checkedDeleteCalls = 0
        XCTAssertThrowsError(try ShortcutDistributionApprovalStore.clear(
            deleteChecked: { checkedDeleteCalls += 1 },
            readChecked: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") }
        )) { error in
            XCTAssertEqual(error.localizedDescription, "KEYCHAIN_READ_FAILED")
        }
        XCTAssertEqual(checkedDeleteCalls, 1)

        XCTAssertThrowsError(try ShortcutDistributionApprovalStore.clear(
            deleteChecked: { checkedDeleteCalls += 1 },
            readChecked: { "https://self-host.example.test" }
        )) { error in
            XCTAssertEqual(error.localizedDescription, "KEYCHAIN_DELETE_FAILED")
        }
        XCTAssertEqual(checkedDeleteCalls, 2)
    }

    @MainActor
    func testProfileDeletionDoesNotCommitPastShortcutApprovalReadbackFailure() async throws {
        let previousUser = Keychain.get("appleUser")
        defer {
            if let previousUser { try? Keychain.set(previousUser, for: "appleUser") }
            else { Keychain.delete("appleUser") }
        }
        try Keychain.set("shortcut-approval-profile", for: "appleUser")

        let transport = CountingUnexpectedNativeTransport()
        let nativeAuth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { })
        )
        let mutationProbe = ProfileMutationProbe()
        let credentialScrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            accountModeVault: NativeAppleAccountModeVault(
                read: { nil },
                write: { _ in mutationProbe.count += 1 },
                delete: { mutationProbe.count += 1 }
            ),
            workspaceBindingVault: NativeLocalWorkspaceBindingVault(
                read: { nil },
                write: { _ in mutationProbe.count += 1 },
                delete: { mutationProbe.count += 1 }
            ),
            recoveryVault: .live,
            read: { _ in nil },
            write: { _, _ in mutationProbe.count += 1 },
            delete: { _ in mutationProbe.count += 1 }
        )
        let app = AppModel(
            nativeAuth: nativeAuth,
            credentialScrubber: credentialScrubber,
            clearShortcutDistributionApproval: {},
            readShortcutDistributionApproval: {
                throw SandboxError.blocked("KEYCHAIN_READ_FAILED")
            }
        )
        app.unlocked = true

        await app.deleteProfile()

        let requestCount = await transport.requestCount()
        XCTAssertEqual(try Keychain.getChecked("appleUser"), "shortcut-approval-profile")
        XCTAssertEqual(mutationProbe.count, 0)
        XCTAssertEqual(requestCount, 0)
        XCTAssertTrue(app.error.contains("KEYCHAIN_READ_FAILED"))
    }

    @MainActor
    func testProfileDeletionKeepsIdentityWhenTransferBlockClearFails() async throws {
        let previousUser = Keychain.get("appleUser")
        defer {
            if let previousUser { try? Keychain.set(previousUser, for: "appleUser") }
            else { Keychain.delete("appleUser") }
        }
        let profileUser = "transfer-clear-profile"
        try Keychain.set(profileUser, for: "appleUser")

        var transferStorage: String?
        var transferDeleteCalls = 0
        let transferVault = NativeAppleTransferBlockVault(
            read: { transferStorage },
            write: { transferStorage = $0 },
            delete: {
                transferDeleteCalls += 1
                throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
            }
        )
        try transferVault.block(oldUser: profileUser)
        var credentials = ["appleUser": profileUser, "githubToken": "secret"]
        let scrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}),
            accountModeVault: NativeAppleAccountModeVault(
                read: { nil }, write: { _ in }, delete: {}
            ),
            workspaceBindingVault: NativeLocalWorkspaceBindingVault(
                read: { nil }, write: { _ in }, delete: {}
            ),
            recoveryVault: .live,
            read: { credentials[$0] },
            write: { credentials[$0] = $1 },
            delete: { credentials.removeValue(forKey: $0) }
        )
        let transport = CountingUnexpectedNativeTransport()
        let auth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {})
        )
        let app = AppModel(
            nativeAuth: auth,
            transferBlockVault: transferVault,
            credentialScrubber: scrubber,
            clearShortcutDistributionApproval: {},
            readShortcutDistributionApproval: { nil },
            localProfileStateIsCleared: { true }
        )
        app.unlocked = true

        await app.deleteProfile()

        XCTAssertEqual(credentials["appleUser"], profileUser)
        XCTAssertNil(credentials["githubToken"])
        XCTAssertEqual(transferDeleteCalls, 1)
        let requestCount = await transport.requestCount()
        XCTAssertEqual(requestCount, 0)
        XCTAssertTrue(app.error.contains("KEYCHAIN_DELETE_FAILED"))
    }

    @MainActor
    func testProfileDeletionKeepsIdentityWhenFinalStateProofFails() async throws {
        var credentials = ["appleUser": "final-proof-profile", "githubToken": "secret"]
        let scrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}),
            accountModeVault: NativeAppleAccountModeVault(
                read: { nil }, write: { _ in }, delete: {}
            ),
            workspaceBindingVault: NativeLocalWorkspaceBindingVault(
                read: { nil }, write: { _ in }, delete: {}
            ),
            recoveryVault: .live,
            read: { credentials[$0] },
            write: { credentials[$0] = $1 },
            delete: { credentials.removeValue(forKey: $0) }
        )
        let transport = CountingUnexpectedNativeTransport()
        let auth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {})
        )
        let app = AppModel(
            nativeAuth: auth,
            credentialScrubber: scrubber,
            clearShortcutDistributionApproval: {},
            readShortcutDistributionApproval: { nil },
            localProfileStateIsCleared: { false }
        )
        app.userID = "final-proof-profile"
        app.unlocked = true

        await app.deleteProfile()

        XCTAssertEqual(credentials["appleUser"], "final-proof-profile")
        XCTAssertNil(credentials["githubToken"])
        let requestCount = await transport.requestCount()
        XCTAssertEqual(requestCount, 0)
        XCTAssertTrue(app.error.contains("LOCAL_PROFILE_SCRUB_FAILED"))
    }

    @MainActor
    func testDeleteProfileKeepsLocalStateWhenBearerCheckedReadFails() async throws {
        let previousUser = Keychain.get("appleUser")
        let admissionWasBlocked = NativeHostedAccessAdmission.isBlocked()
        defer {
            if let previousUser { try? Keychain.set(previousUser, for: "appleUser") }
            else { Keychain.delete("appleUser") }
            if admissionWasBlocked { NativeHostedAccessAdmission.block() }
            else { NativeHostedAccessAdmission.allowAfterCredentialVerification() }
        }
        Keychain.delete("appleUser")

        let now = Int(Date().timeIntervalSince1970)
        let session = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "K", count: 43))",
            expiresAt: now + 600,
            accountMode: .standalone
        )
        var storedBearer: String? = String(decoding: try JSONEncoder().encode(session), as: UTF8.self)
        var bearerDeleteCount = 0
        let bearerVault = NativeBearerVault(
            read: { storedBearer },
            readChecked: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            write: { storedBearer = $0 },
            delete: { bearerDeleteCount += 1; storedBearer = nil }
        )
        let transport = CountingUnexpectedNativeTransport()
        let nativeAuth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            vault: bearerVault
        )

        let profileMutations = ProfileMutationProbe()
        let accountModeVault = NativeAppleAccountModeVault(
            read: { nil },
            write: { _ in profileMutations.count += 1 },
            delete: { profileMutations.count += 1 }
        )
        let workspaceBindingVault = NativeLocalWorkspaceBindingVault(
            read: { nil },
            write: { _ in profileMutations.count += 1 },
            delete: { profileMutations.count += 1 }
        )
        let recoveryVault = NativeRecoverySecretVault(
            read: { _ in nil },
            write: { _, _ in profileMutations.count += 1 },
            delete: { _ in profileMutations.count += 1 },
            readRegistration: { _ in nil },
            writeRegistration: { _, _ in profileMutations.count += 1 },
            deleteRegistration: { _ in profileMutations.count += 1 },
            listRegistrations: { [:] },
            accountBinding: { nil }
        )
        let transferBlockVault = NativeAppleTransferBlockVault(
            read: { nil },
            write: { _ in profileMutations.count += 1 },
            delete: { profileMutations.count += 1 }
        )
        let transferMigration = NativeAppleTransferMigrationCoordinator(
            accountModeVault: accountModeVault,
            workspaceBindingVault: workspaceBindingVault,
            recoveryVault: recoveryVault,
            migrationVault: NativeAppleTransferMigrationVault(
                read: { nil },
                write: { _ in profileMutations.count += 1 },
                delete: { profileMutations.count += 1 }
            ),
            transferBlockVault: transferBlockVault,
            readUser: { nil },
            writeUser: { _ in profileMutations.count += 1 }
        )
        let credentialScrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: bearerVault,
            accountModeVault: accountModeVault,
            workspaceBindingVault: workspaceBindingVault,
            recoveryVault: recoveryVault,
            read: { _ in nil },
            write: { _, _ in profileMutations.count += 1 },
            delete: { _ in profileMutations.count += 1 }
        )
        let app = AppModel(
            nativeAuth: nativeAuth,
            accountModeVault: accountModeVault,
            transferBlockVault: transferBlockVault,
            transferMigration: transferMigration,
            deletionOutcomeVault: NativeAccountDeletionOutcomeVault(
                read: { nil },
                write: { _ in profileMutations.count += 1 },
                delete: { profileMutations.count += 1 }
            ),
            credentialScrubber: credentialScrubber,
            nativeSessionNow: { Date(timeIntervalSince1970: TimeInterval(now)) }
        )
        app.userID = "preserved-local-user"
        app.unlocked = true
        let wasConnected = app.connected

        await app.deleteProfile()

        let requestCount = await transport.requestCount()
        XCTAssertEqual(app.userID, "preserved-local-user")
        XCTAssertTrue(app.unlocked)
        XCTAssertEqual(app.connected, wasConnected)
        XCTAssertEqual(profileMutations.count, 0)
        XCTAssertEqual(bearerDeleteCount, 0)
        XCTAssertNotNil(storedBearer)
        XCTAssertEqual(requestCount, 0)
        XCTAssertTrue(app.error.contains("local profile was kept unchanged"))
        XCTAssertTrue(app.error.contains("KEYCHAIN_READ_FAILED"))
    }

    @MainActor
    func testWorkspace401UsesSeparateDurableBearerRetirement() async throws {
        let admissionWasBlocked = NativeHostedAccessAdmission.isBlocked()
        defer {
            if admissionWasBlocked { NativeHostedAccessAdmission.block() }
            else { NativeHostedAccessAdmission.allowAfterCredentialVerification() }
        }
        let now = Int(Date().timeIntervalSince1970)
        let session = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "J", count: 43))",
            expiresAt: now + 600,
            accountMode: .standalone
        )
        var pendingStorage: String?
        let pendingVault = NativePendingRevocationVault(
            read: { pendingStorage },
            write: { pendingStorage = $0 },
            delete: { pendingStorage = nil }
        )
        var storedBearer: String? = String(decoding: try JSONEncoder().encode(session), as: UTF8.self)
        let bearerVault = NativeBearerVault(
            read: { storedBearer },
            readChecked: { storedBearer },
            write: { storedBearer = $0 },
            delete: { storedBearer = nil },
            admissionBlocked: { NativeHostedAccessAdmission.isBlocked() },
            retirementBlocked: { token, instant in
                pendingVault.blocksAdmission(bearerToken: token, now: instant)
            }
        )
        let revokeTransport = CountingUnexpectedNativeTransport()
        let nativeAuth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: revokeTransport
            ),
            vault: bearerVault,
            pendingRevocationVault: pendingVault
        )
        let workspace401 = try JSONSerialization.data(withJSONObject: [
            "code": "APPLE_NATIVE_SESSION_REQUIRED",
            "error": "session rejected",
        ])
        let model = NativeWorkspaceSyncModel(
            api: NativeWorkspaceSyncAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: SequencedNativeTransport([.init(status: 401, data: workspace401)])
            ),
            bearerVault: bearerVault,
            recoveryVault: NativeRecoverySecretVault(
                read: { _ in nil },
                write: { _, _ in },
                delete: { _ in },
                readRegistration: { _ in nil },
                writeRegistration: { _, _ in },
                deleteRegistration: { _ in },
                listRegistrations: { [:] },
                accountBinding: { nil }
            ),
            nativeAuth: nativeAuth
        )
        NativeHostedAccessAdmission.allowAfterCredentialVerification()

        await model.refreshWorkspaces(operationGeneration: model.captureOperationGeneration())

        let queued = try pendingVault.snapshot(now: now)
        let revokeRequests = await revokeTransport.requestCount()
        XCTAssertTrue(NativeHostedAccessAdmission.isBlocked())
        XCTAssertNil(storedBearer, "Separate retirement may clear only after the exact token is durably queued")
        XCTAssertEqual(queued.map(\.bearerToken), [session.token])
        XCTAssertEqual(revokeRequests, 1)
        XCTAssertTrue(model.status.contains("saved for bounded server-revocation retry"))
    }

    @MainActor
    func testDisconnectFailureThatLocksAppRetiresExecutionGeneration() async throws {
        let previousUser = Keychain.get("appleUser")
        let previousBearer = Keychain.get("appleNativeBearer.v1")
        let admissionWasBlocked = NativeHostedAccessAdmission.isBlocked()
        defer {
            if let previousUser { try? Keychain.set(previousUser, for: "appleUser") }
            else { Keychain.delete("appleUser") }
            if let previousBearer { try? Keychain.set(previousBearer, for: "appleNativeBearer.v1") }
            else { Keychain.delete("appleNativeBearer.v1") }
            if admissionWasBlocked { NativeHostedAccessAdmission.block() }
            else { NativeHostedAccessAdmission.allowAfterCredentialVerification() }
        }
        Keychain.delete("appleUser")
        Keychain.delete("appleNativeBearer.v1")

        let invalidRetainedVault = NativeBearerVault(
            read: { "invalid-retained-bearer" },
            write: { _ in },
            delete: {}
        )
        let nativeAuth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: UnexpectedNativeTransport()
            ),
            vault: invalidRetainedVault
        )
        let model = AppModel(nativeAuth: nativeAuth)
        let retainedSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "V", count: 43))",
            expiresAt: Int(Date().timeIntervalSince1970) + 600,
            accountMode: .standalone
        )
        let retainedEncoding = String(decoding: try JSONEncoder().encode(retainedSession), as: UTF8.self)
        try Keychain.set(retainedEncoding, for: "appleNativeBearer.v1")
        NativeHostedAccessAdmission.allowAfterCredentialVerification()
        model.unlocked = true
        let executionGeneration = ExecutionContinuationGate.shared.capture()

        await model.disconnectNativeSync(executionGeneration: executionGeneration)

        XCTAssertFalse(model.unlocked)
        XCTAssertEqual(try Keychain.getChecked("appleNativeBearer.v1"), retainedEncoding)
        XCTAssertTrue(NativeHostedAccessAdmission.isBlocked())
        XCTAssertNil(NativeBearerVault.live.load(), "A retained bearer must not remain admitted after lock")
        XCTAssertEqual(try NativeBearerVault.live.loadForRetirement()?.token, retainedSession.token)
        XCTAssertTrue(model.error.contains("Local Sandbox was locked"))
        XCTAssertThrowsError(try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)) { error in
            XCTAssertEqual(error.localizedDescription, "LOCAL_SANDBOX_LOCKED")
        }
    }

    @MainActor
    func testDisconnectBlocksAdmissionAndLocksWorkspaceBeforeRevokeReturns() async throws {
        let previousUser = Keychain.get("appleUser")
        let admissionWasBlocked = NativeHostedAccessAdmission.isBlocked()
        defer {
            if let previousUser { try? Keychain.set(previousUser, for: "appleUser") }
            else { Keychain.delete("appleUser") }
            if admissionWasBlocked { NativeHostedAccessAdmission.block() }
            else { NativeHostedAccessAdmission.allowAfterCredentialVerification() }
        }
        Keychain.delete("appleUser")

        let now = Int(Date().timeIntervalSince1970)
        let session = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "D", count: 43))",
            expiresAt: now + 600,
            accountMode: .standalone
        )
        var storedBearer: String? = String(decoding: try JSONEncoder().encode(session), as: UTF8.self)
        let vault = NativeBearerVault(
            read: { storedBearer },
            write: { storedBearer = $0 },
            delete: { storedBearer = nil },
            admissionBlocked: { NativeHostedAccessAdmission.isBlocked() }
        )
        let transport = HeldNativeRevocationTransport()
        let nativeAuth = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            vault: vault
        )
        let app = AppModel(nativeAuth: nativeAuth)
        let sync = NativeWorkspaceSyncModel(bearerVault: vault)
        NativeHostedAccessAdmission.allowAfterCredentialVerification()
        XCTAssertNotNil(vault.load(now: now))

        let executionGeneration = ExecutionContinuationGate.shared.capture()
        let disconnect = Task { @MainActor in
            await app.disconnectNativeSync(executionGeneration: executionGeneration)
        }
        await transport.waitUntilHeld()

        XCTAssertTrue(NativeHostedAccessAdmission.isBlocked())
        XCTAssertNil(vault.load(now: now), "Disconnect must close bearer admission before awaiting revocation")
        XCTAssertTrue(sync.status.contains("Encryption keys were cleared"))
        XCTAssertNotNil(storedBearer, "The held revoke fixture cleared its bearer before the response")

        try await transport.release()
        await disconnect.value
        XCTAssertNil(storedBearer)
    }

    @MainActor
    func testQueuedExecutionEntriesRejectTapGenerationRetiredBeforeTaskStart() async throws {
        let executionGeneration = ExecutionContinuationGate.shared.capture()
        ExecutionContinuationGate.shared.invalidate()
        let routingEvidence = ProviderRoutingEvidence(
            selection: .apple,
            provider: .apple,
            authorizedProvider: .apple,
            strategy: .explicitPinned,
            activity: .workspaceIdle,
            accessEvidence: .onDeviceRuntime,
            deviceProfileSHA256: String(repeating: "d", count: 64),
            configurationSHA256: String(repeating: "e", count: 64),
            qualification: nil
        )

        do {
            _ = try await AgentRunner.shared.run(
                goal: "queued run",
                policy: ResourcePolicy(),
                taskOrigin: .app,
                routingEvidence: routingEvidence,
                executionGeneration: executionGeneration
            )
            XCTFail("Queued AgentRunner entry adopted a post-lock generation")
        } catch {
            XCTAssertEqual(error.localizedDescription, "LOCAL_SANDBOX_LOCKED")
        }
        do {
            _ = try await ShortcutCoordinator.shared.accept(
                "{}",
                executionGeneration: executionGeneration
            )
            XCTFail("Queued Shortcut accept adopted a post-lock generation")
        } catch {
            XCTAssertEqual(error.localizedDescription, "LOCAL_SANDBOX_LOCKED")
        }
        do {
            try await ShortcutCoordinator.shared.stop(executionGeneration: executionGeneration)
            XCTFail("Queued Shortcut stop adopted a post-lock generation")
        } catch {
            XCTAssertEqual(error.localizedDescription, "LOCAL_SANDBOX_LOCKED")
        }
    }

    @MainActor
    func testQueuedWorkspaceOperationRejectsGenerationRetiredBeforeTaskStart() async throws {
        let now = Int(Date().timeIntervalSince1970)
        let session = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "Q", count: 43))",
            expiresAt: now + 600,
            accountMode: .standalone
        )
        let encodedBearer = String(decoding: try JSONEncoder().encode(session), as: UTF8.self)
        let model = NativeWorkspaceSyncModel(
            api: NativeWorkspaceSyncAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: UnexpectedNativeTransport()
            ),
            bearerVault: NativeBearerVault(
                read: { encodedBearer },
                write: { _ in },
                delete: {}
            )
        )
        let operationGeneration = model.captureOperationGeneration()
        model.lock()
        let lockedStatus = model.status

        await model.refreshWorkspaces(operationGeneration: operationGeneration)
        await model.create(
            useICloudRecovery: false,
            localPassphrase: "queued workspace passphrase",
            operationGeneration: operationGeneration
        )

        XCTAssertFalse(model.busy)
        XCTAssertTrue(model.workspaces.isEmpty)
        XCTAssertEqual(model.status, lockedStatus, "A queued post-lock action overwrote lock status")
    }

    @MainActor
    func testAuthoritativeWorkspaceAbsenceClearsUnlockedSecretsAndKeepsRecoveryCleanup() async throws {
        let now = Int(Date().timeIntervalSince1970)
        let bearer = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "M", count: 43))",
            expiresAt: now + 600,
            accountMode: .standalone
        )
        let encodedBearer = String(decoding: try JSONEncoder().encode(bearer), as: UTF8.self)
        let passphrase = String(repeating: "P", count: 43)
        let created = try WorkspaceCrypto.create(
            passphrase: passphrase,
            createdAt: "2026-09-12T00:00:00Z"
        )
        let recoveryObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(created.1))
        let snapshotData = try JSONSerialization.data(withJSONObject: [
            "workspaceId": created.0.workspaceId,
            "epoch": created.0.epoch,
            "recovery": recoveryObject,
            "snapshotRevision": 1,
            "records": [],
            "nextCursor": NSNull(),
        ])
        let emptyListData = try JSONSerialization.data(withJSONObject: ["workspaces": []])
        let transport = SequencedNativeTransport([
            .init(status: 200, data: snapshotData),
            .init(status: 200, data: emptyListData),
        ])
        var synchronizedSecrets: [String: String] = [:]
        var registrations: [String: String] = [:]
        let recoveryVault = NativeRecoverySecretVault(
            read: { synchronizedSecrets[$0] },
            write: { synchronizedSecrets[$0] = $1 },
            delete: { synchronizedSecrets.removeValue(forKey: $0) },
            readRegistration: { registrations[$0] },
            writeRegistration: { registrations[$0] = $1 },
            deleteRegistration: { registrations.removeValue(forKey: $0) },
            listRegistrations: { registrations },
            accountBinding: { "authoritative-absence-user" }
        )
        try recoveryVault.save(passphrase, workspaceId: created.0.workspaceId)
        let model = NativeWorkspaceSyncModel(
            api: NativeWorkspaceSyncAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            bearerVault: NativeBearerVault(
                read: { encodedBearer },
                write: { _ in },
                delete: {}
            ),
            recoveryVault: recoveryVault
        )
        model.selectedWorkspaceId = created.0.workspaceId

        await model.unlock(
            useICloudRecovery: false,
            localPassphrase: passphrase,
            operationGeneration: model.captureOperationGeneration()
        )
        XCTAssertEqual(model.unlockedWorkspaceId, created.0.workspaceId)
        model.revealICloudRecoverySecret(operationGeneration: model.captureOperationGeneration())
        XCTAssertEqual(model.displayedRecoverySecret, passphrase)

        await model.refreshWorkspaces(operationGeneration: model.captureOperationGeneration())

        XCTAssertNil(model.unlockedWorkspaceId)
        XCTAssertNil(model.displayedRecoverySecret)
        XCTAssertTrue(model.workspaces.isEmpty)
        XCTAssertEqual(model.selectedWorkspaceId, "")
        XCTAssertEqual(model.orphanedRecoveryWorkspaceIds, [created.0.workspaceId])
        XCTAssertTrue(model.status.contains("in-memory key was cleared"))
        XCTAssertTrue(model.status.contains("obsolete iCloud recovery credential"))
        XCTAssertEqual(synchronizedSecrets[created.0.workspaceId], passphrase)

        await model.stagePull(operationGeneration: model.captureOperationGeneration())
        XCTAssertEqual(model.status, "UNLOCK_ENCRYPTED_WORKSPACE_FIRST")
        XCTAssertEqual(model.orphanedRecoveryWorkspaceIds, [created.0.workspaceId])
    }

    @MainActor
    func testWorkspaceLockCancelsHeldMutationAndPreventsFollowupClientOperation() async throws {
        let now = Int(Date().timeIntervalSince1970)
        let bearer = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1.\(String(repeating: "A", count: 43))",
            expiresAt: now + 600,
            accountMode: .standalone
        )
        let encodedBearer = String(decoding: try JSONEncoder().encode(bearer), as: UTF8.self)
        let transport = HeldWorkspaceMutationTransport()
        let model = NativeWorkspaceSyncModel(
            api: NativeWorkspaceSyncAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!),
                transport: transport
            ),
            bearerVault: NativeBearerVault(
                read: { encodedBearer },
                write: { _ in },
                delete: {}
            ),
            recoveryVault: NativeRecoverySecretVault(
                read: { _ in nil },
                write: { _, _ in },
                delete: { _ in },
                readRegistration: { _ in nil },
                writeRegistration: { _, _ in },
                deleteRegistration: { _ in },
                listRegistrations: { [:] },
                accountBinding: { "held-workspace-test-user" }
            )
        )

        let operationGeneration = model.captureOperationGeneration()
        let operation = Task { @MainActor in
            await model.create(
                useICloudRecovery: false,
                localPassphrase: "held mutation passphrase",
                operationGeneration: operationGeneration
            )
        }
        await transport.waitUntilHeld()
        XCTAssertTrue(model.busy)

        NotificationCenter.default.post(name: .localSandboxDidLock, object: nil)
        XCTAssertFalse(model.busy)
        XCTAssertNil(model.unlockedWorkspaceId)
        try await transport.releaseAsCommitted()
        await operation.value

        let requestCount = await transport.requestCount()
        let cancellationObserved = await transport.observedCancellationAfterRelease()
        XCTAssertEqual(requestCount, 1, "Lock must prevent the post-enrollment workspace-list request")
        XCTAssertTrue(cancellationObserved, "Lock must cancel the owned transport task")
        XCTAssertNil(model.unlockedWorkspaceId)
        XCTAssertTrue(model.workspaces.isEmpty)
        XCTAssertTrue(model.status.contains("may already have committed"))
        XCTAssertTrue(model.status.contains("idempotent readback"))
    }

    func testAppIntentAuthenticationPolicies() {
        XCTAssertEqual(RunSandboxIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(PlanOneStepIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(BeginProviderQualificationIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(RecordProviderQualificationIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(QualifyAppleProviderIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(ConfigureOracleRoutingIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(BeginOracleTaskIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(ApplyValidatedActionIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(PrepareWorkspaceIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        XCTAssertEqual(OpenSandboxIntent.authenticationPolicy, .alwaysAllowed)
        if #available(iOS 27.0, *) {
            XCTAssertEqual(RunLongAppleTaskIntent.authenticationPolicy, .requiresLocalDeviceAuthentication)
        }
    }

    func testTraversalIsRejected() throws {for path in ["../secrets","workspace/../config/policy.json","/etc/passwd","workspace//notes","workspace/%2e%2e/x","workspace/a\\b"]{XCTAssertThrowsError(try SandboxPath(path))};XCTAssertNoThrow(try SandboxPath("workspace/notes.md"))}
    func testPatchRequiresExactlyOneMatch() throws {XCTAssertEqual(try exactPatch("Status: pending",old:"pending",replacement:"complete"),"Status: complete");XCTAssertThrowsError(try exactPatch("a a",old:"a",replacement:"b"));XCTAssertThrowsError(try exactPatch("aaa",old:"aa",replacement:"b"));XCTAssertThrowsError(try exactPatch("pending",old:"missing",replacement:"b"))}
    func testUnknownToolsCannotExecute() throws {XCTAssertThrowsError(try AgentAction.parse("{\"kind\":\"tool\",\"tool\":\"shell.exec\",\"arguments\":{}}"));XCTAssertThrowsError(try AgentAction.parse("```json\n{}\n```"))}
    func testStaleHashIsRequiredByEditContract() throws {XCTAssertThrowsError(try ToolCall(tool:.patch,arguments:["path":"workspace/a","old":"a","replacement":"b"]).validated())}
    func testBudgetValidation() throws {var policy=ResourcePolicy();policy.memoryTarget=100;XCTAssertThrowsError(try policy.validated())}
    func testPromptCap() {XCTAssertLessThanOrEqual(boundedPrompt(goal:String(repeating:"g",count:3000),capsule:String(repeating:"s",count:3000),latest:String(repeating:"x",count:10000),limit:2000).count,2000)}
    func testKeychainSetUpdatesWithoutDeletingOrAdding() throws {
        var updates=0,adds=0
        let writer=KeychainWriter(update:{_,_ in updates+=1;return errSecSuccess},add:{_ in adds+=1;return errSecSuccess})
        try Keychain.set("replacement",for:"test",writer:writer)
        XCTAssertEqual(updates,1);XCTAssertEqual(adds,0)
    }
    func testKeychainSetAddsOnlyWhenMissing() throws {
        var updates=0,adds=0
        let writer=KeychainWriter(update:{_,_ in updates+=1;return errSecItemNotFound},add:{_ in adds+=1;return errSecSuccess})
        try Keychain.set("new",for:"test",writer:writer)
        XCTAssertEqual(updates,1);XCTAssertEqual(adds,1)
    }
    func testKeychainSetRetriesUpdateAfterDuplicateRace() throws {
        var updates=0,adds=0
        let writer=KeychainWriter(update:{_,_ in updates+=1;return updates==1 ? errSecItemNotFound:errSecSuccess},add:{_ in adds+=1;return errSecDuplicateItem})
        try Keychain.set("replacement",for:"test",writer:writer)
        XCTAssertEqual(updates,2);XCTAssertEqual(adds,1)
    }
    func testKeychainSetPreservesExistingItemOnUnexpectedUpdateFailure() {
        var adds=0
        let writer=KeychainWriter(update:{_,_ in errSecInteractionNotAllowed},add:{_ in adds+=1;return errSecSuccess})
        XCTAssertThrowsError(try Keychain.set("replacement",for:"test",writer:writer))
        XCTAssertEqual(adds,0)
    }
    func testLegacyReceiptCannotRetainVerifiedQualification() throws {
        let data=Data("""
        {"id":"legacy","goal":"old","status":"verified","origin":"native","summary":"old trace","steps":1,"failures":0,"durationMs":2,"createdAt":"2026-09-10T00:00:00Z","trace":[]}
        """.utf8)
        let receipt=try JSONDecoder().decode(RunReceipt.self,from:data)
        XCTAssertEqual(receipt.status,.completed);XCTAssertTrue(receipt.legacyTraceOnly)
    }
    func testEvidenceStaysAheadOfTruncatedBody() {
        let sha=String(repeating:"a",count:64)
        let result=ToolResult(ok:true,tool:"file.read",result:String(repeating:"body",count:2000),sha256:sha,error_code:nil,evidence:ToolEvidence(path:"workspace/a.txt",sha256:sha,byteCount:8000,readbackKind:"source-read",contentComplete:true))
        let prompt=result.promptJSON(maxCharacters:700)
        XCTAssertLessThanOrEqual(prompt.count,700);XCTAssertTrue(prompt.contains(sha));XCTAssertTrue(prompt.contains("\"bodyTruncated\":true"));XCTAssertFalse(result.isCompleteInPrompt(maxCharacters:700))
    }
    func testGoalContractRequiresTypedExpectedState() throws {
        let contract=try filesystemGoalContract(mode:"exactText",path:"workspace/result.txt",expected:"done")
        XCTAssertEqual(contract.assertions.count,1)
        XCTAssertThrowsError(try filesystemGoalContract(mode:"sha256",path:"workspace/result.txt",expected:"not-a-digest"))
        XCTAssertThrowsError(try filesystemGoalContract(mode:"unknown",path:"workspace/result.txt",expected:"done"))
    }
    func testBackgroundResumeRequiresSafeCheckpointAndMatchingPolicy() throws {
        var policy=ResourcePolicy();policy.provider="apple"
        let checkpoint=RunCheckpoint(runID:"run",goal:"goal",nextStep:1,capsule:"state",lastResult:"latest",phase:"ready",policy:policy)
        let context=BackgroundExecutionContext(protectedDataAvailable:true,workspaceConnected:true,workspaceRequiresNetworkConnectivity:false,backgroundRefreshAvailable:true,nativeProviderAvailable:true,currentPolicy:policy)
        guard case .resume(let plan)=BackgroundExecutionPolicy.evaluate(checkpoint:checkpoint,context:context) else{return XCTFail("Expected a resume plan")}
        XCTAssertEqual(plan.runID,"run");XCTAssertEqual(plan.nextStep,1);XCTAssertFalse(plan.requiresNetworkConnectivity)

        let executing=RunCheckpoint(runID:"run",goal:"goal",nextStep:1,capsule:"state",lastResult:"latest",phase:"executing",policy:policy)
        XCTAssertEqual(BackgroundExecutionPolicy.evaluate(checkpoint:executing,context:context),.reviewRequired(.unsafeExecutingCheckpoint))
        let locked=BackgroundExecutionContext(protectedDataAvailable:false,workspaceConnected:true,workspaceRequiresNetworkConnectivity:false,backgroundRefreshAvailable:true,nativeProviderAvailable:true,currentPolicy:policy)
        XCTAssertEqual(BackgroundExecutionPolicy.evaluate(checkpoint:checkpoint,context:locked),.deferred(.protectedDataUnavailable))
    }
    func testBackgroundCompletionCanOnlyBeClaimedOnce() {
        let latch=BackgroundCompletionLatch()
        XCTAssertTrue(latch.claim());XCTAssertFalse(latch.claim())
    }
    func testProviderQualificationDailyLimitUsesUTCDaysAndAllowsDistinctProbes() {
        let finalSecond=Date(timeIntervalSince1970:86_399)
        let nextDay=Date(timeIntervalSince1970:86_400)
        XCTAssertEqual(ProviderQualificationStore.utcDayNumber(for:finalSecond),0)
        XCTAssertEqual(ProviderQualificationStore.utcDayNumber(for:nextDay),1)
        XCTAssertEqual(ProviderQualificationStore.utcDayNumber(for:Date(timeIntervalSince1970:-1)),-1)

        let strict=qualificationAttempt(id:"00000000-0000-0000-0000-000000000001",probe:.strictJSON,startedAt:finalSecond)
        let read=qualificationAttempt(id:"00000000-0000-0000-0000-000000000002",probe:.readTool,startedAt:finalSecond)
        let repeatedStrict=qualificationAttempt(id:"00000000-0000-0000-0000-000000000006",probe:.strictJSON,startedAt:finalSecond.addingTimeInterval(-1))
        let nextDayStrict=qualificationAttempt(id:"00000000-0000-0000-0000-000000000007",probe:.strictJSON,startedAt:nextDay)
        XCTAssertEqual(
            ProviderQualificationStore.recordedProbes(provider:.apple,onUTCDate:finalSecond,attempts:[strict,read]),
            Set([.strictJSON,.readTool])
        )
        XCTAssertTrue(ProviderQualificationStore.recordedProbes(provider:.apple,onUTCDate:nextDay,attempts:[strict,read]).isEmpty)
        XCTAssertTrue(ProviderQualificationStore.hasUniqueDailyAttempts([strict,read]))
        XCTAssertFalse(ProviderQualificationStore.hasUniqueDailyAttempts([strict,repeatedStrict]))
        XCTAssertTrue(ProviderQualificationStore.hasUniqueDailyAttempts([strict,nextDayStrict]))
    }
    func testProviderQualificationDetectsMaterialClockRollbackFromStartOrFinish() {
        let now=Date(timeIntervalSince1970:1_000)
        let withinTolerance=qualificationAttempt(
            id:"00000000-0000-0000-0000-000000000003",
            probe:.strictJSON,
            startedAt:now.addingTimeInterval(ProviderQualificationStore.clockRollbackToleranceSeconds)
        )
        XCTAssertFalse(ProviderQualificationStore.hasMaterialClockRollback(now:now,attempts:[withinTolerance]))

        let futureStart=qualificationAttempt(
            id:"00000000-0000-0000-0000-000000000004",
            probe:.readTool,
            startedAt:now.addingTimeInterval(ProviderQualificationStore.clockRollbackToleranceSeconds+1)
        )
        XCTAssertTrue(ProviderQualificationStore.hasMaterialClockRollback(now:now,attempts:[futureStart]))

        let futureFinish=qualificationAttempt(
            id:"00000000-0000-0000-0000-000000000005",
            probe:.listTool,
            startedAt:now.addingTimeInterval(-10),
            outcome:.verified,
            finishedAt:now.addingTimeInterval(ProviderQualificationStore.clockRollbackToleranceSeconds+1)
        )
        XCTAssertTrue(ProviderQualificationStore.hasMaterialClockRollback(now:now,attempts:[futureFinish]))
    }
    func testProviderQualificationScoresOnlyTerminalAttempts() {
        let now=Date(timeIntervalSince1970:2_000)
        let completed=Array(ProviderQualificationProbe.allCases.prefix(4)).enumerated().map { index,probe in
            qualificationAttempt(
                id:String(format:"00000000-0000-0000-0000-%012d",index+10),
                probe:probe,
                startedAt:now.addingTimeInterval(TimeInterval(-index-10)),
                outcome:.verified,
                finishedAt:now.addingTimeInterval(TimeInterval(-index-9))
            )
        }
        let pending=qualificationAttempt(
            id:"00000000-0000-0000-0000-000000000020",
            probe:.boundedContext,
            startedAt:now.addingTimeInterval(-1)
        )
        let scored=ProviderQualificationStore.scoredAttempts(
            provider:.apple,
            epochSHA256:String(repeating:"a",count:64),
            now:now,
            attempts:completed+[pending]
        )
        XCTAssertEqual(scored.count,4)
        XCTAssertEqual(Set(scored.map(\.probe)).count,4)
        XCTAssertFalse(scored.contains(where:{$0.attemptID == pending.attemptID}))
    }
    func testProviderQualificationLegacyAttemptPreservesCanonicalSignatureInput() throws {
        let now=Date(timeIntervalSince1970:3_000)
        let attempt=qualificationAttempt(
            id:"00000000-0000-0000-0000-000000000030",
            probe:.strictJSON,
            startedAt:now,
            outcome:.verified,
            finishedAt:now.addingTimeInterval(1)
        )
        let encoder=JSONEncoder()
        encoder.outputFormatting=[.sortedKeys]
        var legacyObject=try JSONSerialization.jsonObject(with:encoder.encode(attempt)) as! [String:Any]
        legacyObject.removeValue(forKey:"schemaPassCount")
        let legacyBytes=try JSONSerialization.data(withJSONObject:legacyObject,options:[.sortedKeys])
        let decoded=try JSONDecoder().decode(ProviderQualificationAttempt.self,from:legacyBytes)
        XCTAssertNil(decoded.schemaPassCount)
        XCTAssertEqual(try encoder.encode(decoded),legacyBytes)
    }

    private func qualificationAttempt(
        id:String,
        probe:ProviderQualificationProbe,
        startedAt:Date,
        outcome:ProviderQualificationOutcome = .started,
        finishedAt:Date? = nil
    )->ProviderQualificationAttempt {
        ProviderQualificationAttempt(
            attemptID:id,
            provider:.apple,
            epochSHA256:String(repeating:"a",count:64),
            adapterSHA256:nil,
            probe:probe,
            outcome:outcome,
            schemaPassCount:outcome == .verified ? 1:0,
            assertionPassCount:outcome == .verified ? 1:0,
            assertionCount:1,
            promptCharacterCount:2_000,
            durationBucketMilliseconds:outcome == .started ? 0:500,
            appIntentReturnObserved:true,
            startedAt:startedAt,
            finishedAt:finishedAt
        )
    }
}
