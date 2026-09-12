import Foundation
import Security

private actor HeldLocalAccessPolicy {
    private var continuation: CheckedContinuation<Bool, Never>?
    private var readinessWaiters: [CheckedContinuation<Void, Never>] = []

    func evaluate() async -> Bool {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            let waiters = readinessWaiters
            readinessWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
    }

    func waitUntilHeld() async {
        if continuation != nil { return }
        await withCheckedContinuation { readinessWaiters.append($0) }
    }

    func release(accepted: Bool) {
        let held = continuation
        continuation = nil
        held?.resume(returning: accepted)
    }
}

private enum InjectedLocalAuthenticationError: LocalizedError {
    case cancelled

    var errorDescription: String? { "INJECTED_LOCAL_AUTHENTICATION_CANCELLED" }
}

final class RecordingNativeTransport: NativeHTTPPerforming, @unchecked Sendable {
    struct Planned: Sendable {
        let status: Int
        let data: Data
        let headers: [String: String]
    }
    private let lock = NSLock()
    private var planned: [Planned]
    private var injectedFailures: [SandboxError]
    private var recordedRequests: [(URLRequest, Int)] = []
    private var activeResponsesByToken: [String: Data] = [:]
    private let automaticActivation: Bool

    var requests: [(URLRequest, Int)] {
        lock.lock()
        defer { lock.unlock() }
        return recordedRequests
    }

    init(
        _ planned: [Planned],
        injectedFailures: [SandboxError] = [],
        automaticActivation: Bool = true
    ) {
        self.planned = planned
        self.injectedFailures = injectedFailures
        self.automaticActivation = automaticActivation
    }

    func append(_ plannedResponse: Planned) {
        lock.lock()
        planned.append(plannedResponse)
        lock.unlock()
    }

    private func dequeue(_ request: URLRequest, maximumResponseBytes: Int) throws -> Planned {
        lock.lock()
        defer { lock.unlock() }
        recordedRequests.append((request, maximumResponseBytes))
        if !injectedFailures.isEmpty { throw injectedFailures.removeFirst() }
        let path = request.url?.path
        if automaticActivation,
           path == "/api/auth/apple/native/activate",
           let authorization = request.value(forHTTPHeaderField: "Authorization"),
           authorization.hasPrefix("Bearer "),
           let body = activeResponsesByToken[String(authorization.dropFirst(7))] {
            return Planned(
                status: 200,
                data: body,
                headers: ["Cache-Control": "no-store", "Content-Type": "application/json"]
            )
        }
        guard !planned.isEmpty else { throw SandboxError.blocked("UNEXPECTED_HTTP_REQUEST") }
        let next = planned.removeFirst()
        guard automaticActivation,
              (200...299).contains(next.status),
              path == "/api/auth/apple/native/exchange" || path == "/api/auth/apple/native/refresh",
              var payload = try? JSONSerialization.jsonObject(with: next.data) as? [String: Any],
              let token = payload["token"] as? String else {
            return next
        }
        payload["schemaVersion"] = 2
        payload["activationState"] = path == "/api/auth/apple/native/exchange" ? "pending" : "active"
        let upgraded = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        if path == "/api/auth/apple/native/exchange" {
            payload["activationState"] = "active"
            activeResponsesByToken[token] = try JSONSerialization.data(
                withJSONObject: payload,
                options: [.sortedKeys]
            )
        }
        var headers = next.headers
        headers["Content-Type"] = "application/json"
        return Planned(status: next.status, data: upgraded, headers: headers)
    }

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        let next = try dequeue(request, maximumResponseBytes: maximumResponseBytes)
        guard next.data.count <= maximumResponseBytes else { throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_TOO_LARGE") }
        let response = HTTPURLResponse(url: request.url!, statusCode: next.status, httpVersion: "HTTP/1.1", headerFields: next.headers)!
        return NativeHTTPResult(data: next.data, response: response)
    }
}

actor OutOfOrderNativeTransport: NativeHTTPPerforming {
    private let olderExchangeBody: Data
    private let newerExchangeBody: Data
    private let revokeBody: Data
    private let revokeStatus: Int
    private var exchangeCount = 0
    private var firstExchangeContinuation: CheckedContinuation<NativeHTTPResult, Never>?
    private var observedPaths: [String] = []

    init(
        olderExchangeBody: Data,
        newerExchangeBody: Data,
        revokeBody: Data,
        revokeStatus: Int = 200
    ) {
        self.olderExchangeBody = olderExchangeBody
        self.newerExchangeBody = newerExchangeBody
        self.revokeBody = revokeBody
        self.revokeStatus = revokeStatus
    }

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        let path = request.url?.path ?? ""
        observedPaths.append(path)
        if path == "/api/auth/apple/native/revoke" {
            return response(
                request,
                body: revokeBody,
                maximumResponseBytes: maximumResponseBytes,
                status: revokeStatus
            )
        }
        if path == "/api/auth/apple/native/activate" {
            let authorization = request.value(forHTTPHeaderField: "Authorization") ?? ""
            let olderToken = try token(from: olderExchangeBody)
            let body = authorization == "Bearer \(olderToken)" ? olderExchangeBody : newerExchangeBody
            return response(
                request,
                body: try sessionBody(body, activationState: "active"),
                maximumResponseBytes: maximumResponseBytes
            )
        }
        guard path == "/api/auth/apple/native/exchange" else {
            throw SandboxError.blocked("UNEXPECTED_HTTP_REQUEST")
        }
        exchangeCount += 1
        if exchangeCount == 1 {
            return await withCheckedContinuation { continuation in
                firstExchangeContinuation = continuation
            }
        }
        return response(
            request,
            body: try sessionBody(newerExchangeBody, activationState: "pending"),
            maximumResponseBytes: maximumResponseBytes
        )
    }

    func waitForFirstExchange() async {
        while firstExchangeContinuation == nil { await Task.yield() }
    }

    func completeFirstExchange() {
        guard let continuation = firstExchangeContinuation else { return }
        firstExchangeContinuation = nil
        let request = URLRequest(url: URL(string: "https://sandbox.example.test/api/auth/apple/native/exchange")!)
        continuation.resume(returning: response(
            request,
            body: try! sessionBody(olderExchangeBody, activationState: "pending"),
            maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes
        ))
    }

    func paths() -> [String] { observedPaths }

    private func response(
        _ request: URLRequest,
        body: Data,
        maximumResponseBytes: Int,
        status: Int = 200
    ) -> NativeHTTPResult {
        precondition(body.count <= maximumResponseBytes)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Cache-Control": "no-store", "Content-Type": "application/json"])!
        return NativeHTTPResult(data: body, response: response)
    }

    private func token(from body: Data) throws -> String {
        guard let payload = try JSONSerialization.jsonObject(with: body) as? [String: Any],
              let token = payload["token"] as? String else {
            throw SandboxError.blocked("INVALID_SESSION_FIXTURE")
        }
        return token
    }

    private func sessionBody(_ body: Data, activationState: String) throws -> Data {
        guard var payload = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw SandboxError.blocked("INVALID_SESSION_FIXTURE")
        }
        payload["schemaVersion"] = 2
        payload["activationState"] = activationState
        return try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    }
}

actor HeldNativeRefreshTransport: NativeHTTPPerforming {
    private let refreshedBody: Data
    private let revokeStatus: Int
    private let holdFirstRevoke: Bool
    private var refreshContinuation: CheckedContinuation<NativeHTTPResult, Never>?
    private var revokeContinuation: CheckedContinuation<NativeHTTPResult, Never>?
    private var readinessWaiters: [CheckedContinuation<Void, Never>] = []
    private var revokeReadinessWaiters: [CheckedContinuation<Void, Never>] = []
    private var observedPaths: [String] = []

    init(refreshedBody: Data, revokeStatus: Int, holdFirstRevoke: Bool = false) {
        self.refreshedBody = refreshedBody
        self.revokeStatus = revokeStatus
        self.holdFirstRevoke = holdFirstRevoke
    }

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        let path = request.url?.path ?? ""
        observedPaths.append(path)
        if path == "/api/auth/apple/native/refresh" {
            return await withCheckedContinuation { continuation in
                refreshContinuation = continuation
                let waiters = readinessWaiters
                readinessWaiters.removeAll()
                waiters.forEach { $0.resume() }
            }
        }
        guard path == "/api/auth/apple/native/revoke" else {
            throw SandboxError.blocked("UNEXPECTED_HTTP_REQUEST")
        }
        if holdFirstRevoke, revokeContinuation == nil {
            return await withCheckedContinuation { continuation in
                revokeContinuation = continuation
                let waiters = revokeReadinessWaiters
                revokeReadinessWaiters.removeAll()
                waiters.forEach { $0.resume() }
            }
        }
        return revokeResponse(request, maximumResponseBytes: maximumResponseBytes)
    }

    private func revokeResponse(
        _ request: URLRequest,
        maximumResponseBytes: Int
    ) -> NativeHTTPResult {
        let body = revokeStatus == 200
            ? try! JSONSerialization.data(withJSONObject: ["revoked": true])
            : try! JSONSerialization.data(withJSONObject: ["code": "SERVICE_UNAVAILABLE", "error": "offline"])
        return response(
            request,
            body: body,
            maximumResponseBytes: maximumResponseBytes,
            status: revokeStatus
        )
    }

    func waitUntilRefreshHeld() async {
        if refreshContinuation != nil { return }
        await withCheckedContinuation { readinessWaiters.append($0) }
    }

    func releaseRefresh() {
        guard let continuation = refreshContinuation else { return }
        refreshContinuation = nil
        let request = URLRequest(
            url: URL(string: "https://sandbox.example.test/api/auth/apple/native/refresh")!
        )
        continuation.resume(returning: response(
            request,
            body: refreshedBody,
            maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes,
            status: 200
        ))
    }

    func waitUntilRevokeHeld() async {
        if revokeContinuation != nil { return }
        await withCheckedContinuation { revokeReadinessWaiters.append($0) }
    }

    func releaseRevoke() {
        guard let continuation = revokeContinuation else { return }
        revokeContinuation = nil
        let request = URLRequest(
            url: URL(string: "https://sandbox.example.test/api/auth/apple/native/revoke")!
        )
        continuation.resume(returning: revokeResponse(
            request,
            maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes
        ))
    }

    func paths() -> [String] { observedPaths }

    private func response(
        _ request: URLRequest,
        body: Data,
        maximumResponseBytes: Int,
        status: Int
    ) -> NativeHTTPResult {
        precondition(body.count <= maximumResponseBytes)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Cache-Control": "no-store", "Content-Type": "application/json"]
        )!
        return NativeHTTPResult(data: body, response: response)
    }
}

actor PairedHeldRefreshTransport: NativeHTTPPerforming {
    private struct Held {
        let request: URLRequest
        let maximumResponseBytes: Int
        let continuation: CheckedContinuation<NativeHTTPResult, Never>
    }

    private var held: [Int: Held] = [:]
    private var nextIndex = 0
    private var waiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var observedPaths: [String] = []

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        let path = request.url?.path ?? ""
        observedPaths.append(path)
        guard path == "/api/auth/apple/native/refresh" else {
            throw SandboxError.blocked("UNEXPECTED_HTTP_REQUEST")
        }
        let index = nextIndex
        nextIndex += 1
        return await withCheckedContinuation { continuation in
            held[index] = Held(
                request: request,
                maximumResponseBytes: maximumResponseBytes,
                continuation: continuation
            )
            let ready = waiters.filter { nextIndex >= $0.0 }
            waiters.removeAll { nextIndex >= $0.0 }
            ready.forEach { $0.1.resume() }
        }
    }

    func waitUntilHeld(count: Int) async {
        if nextIndex >= count { return }
        await withCheckedContinuation { waiters.append((count, $0)) }
    }

    func release(index: Int, body: Data) throws {
        guard let held = held.removeValue(forKey: index),
              body.count <= held.maximumResponseBytes,
              let url = held.request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Cache-Control": "no-store", "Content-Type": "application/json"]
              ) else {
            throw SandboxError.blocked("HELD_REFRESH_FIXTURE_INVALID")
        }
        held.continuation.resume(returning: NativeHTTPResult(data: body, response: response))
    }

    func paths() -> [String] { observedPaths }
}

actor HeldSnapshotChangeTransport: NativeHTTPPerforming {
    private var responseContinuation: CheckedContinuation<NativeHTTPResult, Never>?
    private var readinessWaiters: [CheckedContinuation<Void, Never>] = []
    private var requests = 0

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        requests += 1
        guard requests == 1, maximumResponseBytes == NativeServiceLimits.syncResponseBytes else {
            throw SandboxError.blocked("UNEXPECTED_POST_CANCELLATION_SYNC_REQUEST")
        }
        return await withCheckedContinuation { continuation in
            responseContinuation = continuation
            let waiters = readinessWaiters
            readinessWaiters.removeAll()
            waiters.forEach { $0.resume() }
        }
    }

    func waitUntilHeld() async {
        if responseContinuation != nil { return }
        await withCheckedContinuation { readinessWaiters.append($0) }
    }

    func releaseSnapshotChanged() throws {
        guard let continuation = responseContinuation,
              let response = HTTPURLResponse(
                  url: URL(string: "https://sandbox.example.test/api/sync")!,
                  statusCode: 409,
                  httpVersion: "HTTP/1.1",
                  headerFields: ["Content-Type": "application/json"]
              ) else {
            throw SandboxError.blocked("HELD_SNAPSHOT_FIXTURE_INVALID")
        }
        let data = try JSONSerialization.data(withJSONObject: [
            "code": "SYNC_SNAPSHOT_CHANGED",
            "error": "changed",
        ])
        responseContinuation = nil
        continuation.resume(returning: NativeHTTPResult(data: data, response: response))
    }

    func requestCount() -> Int { requests }
}

private final class AdversarialBearerStore: @unchecked Sendable {
    private let valueLock = NSLock()
    private var value: String?
    private var suspendNextRead = true
    let readCaptured = DispatchSemaphore(value: 0)
    let resumeRead = DispatchSemaphore(value: 0)
    let writeEntered = DispatchSemaphore(value: 0)

    init(value: String) {
        self.value = value
    }

    func read() -> String? {
        valueLock.lock()
        let snapshot = value
        let shouldSuspend = suspendNextRead
        suspendNextRead = false
        valueLock.unlock()
        if shouldSuspend {
            readCaptured.signal()
            resumeRead.wait()
        }
        return snapshot
    }

    func write(_ value: String) {
        writeEntered.signal()
        valueLock.lock()
        self.value = value
        valueLock.unlock()
    }

    func delete() {
        valueLock.lock()
        value = nil
        valueLock.unlock()
    }

    func current() -> String? {
        valueLock.lock()
        defer { valueLock.unlock() }
        return value
    }
}

private final class ConcurrentFirstUseURLProtocol: URLProtocol, @unchecked Sendable {
    static let body = Data("race-free".utf8)

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "native-transport.test"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Length": String(Self.body.count), "Cache-Control": "no-store"]
              ) else {
            client?.urlProtocol(self, didFailWithError: SandboxError.blocked("TEST_RESPONSE_INVALID"))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private final class TransferMigrationStore: @unchecked Sendable {
    var user: String?
    var accountMode: String?
    var transferBlock: String?
    var migration: String?
    var workspaceBinding: String?
    var recovery: [String: String] = [:]
    var recoveryRegistrations: [String: String] = [:]
    var failOnce = ""
    var alwaysFailUserWrite = false
    var failReadAt: [String: Int] = [:]
    private var readCounts: [String: Int] = [:]

    init(user: String) { self.user = user }

    func shouldFail(_ boundary: String) -> Bool {
        guard failOnce == boundary else { return false }
        failOnce = ""
        return true
    }

    func checkedRead(_ boundary: String, value: String?) throws -> String? {
        let count = (readCounts[boundary] ?? 0) + 1
        readCounts[boundary] = count
        if failReadAt[boundary] == count {
            throw SandboxError.blocked("KEYCHAIN_READ_FAILED")
        }
        return value
    }
}

private final class InjectedCheckedStringStore: @unchecked Sendable {
    var value: String?
    let failingReadCalls: Set<Int>
    let failReadsAfterDelete: Bool
    private(set) var readCount = 0
    private(set) var writeCount = 0
    private(set) var deleteCount = 0

    init(
        value: String? = nil,
        failingReadCalls: Set<Int> = [],
        failReadsAfterDelete: Bool = false
    ) {
        self.value = value
        self.failingReadCalls = failingReadCalls
        self.failReadsAfterDelete = failReadsAfterDelete
    }

    func read() throws -> String? {
        readCount += 1
        if failingReadCalls.contains(readCount) || (failReadsAfterDelete && deleteCount > 0) {
            throw SandboxError.blocked("KEYCHAIN_READ_FAILED")
        }
        return value
    }

    func write(_ newValue: String) {
        writeCount += 1
        value = newValue
    }

    func delete() {
        deleteCount += 1
        value = nil
    }
}

private final class InjectedCheckedKeyedStore: @unchecked Sendable {
    var values: [String: String]
    let failingReadCalls: Set<Int>
    let failReadsAfterDelete: Bool
    private(set) var readCount = 0
    private(set) var writeCount = 0
    private(set) var deleteCount = 0

    init(
        values: [String: String] = [:],
        failingReadCalls: Set<Int> = [],
        failReadsAfterDelete: Bool = false
    ) {
        self.values = values
        self.failingReadCalls = failingReadCalls
        self.failReadsAfterDelete = failReadsAfterDelete
    }

    func read(_ key: String) throws -> String? {
        readCount += 1
        if failingReadCalls.contains(readCount) || (failReadsAfterDelete && deleteCount > 0) {
            throw SandboxError.blocked("KEYCHAIN_READ_FAILED")
        }
        return values[key]
    }

    func write(_ key: String, _ value: String) {
        writeCount += 1
        values[key] = value
    }

    func delete(_ key: String) {
        deleteCount += 1
        values.removeValue(forKey: key)
    }
}

private final class ReceivedClockProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let expectedValue: Int
    private var sampleCount = 0

    init(expectedValue: Int) { self.expectedValue = expectedValue }

    func sample() -> Int {
        lock.lock()
        defer { lock.unlock() }
        sampleCount += 1
        return sampleCount <= 2 ? expectedValue : expectedValue + 10_000
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return sampleCount
    }
}

private final class ConcurrentRecoveryRegistrationStore: @unchecked Sendable {
    private let condition = NSCondition()
    private var secretItems: [String: String] = [:]
    private var registrationItems: [String: String] = [:]
    private var firstEnumerationCount = 0
    private var failures: [String] = []

    func vault(accountBinding: String) -> NativeRecoverySecretVault {
        NativeRecoverySecretVault(
            read: readSecret,
            write: writeSecret,
            delete: deleteSecret,
            readRegistration: readRegistration,
            writeRegistration: writeRegistration,
            deleteRegistration: deleteRegistration,
            listRegistrations: listRegistrations,
            accountBinding: { accountBinding }
        )
    }

    func record(_ error: Error) {
        condition.lock()
        failures.append(error.localizedDescription)
        condition.unlock()
    }

    func recordedFailures() -> [String] {
        condition.lock()
        defer { condition.unlock() }
        return failures
    }

    private func readSecret(_ key: String) -> String? {
        condition.lock()
        defer { condition.unlock() }
        return secretItems[key]
    }

    private func writeSecret(_ key: String, _ value: String) {
        condition.lock()
        secretItems[key] = value
        condition.unlock()
    }

    private func deleteSecret(_ key: String) {
        condition.lock()
        secretItems.removeValue(forKey: key)
        condition.unlock()
    }

    private func readRegistration(_ workspaceId: String) -> String? {
        condition.lock()
        defer { condition.unlock() }
        return registrationItems[workspaceId]
    }

    private func writeRegistration(_ workspaceId: String, _ value: String) {
        condition.lock()
        registrationItems[workspaceId] = value
        condition.unlock()
    }

    private func deleteRegistration(_ workspaceId: String) {
        condition.lock()
        registrationItems.removeValue(forKey: workspaceId)
        condition.unlock()
    }

    private func listRegistrations() throws -> [String: String] {
        condition.lock()
        let snapshot = registrationItems
        if firstEnumerationCount < 2 {
            firstEnumerationCount += 1
            if firstEnumerationCount == 2 {
                condition.broadcast()
            } else {
                let deadline = Date().addingTimeInterval(2)
                while firstEnumerationCount < 2 {
                    guard condition.wait(until: deadline) else {
                        condition.unlock()
                        throw SandboxError.blocked("CONCURRENT_RECOVERY_TEST_TIMEOUT")
                    }
                }
            }
        }
        condition.unlock()
        return snapshot
    }
}

@main
enum NativeAccountSyncContractTests {
    static let now = Int(Date().timeIntervalSince1970)
    static let bearer = "v1." + String(repeating: "A", count: 43)

    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func requireKeychainReadFailure(_ context: String, _ operation: () throws -> Void) {
        do {
            try operation()
            fatalError("\(context) treated a Keychain read failure as missing state")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "\(context) returned the wrong read failure")
        } catch {
            fatalError("\(context) returned an unexpected error: \(error.localizedDescription)")
        }
    }

    static func json(_ value: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    }

    static func jsonObject<T: Encodable>(_ value: T) throws -> Any {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
    }

    static func main() async throws {
        try nonceContract()
        try await localAccessGenerationContract()
        try await possibleCredentialReviewContract()
        lifecycleGenerationContract()
        syncPathPolicyContract()
        try keychainPolicyContract()
        try bearerVaultAtomicityContract()
        try await durableVaultReadFailureContract()
        try hostedAdmissionContract()
        try await urlSessionConcurrentFirstUseContract()
        try await authLifecycleContract()
        try await pendingActivationContract()
        try await activationAdversarialContract()
        try await responseTimingAndRefreshAdversarialContract()
        try await revocationFollowUpContract()
        try accountDeletionRecoveryContract()
        try await accountDeletionContract()
        try await cancelledSnapshotReadDoesNotRetryTransport()
        try await syncTransportContract()
        try recoveryContract()
        try recoveryRegistryMigrationContract()
        try concurrentRecoveryRegistrationContract()
        try transferMigrationContract()
        print("Native account/sync contracts passed: Apple nonce binding, bounded device-only revocation follow-up, local-only bearer lifecycle, explicit sync requests, and recoverable iCloud Keychain semantics.")
    }

    static func lifecycleGenerationContract() {
        var generation = NativeLifecycleGeneration()
        let delayedUnlock = generation.capture()
        require(generation.isCurrent(delayedUnlock), "new native sync operation was stale")
        generation.invalidate()
        require(!generation.isCurrent(delayedUnlock), "lock did not retire a delayed native sync completion")
        let afterLock = generation.capture()
        require(generation.isCurrent(afterLock), "post-lock native sync generation was not current")

        let expiry = Date(timeIntervalSince1970: 1_000)
        let authority = NativeBearerAuthorityWindow(expiresAt: expiry)
        require(authority.isAvailable(at: Date(timeIntervalSince1970: 999)), "bearer authority ended before its exact expiry")
        require(authority.remainingSeconds(at: Date(timeIntervalSince1970: 999)) == 1, "bearer authority delay changed")
        require(!authority.isAvailable(at: expiry), "bearer authority survived its exact expiry")
        require(authority.remainingSeconds(at: Date(timeIntervalSince1970: 1_001)) == nil, "expired bearer exposed a timer delay")
    }

    @MainActor
    static func localAccessGenerationContract() async throws {
        let gate = ExecutionContinuationGate()
        let executionGeneration = gate.capture()
        let heldPolicy = HeldLocalAccessPolicy()
        var protectedMutations = 0
        let authentication = Task { @MainActor in
            let lease = try await LocalAccess.authenticate(
                executionGeneration: executionGeneration,
                gate: gate,
                hasLocalAccount: { true },
                evaluatePolicy: { await heldPolicy.evaluate() }
            )
            try lease.requireCurrent()
            protectedMutations += 1
        }

        await heldPolicy.waitUntilHeld()
        gate.invalidate()
        await heldPolicy.release(accepted: true)
        do {
            try await authentication.value
            fatalError("held local authentication crossed the lock generation")
        } catch let error as SandboxError {
            require(error.localizedDescription == "LOCAL_SANDBOX_LOCKED", "held local authentication returned the wrong lock error")
        }
        require(protectedMutations == 0, "held local authentication resumed a protected mutation after lock")

        let currentGate = ExecutionContinuationGate()
        do {
            _ = try await LocalAccess.authenticate(
                gate: currentGate,
                hasLocalAccount: { true },
                evaluatePolicy: { throw InjectedLocalAuthenticationError.cancelled }
            )
            fatalError("current-generation authentication cancellation unexpectedly succeeded")
        } catch {
            require(error.localizedDescription == "INJECTED_LOCAL_AUTHENTICATION_CANCELLED", "current-generation authentication error was not preserved")
        }
    }

    static func cancelledSnapshotReadDoesNotRetryTransport() async throws {
        let transport = HeldSnapshotChangeTransport()
        let api = NativeWorkspaceSyncAPI(
            endpoints: try NativeServiceEndpoints(origin: URL(string: "https://sandbox.example.test")!),
            transport: transport
        )
        let read = Task {
            try await api.readWorkspace(workspaceId: String(repeating: "W", count: 32), bearer: bearer)
        }

        await transport.waitUntilHeld()
        read.cancel()
        try await transport.releaseSnapshotChanged()
        do {
            _ = try await read.value
            fatalError("cancelled snapshot read retried its transport")
        } catch is CancellationError {}
        let requestCount = await transport.requestCount()
        require(requestCount == 1, "cancelled snapshot read issued a second client request")
    }

    static func syncPathPolicyContract() {
        for path in [
            "workspace/signing-key.p8",
            "workspace/private-exports/token.txt",
            "output/profile.json",
            "workspace/credentials/account.txt",
            "output/.env.production",
        ] {
            require(!isNativeDefaultSyncPath(path), "native encrypted sync admitted private path \(path)")
        }
        require(isNativeDefaultSyncPath("workspace/reports/profile-notes.md"), "native encrypted sync rejected an ordinary workspace document")
        require(isNativeDefaultSyncPath("output/result.txt"), "native encrypted sync rejected an ordinary output document")
    }

    static func nonceContract() throws {
        let bytes = Data((0..<32).map(UInt8.init))
        let raw = try NativeAppleNonce.make { count in
            require(count == 32, "nonce did not request 256 bits")
            return bytes
        }
        require(raw == "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "raw nonce encoding drifted")
        let hash = try NativeAppleNonce.requestHash(raw)
        require(hash == "6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A", "Apple request nonce was not SHA-256 base64url")
        let randomA = try NativeAppleNonce.make(), randomB = try NativeAppleNonce.make()
        require(randomA != randomB, "two random nonces unexpectedly matched")
        require(!NativeAccountDeletionKey.valid("v1." + String(repeating: "I", count: 42) + "B"), "account deletion accepted a non-canonical base64url tail")
        do {
            _ = try NativeAppleNonce.make { _ in Data(repeating: 0, count: 31) }
            fatalError("nonce accepted the wrong random byte count")
        } catch let error as SandboxError {
            require(error.localizedDescription == "SECURE_RANDOM_LENGTH_INVALID", "nonce length failure was ambiguous")
        }
        let decodedAuthorizationCode = try NativeAppleAuthorizationCode.strictUTF8(Data("one-use-code".utf8))
        require(
            decodedAuthorizationCode == "one-use-code",
            "authorization code did not decode as strict UTF-8"
        )
        for invalidCode in [nil, Data(), Data([0xff]), Data(repeating: 0x61, count: 8_001)] as [Data?] {
            do {
                _ = try NativeAppleAuthorizationCode.strictUTF8(invalidCode)
                fatalError("authorization code accepted missing, malformed, or oversized bytes")
            } catch let error as SandboxError {
                require(
                    error.localizedDescription == "APPLE_AUTHORIZATION_CODE_INVALID",
                    "authorization code failure was ambiguous"
                )
            }
        }
    }

    static func possibleCredentialReviewContract() async throws {
        let acknowledgement = String(repeating: "R", count: 43)
        for invalidAcknowledgementID in [
            "",
            String(repeating: "R", count: 42),
            String(repeating: "R", count: 42) + "!",
        ] {
            do {
                _ = try NativeAppleCredentialReviewAcknowledgementID(invalidAcknowledgementID)
                fatalError("credential review accepted an invalid acknowledgement identifier")
            } catch let error as SandboxError {
                require(error.localizedDescription == "APPLE_AUTH_CREDENTIAL_REVIEW_ID_INVALID", "invalid credential review identifier returned the wrong error")
            }
        }
        let session = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: bearer,
            expiresAt: now + 900,
            accountMode: .linked
        )
        var storedBearer: String? = String(decoding: try JSONEncoder().encode(session), as: UTF8.self)
        let vault = NativeBearerVault(
            read: { storedBearer },
            write: { storedBearer = $0 },
            delete: { storedBearer = nil }
        )
        let transport = RecordingNativeTransport([
            .init(status: 200, data: try json([
                "manualReviewRequired": true,
                "acknowledgementId": acknowledgement,
                "markedAt": now - 60,
            ]), headers: ["Content-Type": "application/json; charset=utf-8"]),
            .init(status: 200, data: try json(["acknowledged": true]), headers: ["Content-Type": "application/json"]),
            .init(status: 200, data: try json([
                "manualReviewRequired": false,
                "acknowledgementId": NSNull(),
                "markedAt": NSNull(),
            ]), headers: ["Content-Type": "application/json"]),
        ])
        let endpoints = try NativeServiceEndpoints(origin: URL(string: "https://review.example.test")!)
        let controller = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
            vault: vault
        )

        guard case .required(let receipt) = try await controller.possibleCredentialReview(now: now) else {
            fatalError("possible Apple credential did not produce a review receipt")
        }
        require(receipt.markedAt == now - 60, "credential review detection time changed")
        require(receipt.acknowledgementID.rawValue == acknowledgement, "credential review receipt changed")
        let current = try await controller.acknowledgePossibleCredentialReview(
            receipt.acknowledgementID,
            now: now
        )
        require(current == .clear, "confirmed credential review did not reread current server state")
        require(transport.requests.count == 3, "credential review did not perform GET, POST, final GET")
        let first = transport.requests[0]
        require(first.0.httpMethod == "GET", "credential review status did not use GET")
        require(first.0.url?.path == "/api/auth/apple/possible-credential", "credential review used the wrong path")
        require(first.0.value(forHTTPHeaderField: "Authorization") == "Bearer \(bearer)", "credential review omitted its native bearer")
        require(first.0.value(forHTTPHeaderField: "Cookie") == nil, "credential review leaked an ambient cookie")
        require(first.0.value(forHTTPHeaderField: "Accept") == "application/json", "credential review omitted its response type")
        require(first.0.value(forHTTPHeaderField: "Content-Type") == nil, "credential review GET sent a content type")
        require(first.1 == NativeServiceLimits.credentialReviewResponseBytes, "credential review response was not bounded")
        let acknowledgementRequest = transport.requests[1]
        require(acknowledgementRequest.0.httpMethod == "POST", "credential review acknowledgement did not use POST")
        require(acknowledgementRequest.0.url?.path == "/api/auth/apple/possible-credential", "credential review acknowledgement used the wrong path")
        require(acknowledgementRequest.0.value(forHTTPHeaderField: "Authorization") == "Bearer \(bearer)", "credential review acknowledgement omitted its native bearer")
        require(acknowledgementRequest.0.value(forHTTPHeaderField: "Cookie") == nil, "credential review acknowledgement leaked an ambient cookie")
        require(acknowledgementRequest.0.value(forHTTPHeaderField: "Content-Type") == "application/json", "credential review acknowledgement omitted JSON content type")
        let acknowledgementBody = try JSONSerialization.jsonObject(
            with: acknowledgementRequest.0.httpBody ?? Data()
        ) as? [String: String]
        require(
            acknowledgementBody == ["acknowledgementId": acknowledgement],
            "credential review acknowledgement body was not the exact receipt"
        )
        require(
            (acknowledgementRequest.0.httpBody?.count ?? Int.max) <= NativeServiceLimits.credentialReviewRequestBytes,
            "credential review acknowledgement exceeded its request bound"
        )
        require(transport.requests[2].0.httpMethod == "GET", "credential review cleared UI state without a final status read")

        for invalid in [
            ["manualReviewRequired": false, "acknowledgementId": acknowledgement, "markedAt": now] as [String: Any],
            ["manualReviewRequired": true, "acknowledgementId": NSNull(), "markedAt": now] as [String: Any],
            ["manualReviewRequired": true, "acknowledgementId": String(repeating: "R", count: 42), "markedAt": now] as [String: Any],
            ["manualReviewRequired": true, "acknowledgementId": acknowledgement, "markedAt": -1] as [String: Any],
            ["manualReviewRequired": true, "acknowledgementId": acknowledgement, "markedAt": NativeServiceLimits.maximumSafeInteger + 1] as [String: Any],
            ["manualReviewRequired": false, "acknowledgementId": NSNull(), "markedAt": NSNull(), "unexpected": true] as [String: Any],
        ] {
            let invalidTransport = RecordingNativeTransport([
                .init(status: 200, data: try json(invalid), headers: ["Content-Type": "application/json"]),
            ])
            do {
                _ = try await NativeAppleAuthAPI(endpoints: endpoints, transport: invalidTransport)
                    .possibleCredentialReview(bearer: bearer)
                fatalError("credential review accepted an invalid response union")
            } catch let error as SandboxError {
                require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "invalid credential review returned the wrong error")
            }
        }

        let wrongTypeTransport = RecordingNativeTransport([
            .init(status: 200, data: try json([
                "manualReviewRequired": false,
                "acknowledgementId": NSNull(),
                "markedAt": NSNull(),
            ]), headers: ["Content-Type": "text/plain"]),
        ])
        do {
            _ = try await NativeAppleAuthAPI(endpoints: endpoints, transport: wrongTypeTransport)
                .possibleCredentialReview(bearer: bearer)
            fatalError("credential review accepted a non-JSON success")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "credential review content type returned the wrong error")
        }

        for invalidAcknowledgement in [
            ["acknowledged": false] as [String: Any],
            ["acknowledged": true, "unexpected": true] as [String: Any],
        ] {
            let invalidTransport = RecordingNativeTransport([
                .init(status: 200, data: try json(invalidAcknowledgement), headers: ["Content-Type": "application/json"]),
            ])
            do {
                try await NativeAppleAuthAPI(endpoints: endpoints, transport: invalidTransport)
                    .acknowledgePossibleCredentialReview(
                        bearer: bearer,
                        acknowledgementID: try NativeAppleCredentialReviewAcknowledgementID(acknowledgement)
                    )
                fatalError("credential review accepted an invalid acknowledgement")
            } catch let error as SandboxError {
                require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "invalid review acknowledgement returned the wrong error")
            }
        }

        let staleTransport = RecordingNativeTransport([
            .init(status: 409, data: try json([
                "code": "APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED",
                "error": "Review current state.",
            ]), headers: ["Content-Type": "application/json"]),
        ])
        do {
            try await NativeAppleAuthAPI(endpoints: endpoints, transport: staleTransport)
                .acknowledgePossibleCredentialReview(
                    bearer: bearer,
                    acknowledgementID: try NativeAppleCredentialReviewAcknowledgementID(acknowledgement)
                )
            fatalError("credential review accepted a stale acknowledgement receipt")
        } catch let error as NativeServiceError {
            require(error.status == 409, "stale credential review lost its status")
            require(error.code == "APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED", "stale credential review lost its code")
        }
    }

    static func keychainPolicyContract() throws {
        var localQuery: NSDictionary?
        var localAttributes: NSDictionary?
        let local = KeychainWriter(
            update: { query, attributes in localQuery = query; localAttributes = attributes; return errSecSuccess },
            add: { _ in errSecSuccess }
        )
        try Keychain.set("opaque", for: "native-test", writer: local)
        require((localQuery?[kSecAttrSynchronizable] as? Bool) == false, "native bearer query was synchronizable")
        require(CFEqual(localAttributes?[kSecAttrAccessible] as CFTypeRef?, kSecAttrAccessibleWhenUnlockedThisDeviceOnly), "native bearer was not device-only")

        var cloudQuery: NSDictionary?
        var cloudAttributes: NSDictionary?
        let cloud = KeychainWriter(
            update: { query, attributes in cloudQuery = query; cloudAttributes = attributes; return errSecSuccess },
            add: { _ in errSecSuccess }
        )
        try Keychain.setSynchronizable("recovery", for: "cloud-test", writer: cloud)
        require((cloudQuery?[kSecAttrSynchronizable] as? Bool) == true, "recovery secret was not synchronizable")
        require(CFEqual(cloudAttributes?[kSecAttrAccessible] as CFTypeRef?, kSecAttrAccessibleWhenUnlocked), "recovery secret used an incompatible accessibility policy")

        let registrationWorkspace = String(repeating: "K", count: 32)
        let registrationPayload = "registration"
        var registrationQuery: NSDictionary?
        let registrationReader = KeychainReader(copyMatching: { query, result in
            registrationQuery = query
            result?.pointee = [[
                kSecAttrAccount as String: registrationWorkspace,
                kSecValueData as String: Data(registrationPayload.utf8),
            ]] as CFArray
            return errSecSuccess
        })
        let registrationItems = try Keychain.synchronizableRecoveryRegistrations(
            maximumItems: 1,
            maximumValueBytes: registrationPayload.utf8.count,
            reader: registrationReader
        )
        require(registrationItems == [registrationWorkspace: registrationPayload], "recovery registration enumeration changed values")
        require(
            registrationQuery?[kSecAttrService] as? String == "LocalSandbox.WorkspaceRecoveryRegistration.v2",
            "recovery registrations did not use their per-workspace Keychain service"
        )
        require((registrationQuery?[kSecAttrSynchronizable] as? Bool) == true, "recovery registration query was not synchronizable")
        require((registrationQuery?[kSecReturnAttributes] as? Bool) == true, "recovery registration query omitted workspace identifiers")
        require((registrationQuery?[kSecReturnData] as? Bool) == true, "recovery registration query omitted values")
        require(
            CFEqual(registrationQuery?[kSecMatchLimit] as CFTypeRef?, kSecMatchLimitAll),
            "recovery registration enumeration was not bounded over all service items"
        )
        var registrationWriteQuery: NSDictionary?
        var registrationWriteAttributes: NSDictionary?
        try Keychain.setSynchronizableRecoveryRegistration(
            registrationPayload,
            workspaceId: registrationWorkspace,
            writer: KeychainWriter(
                update: { query, attributes in
                    registrationWriteQuery = query
                    registrationWriteAttributes = attributes
                    return errSecSuccess
                },
                add: { _ in errSecSuccess }
            )
        )
        require(
            registrationWriteQuery?[kSecAttrService] as? String == "LocalSandbox.WorkspaceRecoveryRegistration.v2"
                && registrationWriteQuery?[kSecAttrAccount] as? String == registrationWorkspace,
            "recovery registration write did not address one workspace-scoped item"
        )
        require((registrationWriteQuery?[kSecAttrSynchronizable] as? Bool) == true, "recovery registration write was not synchronizable")
        require(
            CFEqual(registrationWriteAttributes?[kSecAttrAccessible] as CFTypeRef?, kSecAttrAccessibleWhenUnlocked),
            "recovery registration write used a non-synchronizable accessibility class"
        )
        let tooManyReader = KeychainReader(copyMatching: { _, result in
            result?.pointee = [
                [kSecAttrAccount as String: String(repeating: "A", count: 32), kSecValueData as String: Data()],
                [kSecAttrAccount as String: String(repeating: "B", count: 32), kSecValueData as String: Data()],
            ] as CFArray
            return errSecSuccess
        })
        do {
            _ = try Keychain.synchronizableRecoveryRegistrations(
                maximumItems: 1,
                maximumValueBytes: 512,
                reader: tooManyReader
            )
            fatalError("recovery registration enumeration ignored its item bound")
        } catch let error as SandboxError {
            require(error.localizedDescription == "ICLOUD_RECOVERY_REGISTRY_FULL", "recovery item bound returned the wrong error")
        }
        let oversizedReader = KeychainReader(copyMatching: { _, result in
            result?.pointee = [[
                kSecAttrAccount as String: registrationWorkspace,
                kSecValueData as String: Data(repeating: 65, count: 513),
            ]] as CFArray
            return errSecSuccess
        })
        do {
            _ = try Keychain.synchronizableRecoveryRegistrations(
                maximumItems: 1,
                maximumValueBytes: 512,
                reader: oversizedReader
            )
            fatalError("recovery registration enumeration ignored its value bound")
        } catch let error as SandboxError {
            require(error.localizedDescription == "ICLOUD_RECOVERY_REGISTRY_INVALID", "recovery value bound returned the wrong error")
        }
        do {
            _ = try Keychain.getSynchronizableChecked(
                "registry-read-failure",
                reader: KeychainReader(copyMatching: { _, _ in errSecInteractionNotAllowed })
            )
            fatalError("checked synchronizable Keychain read treated an OS failure as missing")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "checked Keychain read returned the wrong error")
        }
        let missingLocalValue = try Keychain.getChecked(
            "missing-local-value",
            reader: KeychainReader(copyMatching: { _, _ in errSecItemNotFound })
        )
        require(missingLocalValue == nil, "checked local Keychain read did not preserve item-not-found semantics")
        do {
            _ = try Keychain.getChecked(
                "local-read-failure",
                reader: KeychainReader(copyMatching: { _, _ in errSecInteractionNotAllowed })
            )
            fatalError("checked local Keychain read treated an OS failure as missing")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "checked local Keychain read returned the wrong error")
        }
        try Keychain.deleteChecked("delete-test", deleter: KeychainDeleter(delete: { _ in errSecSuccess }))
        try Keychain.deleteChecked("missing-delete-test", deleter: KeychainDeleter(delete: { _ in errSecItemNotFound }))
        do {
            try Keychain.deleteChecked("locked-delete-test", deleter: KeychainDeleter(delete: { _ in errSecInteractionNotAllowed }))
            fatalError("Keychain deletion ignored a failing OSStatus")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_DELETE_FAILED", "Keychain delete failure returned the wrong error")
        }
    }

    static func bearerVaultAtomicityContract() throws {
        let retiringToken = "v1." + String(repeating: "R", count: 43)
        let replacementToken = "v1." + String(repeating: "S", count: 43)
        let retiringSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: retiringToken,
            expiresAt: now + 600,
            accountMode: .linked
        )
        let replacementSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: replacementToken,
            expiresAt: now + 600,
            accountMode: .linked
        )
        let store = AdversarialBearerStore(
            value: String(decoding: try JSONEncoder().encode(retiringSession), as: UTF8.self)
        )
        let retiringVault = NativeBearerVault(
            read: store.read,
            write: store.write,
            delete: store.delete
        )
        let replacementVault = retiringVault
        let operations = DispatchGroup()

        operations.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            defer { operations.leave() }
            try! retiringVault.clearIfMatchingChecked(token: retiringToken)
        }
        require(store.readCaptured.wait(timeout: .now() + 2) == .success, "retiring bearer did not reach its compare read")

        operations.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            defer { operations.leave() }
            try! replacementVault.save(replacementSession, now: now)
        }
        let writeRacedTheSuspendedClear = store.writeEntered.wait(timeout: .now() + 0.5) == .success
        store.resumeRead.signal()
        require(operations.wait(timeout: .now() + 2) == .success, "serialized bearer operations did not finish")
        require(!writeRacedTheSuspendedClear, "a copied vault saved between the retired token comparison and deletion")
        require(
            replacementVault.load(now: now)?.token == replacementToken && store.current()?.contains(replacementToken) == true,
            "retired-token cleanup deleted the newly persisted bearer"
        )

        let replacementEncoding = String(decoding: try JSONEncoder().encode(replacementSession), as: UTF8.self)
        var compareDeleteCount = 0
        let compareReadFailureVault = NativeBearerVault(
            read: { replacementEncoding },
            readChecked: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            write: { _ in },
            delete: { compareDeleteCount += 1 }
        )
        do {
            try compareReadFailureVault.clearIfMatchingChecked(token: replacementToken)
            fatalError("retired-token cleanup treated a Keychain read failure as a missing bearer")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "retired-token compare returned the wrong read failure")
        }
        require(compareDeleteCount == 0, "retired-token cleanup deleted without a successful checked compare")

        var clearDeleteCount = 0
        let clearReadFailureVault = NativeBearerVault(
            read: { replacementEncoding },
            readChecked: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            write: { _ in },
            delete: { clearDeleteCount += 1 }
        )
        do {
            try clearReadFailureVault.clearChecked()
            fatalError("bearer deletion treated a verification read failure as confirmed absence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "bearer deletion verification returned the wrong read failure")
        }
        require(clearDeleteCount == 1, "bearer deletion verification did not follow the delete attempt")

        var savedBeforeReadFailure: String?
        let saveReadFailureVault = NativeBearerVault(
            read: { savedBeforeReadFailure },
            readChecked: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            write: { savedBeforeReadFailure = $0 },
            delete: { savedBeforeReadFailure = nil }
        )
        do {
            try saveReadFailureVault.save(replacementSession, now: now)
            fatalError("bearer persistence treated a verification read failure as success")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "bearer persistence verification returned the wrong read failure")
        }
        let savedBeforeReadFailureSession = savedBeforeReadFailure.flatMap { encoded -> NativeBearerSession? in
            guard let data = encoded.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(NativeBearerSession.self, from: data)
        }
        require(
            savedBeforeReadFailureSession?.token == replacementToken,
            "bearer read-failure fixture did not reach persistence verification"
        )
    }

    static func durableVaultReadFailureContract() async throws {
        let accountBinding = "transaction-read-failure-user"
        let workspaceId = String(repeating: "H", count: 32)
        let retainedSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "R", count: 43),
            expiresAt: now + 600,
            accountMode: .linked
        )
        let issuedSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "I", count: 43),
            expiresAt: now + 900,
            accountMode: .linked
        )
        let retainedEncoding = String(decoding: try JSONEncoder().encode(retainedSession), as: UTF8.self)

        let bearerStore = InjectedCheckedStringStore(value: retainedEncoding, failingReadCalls: [1])
        let bearerVault = NativeBearerVault(
            read: { bearerStore.value },
            readChecked: bearerStore.read,
            write: bearerStore.write,
            delete: bearerStore.delete
        )
        let bearerTransport = RecordingNativeTransport([
            .init(status: 200, data: try JSONEncoder().encode(issuedSession), headers: ["Cache-Control": "no-store"]),
            .init(status: 200, data: try json(["revoked": true]), headers: ["Cache-Control": "no-store"]),
        ])
        let bearerController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://transaction-read.example.test")!),
                transport: bearerTransport
            ),
            vault: bearerVault
        )
        do {
            _ = try await bearerController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "transaction-read-authorization-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "transaction-read-user",
                now: now
            )
            fatalError("bearer transaction read failure accepted a replacement grant")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "bearer transaction returned the wrong read failure")
        }
        require(bearerStore.value == retainedEncoding, "bearer transaction read failure replaced the retained grant")
        require(bearerStore.writeCount == 0 && bearerStore.deleteCount == 0, "bearer transaction mutated retained Keychain state after a read failure")
        require(
            bearerTransport.requests.isEmpty,
            "bearer transaction read failure consumed an Apple authorization code"
        )
        let retainedPendingActivation = try bearerController.pendingActivationVault.load()
        require(
            retainedPendingActivation == nil,
            "bearer transaction read failure wrote a pending token without an exchange"
        )

        let expiredRetainedSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "E", count: 43),
            expiresAt: now - 1,
            accountMode: .linked
        )
        let expiredRetainedEncoding = String(
            decoding: try JSONEncoder().encode(expiredRetainedSession),
            as: UTF8.self
        )
        let expiredBearerStore = InjectedCheckedStringStore(value: expiredRetainedEncoding)
        let expiredBearerVault = NativeBearerVault(
            read: { expiredBearerStore.value },
            readChecked: expiredBearerStore.read,
            write: expiredBearerStore.write,
            delete: expiredBearerStore.delete
        )
        require(
            expiredBearerVault.load(now: now) == nil,
            "expired prior bearer remained available before replacement"
        )
        require(
            expiredBearerStore.value == expiredRetainedEncoding,
            "ordinary availability refresh destroyed the expired prior bearer before replacement"
        )
        let expiredBearerTransport = RecordingNativeTransport([
            .init(status: 200, data: try JSONEncoder().encode(issuedSession), headers: ["Cache-Control": "no-store"]),
            .init(status: 200, data: try json(["revoked": true]), headers: ["Cache-Control": "no-store"]),
        ])
        let expiredBearerController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://expired-transaction.example.test")!),
                transport: expiredBearerTransport
            ),
            vault: expiredBearerVault
        )
        _ = try await expiredBearerController.connect(
            identityToken: "header.payload.signature",
            authorizationCode: "expired-transaction-authorization-code",
            rawNonce: String(repeating: "n", count: 43),
            targetAccountBinding: "expired-transaction-user",
            now: now
        )
        let persistedReplacement = expiredBearerStore.value.flatMap { encoded -> NativeBearerSession? in
            guard let data = encoded.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(NativeBearerSession.self, from: data)
        }
        require(persistedReplacement?.token == issuedSession.token, "expired prior bearer prevented replacement persistence")
        require(
            expiredBearerTransport.requests.compactMap { $0.0.url?.path } == [
                "/api/auth/apple/native/exchange",
                "/api/auth/apple/native/activate",
                "/api/auth/apple/native/revoke",
            ],
            "expired structurally valid prior bearer was not retired after replacement"
        )
        require(
            expiredBearerTransport.requests.last?.0.value(forHTTPHeaderField: "Authorization")
                == "Bearer \(expiredRetainedSession.token)",
            "expired prior Apple grant retirement used the replacement bearer"
        )

        let stageFailureBearerStore = InjectedCheckedStringStore(value: retainedEncoding)
        var stageFailureQueueWrites = 0
        let stageFailureQueue = NativePendingRevocationVault(
            read: { nil },
            write: { _ in
                stageFailureQueueWrites += 1
                throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED")
            },
            delete: {}
        )
        let stageFailureTransport = RecordingNativeTransport([
            .init(status: 200, data: try JSONEncoder().encode(issuedSession), headers: ["Cache-Control": "no-store"]),
            .init(status: 200, data: try json(["revoked": true]), headers: ["Cache-Control": "no-store"]),
        ])
        let stageFailureController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://stage-failure.example.test")!),
                transport: stageFailureTransport
            ),
            vault: NativeBearerVault(
                read: { stageFailureBearerStore.value },
                readChecked: stageFailureBearerStore.read,
                write: stageFailureBearerStore.write,
                delete: stageFailureBearerStore.delete
            ),
            pendingRevocationVault: stageFailureQueue
        )
        do {
            _ = try await stageFailureController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "stage-failure-authorization-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "stage-failure-user",
                now: now
            )
            fatalError("replacement overwrote a still-revocable bearer without durable staging")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_WRITE_FAILED", "prior-bearer staging failure returned the wrong error")
        }
        require(stageFailureBearerStore.value == retainedEncoding, "prior-bearer staging failure overwrote retained auth evidence")
        require(stageFailureBearerStore.writeCount == 0, "replacement reached bearer persistence before prior staging")
        require(stageFailureQueueWrites == 1, "stage-failure fixture did not stop at prior-token staging")
        require(
            stageFailureTransport.requests.compactMap { $0.0.url?.path } == [
                "/api/auth/apple/native/exchange",
                "/api/auth/apple/native/activate",
            ],
            "prior-stage failure did not retain the active response in its checked activation journal"
        )
        require(
            stageFailureTransport.requests.last?.0.value(forHTTPHeaderField: "Authorization")
                == "Bearer \(issuedSession.token)",
            "prior-stage failure activated an unexpected bearer"
        )
        let stageFailurePending = try stageFailureController.pendingActivationVault.load()
        require(
            stageFailurePending?.pendingSession.token == issuedSession.token,
            "prior-stage failure lost the newly active exact token"
        )

        var deferredReplacementQueueStorage: String?
        let deferredReplacementQueue = NativePendingRevocationVault(
            read: { deferredReplacementQueueStorage },
            write: { deferredReplacementQueueStorage = $0 },
            delete: { deferredReplacementQueueStorage = nil }
        )
        var deferredReplacementBearerStorage: String? = retainedEncoding
        var replacementObservedDurablePrior = false
        let deferredReplacementVault = NativeBearerVault(
            read: { deferredReplacementBearerStorage },
            readChecked: { deferredReplacementBearerStorage },
            write: { replacement in
                guard deferredReplacementQueueStorage?.contains(retainedSession.token) == true else {
                    throw SandboxError.blocked("PRIOR_BEARER_NOT_STAGED_BEFORE_REPLACEMENT")
                }
                replacementObservedDurablePrior = true
                deferredReplacementBearerStorage = replacement
            },
            delete: { deferredReplacementBearerStorage = nil },
            retirementBlocked: { token, instant in
                deferredReplacementQueue.blocksAdmission(bearerToken: token, now: instant)
            }
        )
        let deferredReplacementTransport = RecordingNativeTransport([
            .init(status: 200, data: try JSONEncoder().encode(issuedSession), headers: ["Cache-Control": "no-store"]),
            .init(
                status: 503,
                data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]),
                headers: ["Cache-Control": "no-store"]
            ),
        ])
        let deferredReplacementController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://deferred-replacement.example.test")!),
                transport: deferredReplacementTransport
            ),
            vault: deferredReplacementVault,
            pendingRevocationVault: deferredReplacementQueue
        )
        let deferredReplacement = try await deferredReplacementController.connect(
            identityToken: "header.payload.signature",
            authorizationCode: "deferred-replacement-authorization-code",
            rawNonce: String(repeating: "n", count: 43),
            targetAccountBinding: "deferred-replacement-user",
            now: now
        )
        require(replacementObservedDurablePrior, "replacement did not observe durable prior-token staging")
        require(deferredReplacement.token == issuedSession.token, "deferred prior revocation returned the wrong replacement")
        require(
            deferredReplacementVault.load(now: now)?.token == issuedSession.token,
            "an old queued token blocked admission of a distinct replacement bearer"
        )
        let deferredReplacementEntries = try deferredReplacementQueue.snapshot(now: now)
        require(
            deferredReplacementEntries.map(\.bearerToken) == [retainedSession.token],
            "failed prior revocation did not retain the exact old bearer in the durable queue"
        )
        require(
            deferredReplacementTransport.requests.last?.0.value(forHTTPHeaderField: "Authorization")
                == "Bearer \(retainedSession.token)",
            "deferred prior revocation used the replacement bearer"
        )

        let grantTail = NativeServiceLimits.nativeGrantLifetimeSeconds
            - NativeServiceLimits.bearerLifetimeSeconds
        let ancientSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "G", count: 43),
            expiresAt: now - grantTail,
            accountMode: .linked
        )
        var ancientStorage: String? = String(
            decoding: try JSONEncoder().encode(ancientSession),
            as: UTF8.self
        )
        var ancientStageCalls = 0
        let ancientVault = NativeBearerVault(
            read: { ancientStorage },
            readChecked: { ancientStorage },
            write: { ancientStorage = $0 },
            delete: { ancientStorage = nil }
        )
        let ancientGate = NativeAppleAuthPersistenceGate()
        ancientGate.register(1)
        _ = try ancientGate.persistIfCurrent(
            1,
            issued: issuedSession,
            vault: ancientVault,
            stagePrevious: { _ in ancientStageCalls += 1 },
            now: now
        )
        require(
            ancientStageCalls == 1,
            "local wall-clock expiry skipped authoritative retirement of prior Apple grant evidence"
        )
        require(
            ancientVault.load(now: now)?.token == issuedSession.token,
            "replacement was not admitted after the prior grant follow-up window ended"
        )

        let transferReadStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let transferReadVault = NativeAppleTransferBlockVault(
            read: transferReadStore.read,
            write: transferReadStore.write,
            delete: transferReadStore.delete
        )
        requireKeychainReadFailure("transfer-block load") { _ = try transferReadVault.load() }
        require(transferReadStore.writeCount == 0 && transferReadStore.deleteCount == 0, "transfer-block read failure mutated Keychain")

        let transferPersistenceStore = InjectedCheckedStringStore(failingReadCalls: [2])
        let transferPersistenceVault = NativeAppleTransferBlockVault(
            read: transferPersistenceStore.read,
            write: transferPersistenceStore.write,
            delete: transferPersistenceStore.delete
        )
        requireKeychainReadFailure("transfer-block persistence") {
            try transferPersistenceVault.block(oldUser: accountBinding)
        }
        require(transferPersistenceStore.writeCount == 1 && transferPersistenceStore.value != nil, "transfer-block persistence fixture did not reach checked readback")

        let transferDeleteStore = InjectedCheckedStringStore(
            value: transferPersistenceStore.value,
            failingReadCalls: [2]
        )
        let transferDeleteVault = NativeAppleTransferBlockVault(
            read: transferDeleteStore.read,
            write: transferDeleteStore.write,
            delete: transferDeleteStore.delete
        )
        requireKeychainReadFailure("transfer-block deletion verification") {
            try transferDeleteVault.clearChecked(oldUser: accountBinding)
        }
        require(transferDeleteStore.deleteCount == 1, "transfer-block read failure happened before its deletion verification")

        let pendingReadStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let pendingReadVault = NativePendingRevocationVault(
            read: pendingReadStore.read,
            write: pendingReadStore.write,
            delete: pendingReadStore.delete
        )
        requireKeychainReadFailure("pending-revocation load") {
            _ = try pendingReadVault.snapshot(now: now)
        }
        require(pendingReadStore.writeCount == 0 && pendingReadStore.deleteCount == 0, "pending-revocation read failure mutated the queue")

        let pendingPersistenceStore = InjectedCheckedStringStore(failingReadCalls: [2])
        let pendingPersistenceVault = NativePendingRevocationVault(
            read: pendingPersistenceStore.read,
            write: pendingPersistenceStore.write,
            delete: pendingPersistenceStore.delete
        )
        requireKeychainReadFailure("pending-revocation persistence") {
            try pendingPersistenceVault.stage(retainedSession, now: now)
        }
        require(pendingPersistenceStore.writeCount == 1 && pendingPersistenceStore.value != nil, "pending-revocation fixture did not reach persistence readback")

        let pendingDeleteStore = InjectedCheckedStringStore(
            value: pendingPersistenceStore.value,
            failingReadCalls: [1]
        )
        let pendingDeleteVault = NativePendingRevocationVault(
            read: pendingDeleteStore.read,
            write: pendingDeleteStore.write,
            delete: pendingDeleteStore.delete
        )
        requireKeychainReadFailure("pending-revocation deletion verification") {
            try pendingDeleteVault.clearChecked()
        }
        require(pendingDeleteStore.deleteCount == 1, "pending-revocation deletion verification did not follow the delete")

        let bindingReadStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let bindingReadVault = NativeLocalWorkspaceBindingVault(
            read: bindingReadStore.read,
            write: bindingReadStore.write,
            delete: bindingReadStore.delete
        )
        requireKeychainReadFailure("workspace-binding load") {
            _ = try bindingReadVault.directoryName(accountBinding: accountBinding)
        }
        require(bindingReadStore.writeCount == 0, "workspace-binding read failure created a new binding")

        let bindingPersistenceStore = InjectedCheckedStringStore(failingReadCalls: [2])
        let bindingPersistenceVault = NativeLocalWorkspaceBindingVault(
            read: bindingPersistenceStore.read,
            write: bindingPersistenceStore.write,
            delete: bindingPersistenceStore.delete
        )
        requireKeychainReadFailure("workspace-binding persistence") {
            _ = try bindingPersistenceVault.directoryName(accountBinding: accountBinding)
        }
        require(bindingPersistenceStore.writeCount == 1 && bindingPersistenceStore.value != nil, "workspace-binding fixture did not reach persistence readback")

        let bindingDeleteStore = InjectedCheckedStringStore(
            value: bindingPersistenceStore.value,
            failingReadCalls: [1]
        )
        let bindingDeleteVault = NativeLocalWorkspaceBindingVault(
            read: bindingDeleteStore.read,
            write: bindingDeleteStore.write,
            delete: bindingDeleteStore.delete
        )
        requireKeychainReadFailure("workspace-binding deletion verification") {
            try bindingDeleteVault.clearChecked()
        }
        require(bindingDeleteStore.deleteCount == 1, "workspace-binding deletion verification did not follow the delete")

        let modeReadStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let modeReadVault = NativeAppleAccountModeVault(
            read: modeReadStore.read,
            write: modeReadStore.write,
            delete: modeReadStore.delete
        )
        requireKeychainReadFailure("account-mode load") {
            _ = try modeReadVault.load(accountBinding: accountBinding)
        }
        require(modeReadStore.writeCount == 0, "account-mode read failure created a record")

        let modePersistenceStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let modePersistenceVault = NativeAppleAccountModeVault(
            read: modePersistenceStore.read,
            write: modePersistenceStore.write,
            delete: modePersistenceStore.delete
        )
        requireKeychainReadFailure("account-mode persistence") {
            try modePersistenceVault.save(.linked, accountBinding: accountBinding)
        }
        require(modePersistenceStore.writeCount == 1 && modePersistenceStore.value != nil, "account-mode fixture did not reach persistence readback")

        let modeDeleteStore = InjectedCheckedStringStore(
            value: modePersistenceStore.value,
            failingReadCalls: [1]
        )
        let modeDeleteVault = NativeAppleAccountModeVault(
            read: modeDeleteStore.read,
            write: modeDeleteStore.write,
            delete: modeDeleteStore.delete
        )
        requireKeychainReadFailure("account-mode deletion verification") {
            try modeDeleteVault.clearChecked()
        }
        require(modeDeleteStore.deleteCount == 1, "account-mode deletion verification did not follow the delete")

        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        let outcome = NativeAccountDeletionOutcome(
            accountBindingHash: accountBindingHash,
            accountMode: .linked,
            manualRevocationRequired: true,
            manualOriginRevocationRequired: true
        )
        let outcomeReadStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let outcomeReadVault = NativeAccountDeletionOutcomeVault(
            read: outcomeReadStore.read,
            write: outcomeReadStore.write,
            delete: outcomeReadStore.delete
        )
        requireKeychainReadFailure("deletion-outcome load") { _ = try outcomeReadVault.load() }
        require(outcomeReadStore.writeCount == 0, "deletion-outcome read failure created a record")

        let outcomePersistenceStore = InjectedCheckedStringStore(failingReadCalls: [1])
        let outcomePersistenceVault = NativeAccountDeletionOutcomeVault(
            read: outcomePersistenceStore.read,
            write: outcomePersistenceStore.write,
            delete: outcomePersistenceStore.delete
        )
        requireKeychainReadFailure("deletion-outcome persistence") {
            try outcomePersistenceVault.save(outcome)
        }
        require(outcomePersistenceStore.writeCount == 1 && outcomePersistenceStore.value != nil, "deletion-outcome fixture did not reach persistence readback")

        let outcomeDeleteStore = InjectedCheckedStringStore(
            value: outcomePersistenceStore.value,
            failingReadCalls: [1]
        )
        let outcomeDeleteVault = NativeAccountDeletionOutcomeVault(
            read: outcomeDeleteStore.read,
            write: outcomeDeleteStore.write,
            delete: outcomeDeleteStore.delete
        )
        requireKeychainReadFailure("deletion-outcome deletion verification") {
            try outcomeDeleteVault.clearChecked()
        }
        require(outcomeDeleteStore.deleteCount == 1, "deletion-outcome deletion verification did not follow the delete")

        let deterministicDeletionKey = Data(repeating: 23, count: 32)
        let attemptReadStore = InjectedCheckedKeyedStore(failingReadCalls: [1])
        var attemptReadRandomCalls = 0
        let attemptReadVault = NativeAccountDeletionAttemptVault(
            read: attemptReadStore.read,
            write: attemptReadStore.write,
            delete: attemptReadStore.delete,
            random: { _ in attemptReadRandomCalls += 1; return deterministicDeletionKey }
        )
        requireKeychainReadFailure("deletion-attempt initial load") {
            _ = try attemptReadVault.attempt(accountBinding: accountBinding, bearer: retainedSession, now: now)
        }
        require(
            attemptReadRandomCalls == 0 && attemptReadStore.writeCount == 0,
            "deletion-attempt read failure generated or wrote a new idempotency key"
        )

        let attemptPersistenceStore = InjectedCheckedKeyedStore(failingReadCalls: [2])
        var attemptPersistenceRandomCalls = 0
        let attemptPersistenceVault = NativeAccountDeletionAttemptVault(
            read: attemptPersistenceStore.read,
            write: attemptPersistenceStore.write,
            delete: attemptPersistenceStore.delete,
            random: { _ in attemptPersistenceRandomCalls += 1; return deterministicDeletionKey }
        )
        requireKeychainReadFailure("deletion-attempt persistence") {
            _ = try attemptPersistenceVault.attempt(accountBinding: accountBinding, bearer: retainedSession, now: now)
        }
        require(
            attemptPersistenceRandomCalls == 1 && attemptPersistenceStore.writeCount == 1 && !attemptPersistenceStore.values.isEmpty,
            "deletion-attempt fixture did not reach persistence readback"
        )

        let attemptOverwriteStore = InjectedCheckedKeyedStore(
            values: attemptPersistenceStore.values,
            failingReadCalls: [1]
        )
        var attemptOverwriteRandomCalls = 0
        let attemptOverwriteVault = NativeAccountDeletionAttemptVault(
            read: attemptOverwriteStore.read,
            write: attemptOverwriteStore.write,
            delete: attemptOverwriteStore.delete,
            random: { _ in attemptOverwriteRandomCalls += 1; return Data(repeating: 24, count: 32) }
        )
        requireKeychainReadFailure("deletion-attempt retained-record load") {
            _ = try attemptOverwriteVault.attempt(accountBinding: accountBinding, bearer: retainedSession, now: now)
        }
        require(
            attemptOverwriteRandomCalls == 0 && attemptOverwriteStore.writeCount == 0,
            "deletion-attempt read failure replaced a retained idempotency key"
        )

        let attemptDeleteStore = InjectedCheckedKeyedStore(
            values: attemptPersistenceStore.values,
            failingReadCalls: [1]
        )
        let attemptDeleteVault = NativeAccountDeletionAttemptVault(
            read: attemptDeleteStore.read,
            write: attemptDeleteStore.write,
            delete: attemptDeleteStore.delete
        )
        requireKeychainReadFailure("deletion-attempt deletion verification") {
            try attemptDeleteVault.clearChecked()
        }
        require(attemptDeleteStore.deleteCount == 1, "deletion-attempt deletion verification did not follow the delete")
        let attemptAvailabilityStore = InjectedCheckedKeyedStore(failingReadCalls: [1])
        let attemptAvailabilityVault = NativeAccountDeletionAttemptVault(
            read: attemptAvailabilityStore.read,
            write: attemptAvailabilityStore.write,
            delete: attemptAvailabilityStore.delete
        )
        require(attemptAvailabilityVault.hasPending(), "deletion-attempt availability read failed open")
        let boundAttemptAvailabilityStore = InjectedCheckedKeyedStore(failingReadCalls: [1])
        let boundAttemptAvailabilityVault = NativeAccountDeletionAttemptVault(
            read: boundAttemptAvailabilityStore.read,
            write: boundAttemptAvailabilityStore.write,
            delete: boundAttemptAvailabilityStore.delete
        )
        require(
            boundAttemptAvailabilityVault.hasPending(accountBinding: accountBinding, now: now),
            "bound deletion-attempt availability read failed open"
        )
        require(
            boundAttemptAvailabilityStore.readCount == 1,
            "bound deletion-attempt availability retried an ambiguous Keychain read"
        )

        var recoveryWriteCount = 0
        var recoveryRegistrationWriteCount = 0
        let recoveryBindingReadVault = NativeRecoverySecretVault(
            read: { _ in nil },
            write: { _, _ in recoveryWriteCount += 1 },
            delete: { _ in },
            readLegacyRegistry: { nil },
            readRegistration: { _ in nil },
            writeRegistration: { _, _ in recoveryRegistrationWriteCount += 1 },
            deleteRegistration: { _ in },
            listRegistrations: { [:] },
            accountBinding: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") }
        )
        requireKeychainReadFailure("recovery account-binding load") {
            try recoveryBindingReadVault.save(String(repeating: "A", count: 43), workspaceId: workspaceId)
        }
        require(
            recoveryWriteCount == 0 && recoveryRegistrationWriteCount == 0,
            "recovery account-binding read failure wrote secret or registration state"
        )

        let scrubModeStore = InjectedCheckedStringStore()
        let scrubModeVault = NativeAppleAccountModeVault(
            read: scrubModeStore.read,
            write: scrubModeStore.write,
            delete: scrubModeStore.delete
        )
        try scrubModeVault.save(.linked, accountBinding: accountBinding)
        let scrubCredentials = InjectedCheckedKeyedStore(
            values: ["appleUser": accountBinding, "githubToken": "retained-token"],
            failReadsAfterDelete: true
        )
        let unusedRecoveryVault = NativeRecoverySecretVault(
            read: { _ in nil },
            write: { _, _ in },
            delete: { _ in },
            readLegacyRegistry: { nil },
            readRegistration: { _ in nil },
            writeRegistration: { _, _ in },
            deleteRegistration: { _ in },
            listRegistrations: { [:] },
            accountBinding: { accountBinding }
        )
        let scrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}),
            accountModeVault: scrubModeVault,
            workspaceBindingVault: NativeLocalWorkspaceBindingVault(
                read: { nil },
                write: { _ in },
                delete: {}
            ),
            recoveryVault: unusedRecoveryVault,
            read: scrubCredentials.read,
            write: scrubCredentials.write,
            delete: scrubCredentials.delete
        )
        requireKeychainReadFailure("profile scrub verification") { try scrubber.scrub() }
        require(scrubCredentials.values["githubToken"] == "retained-token", "profile scrub continued after a verification read failure")
        require(scrubModeStore.deleteCount == 0 && scrubModeStore.value != nil, "profile scrub cleared later auth state after a verification read failure")

        let oldUser = "old-transaction-read-user"
        let newUser = "new-transaction-read-user"

        let migrationInitialStore = TransferMigrationStore(user: oldUser)
        let migrationInitial = transferFixtures(migrationInitialStore)
        try seedTransfer(fixtures: migrationInitial, oldUser: oldUser, workspaceId: workspaceId)
        migrationInitialStore.failReadAt["migration"] = 1
        requireKeychainReadFailure("transfer-migration initial journal load") {
            try migrationInitial.coordinator.migrateVerifiedTransfer(from: oldUser, to: newUser, verifiedAccountMode: .linked)
        }
        require(
            migrationInitialStore.migration == nil && migrationInitialStore.user == oldUser,
            "transfer migration started after its journal read failed"
        )

        let migrationPersistenceStore = TransferMigrationStore(user: oldUser)
        let migrationPersistence = transferFixtures(migrationPersistenceStore)
        try seedTransfer(fixtures: migrationPersistence, oldUser: oldUser, workspaceId: workspaceId)
        migrationPersistenceStore.failReadAt["migration"] = 2
        requireKeychainReadFailure("transfer-migration journal persistence") {
            try migrationPersistence.coordinator.migrateVerifiedTransfer(from: oldUser, to: newUser, verifiedAccountMode: .linked)
        }
        require(
            migrationPersistenceStore.migration != nil && migrationPersistenceStore.user == oldUser,
            "transfer migration did not retain an unverified journal write for recovery"
        )

        let migrationDeleteStore = TransferMigrationStore(user: oldUser)
        let migrationDelete = transferFixtures(migrationDeleteStore)
        try seedTransfer(fixtures: migrationDelete, oldUser: oldUser, workspaceId: workspaceId)
        migrationDeleteStore.failReadAt["migration"] = 3
        requireKeychainReadFailure("transfer-migration journal deletion verification") {
            try migrationDelete.coordinator.migrateVerifiedTransfer(from: oldUser, to: newUser, verifiedAccountMode: .linked)
        }
        require(
            migrationDeleteStore.user == oldUser && migrationDeleteStore.transferBlock != nil,
            "transfer migration reported success or lost its hosted block after delete verification failed"
        )

        let userInitialStore = TransferMigrationStore(user: oldUser)
        let userInitial = transferFixtures(userInitialStore)
        try seedTransfer(fixtures: userInitial, oldUser: oldUser, workspaceId: workspaceId)
        userInitialStore.failReadAt["user"] = 1
        requireKeychainReadFailure("transfer user initial comparison") {
            try userInitial.coordinator.migrateVerifiedTransfer(from: oldUser, to: newUser, verifiedAccountMode: .linked)
        }
        require(userInitialStore.migration == nil && userInitialStore.user == oldUser, "transfer user read failure started a migration")

        let userPersistenceStore = TransferMigrationStore(user: oldUser)
        let userPersistence = transferFixtures(userPersistenceStore)
        try seedTransfer(fixtures: userPersistence, oldUser: oldUser, workspaceId: workspaceId)
        userPersistenceStore.failReadAt["user"] = 2
        requireKeychainReadFailure("transfer user persistence verification") {
            try userPersistence.coordinator.migrateVerifiedTransfer(from: oldUser, to: newUser, verifiedAccountMode: .linked)
        }
        require(
            userPersistenceStore.user == oldUser && userPersistenceStore.transferBlock != nil,
            "transfer user readback failure left a mixed identity or removed hosted blocking"
        )
    }

    static func hostedAdmissionContract() throws {
        let session = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "T", count: 43),
            expiresAt: now + 600,
            accountMode: .linked
        )
        var stored: String? = String(decoding: try JSONEncoder().encode(session), as: UTF8.self)
        var blocked = true
        let vault = NativeBearerVault(
            read: { stored },
            write: { stored = $0 },
            delete: { stored = nil },
            admissionBlocked: { blocked }
        )
        require(vault.load(now: now) == nil, "transfer gate admitted a valid hosted bearer")
        let retirementSession = try vault.loadForRetirement()
        require(
            retirementSession?.token == session.token,
            "transfer gate prevented bounded revocation of the blocked bearer"
        )
        blocked = false
        require(vault.load(now: now)?.token == session.token, "verified admission did not restore the bearer")

        var transferBlock: String?
        let blockVault = NativeAppleTransferBlockVault(
            read: { transferBlock },
            write: { transferBlock = $0 },
            delete: { transferBlock = nil }
        )
        try blockVault.block(oldUser: "old-transfer-user")
        let blockedUser = try blockVault.load()
        require(blockedUser == "old-transfer-user", "transfer block did not retain the old user")
        do {
            try blockVault.block(oldUser: "different-user")
            fatalError("transfer block switched old users")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_TRANSFER_BLOCK_CONFLICT", "transfer block conflict was ambiguous")
        }
        try blockVault.clearChecked(oldUser: "old-transfer-user")
        let clearedBlock = try blockVault.load()
        require(clearedBlock == nil, "verified transfer block was not cleared")
    }

    static func urlSessionConcurrentFirstUseContract() async throws {
        let transport = NativeURLSessionTransport(protocolClasses: [ConcurrentFirstUseURLProtocol.self])
        let request = URLRequest(url: URL(string: "https://native-transport.test/first-use")!)
        let completed = try await withThrowingTaskGroup(of: Int.self, returning: Int.self) { group in
            for _ in 0..<24 {
                group.addTask {
                    let result = try await transport.perform(request, maximumResponseBytes: 64)
                    guard result.response.statusCode == 200, result.data == ConcurrentFirstUseURLProtocol.body else {
                        throw SandboxError.blocked("CONCURRENT_FIRST_USE_RESPONSE_INVALID")
                    }
                    return 1
                }
            }
            var count = 0
            for try await value in group { count += value }
            return count
        }
        require(completed == 24, "concurrent first use lost native transport requests")
    }

    static func authLifecycleContract() async throws {
        let persistenceGate = NativeAppleAuthPersistenceGate()
        persistenceGate.register(1)
        persistenceGate.register(2)
        let exchangeBody = try json([
            "schemaVersion": 1,
            "tokenType": "Bearer",
            "token": bearer,
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        let revokeBody = try json(["revoked": true])
        let transport = RecordingNativeTransport([
            .init(status: 200, data: exchangeBody, headers: ["Cache-Control": "no-store"]),
            .init(status: 200, data: revokeBody, headers: ["Cache-Control": "no-store"]),
        ])
        var stored: String?
        let vault = NativeBearerVault(read: { stored }, write: { stored = $0 }, delete: { stored = nil })
        let endpoints = try NativeServiceEndpoints(origin: URL(string: "https://sandbox.example.test")!)
        let controller = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport), vault: vault)
        let identityToken = "header.payload.signature"
        let rawNonce = String(repeating: "n", count: 43)

        let olderBearer = "v1." + String(repeating: "O", count: 43)
        let newerBearer = "v1." + String(repeating: "N", count: 43)
        let olderBody = try json([
            "schemaVersion": 1,
            "tokenType": "Bearer",
            "token": olderBearer,
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        let newerBody = try json([
            "schemaVersion": 1,
            "tokenType": "Bearer",
            "token": newerBearer,
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        let outOfOrderTransport = OutOfOrderNativeTransport(
            olderExchangeBody: olderBody,
            newerExchangeBody: newerBody,
            revokeBody: revokeBody
        )
        var outOfOrderStored: String?
        let outOfOrderVault = NativeBearerVault(
            read: { outOfOrderStored },
            write: { outOfOrderStored = $0 },
            delete: { outOfOrderStored = nil }
        )
        let outOfOrderController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: outOfOrderTransport),
            vault: outOfOrderVault
        )
        let olderConnect = Task {
            try await outOfOrderController.connect(
                identityToken: identityToken,
                authorizationCode: "older-authorization-code",
                rawNonce: rawNonce,
                targetAccountBinding: "concurrent-user",
                persistenceGeneration: 1,
                now: now
            )
        }
        await outOfOrderTransport.waitForFirstExchange()
        let newerConnect = Task {
            try await outOfOrderController.connect(
                identityToken: identityToken,
                authorizationCode: "newer-authorization-code",
                rawNonce: rawNonce,
                targetAccountBinding: "concurrent-user",
                persistenceGeneration: 2,
                now: now
            )
        }
        for _ in 0..<8 { await Task.yield() }
        await outOfOrderTransport.completeFirstExchange()
        let newerIssued = try await newerConnect.value
        do {
            _ = try await olderConnect.value
            fatalError("an older coalesced caller received the newer generation's bearer")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED", "older coalesced caller returned an unexpected failure")
        }
        require(newerIssued.token == olderBearer, "same-account coalescing did not return the one exchanged bearer")
        require(outOfOrderVault.load(now: now)?.token == olderBearer, "same-account coalescing persisted the wrong bearer")
        let outOfOrderPaths = await outOfOrderTransport.paths()
        require(outOfOrderPaths.filter { $0 == "/api/auth/apple/native/exchange" }.count == 1, "same-account single-flight minted more than one pending token")
        require(outOfOrderPaths.filter { $0 == "/api/auth/apple/native/activate" }.count == 1, "same-account single-flight did not activate exactly once")
        require(!outOfOrderPaths.contains("/api/auth/apple/native/revoke"), "stale caller revoked a coalesced current bearer")

        let backgroundTransport = OutOfOrderNativeTransport(
            olderExchangeBody: olderBody,
            newerExchangeBody: newerBody,
            revokeBody: revokeBody
        )
        var backgroundStored: String?
        let backgroundVault = NativeBearerVault(
            read: { backgroundStored },
            write: { backgroundStored = $0 },
            delete: { backgroundStored = nil }
        )
        let backgroundController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: backgroundTransport),
            vault: backgroundVault
        )
        let preBackgroundConnect = Task {
            try await backgroundController.connect(
                identityToken: identityToken,
                authorizationCode: "background-authorization-code",
                rawNonce: rawNonce,
                targetAccountBinding: "background-user",
                persistenceGeneration: 10,
                now: now
            )
        }
        await backgroundTransport.waitForFirstExchange()
        backgroundController.invalidatePersistence(generation: 11)
        await backgroundTransport.completeFirstExchange()
        do {
            _ = try await preBackgroundConnect.value
            fatalError("background invalidation allowed an in-flight exchange to persist")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED", "background invalidation returned an unexpected failure")
        }
        require(backgroundStored == nil, "in-flight exchange wrote a bearer after background invalidation")
        let backgroundPaths = await backgroundTransport.paths()
        require(backgroundPaths.filter { $0 == "/api/auth/apple/native/revoke" }.count == 1, "background-invalidated bearer was not compensatingly revoked")

        let authorizationCode = "native-one-use-authorization-code"
        let issued = try await controller.connect(identityToken: identityToken, authorizationCode: authorizationCode, rawNonce: rawNonce, targetAccountBinding: "native-contract-user", now: now)
        require(issued.expiresAt == now + 900, "client did not honor the 900-second session")
        require(stored?.contains(bearer) == true, "opaque bearer was not saved")
        require(stored?.contains(identityToken) == false && stored?.contains(rawNonce) == false, "Apple credential material leaked into the bearer vault")
        require(transport.requests.count == 2, "exchange and activation made an unexpected request")
        let exchange = transport.requests[0].0
        require(exchange.url?.path == "/api/auth/apple/native/exchange", "wrong exchange path")
        require(exchange.value(forHTTPHeaderField: "Authorization") == nil && exchange.value(forHTTPHeaderField: "Cookie") == nil, "exchange used ambient authentication")
        require(exchange.value(forHTTPHeaderField: "Content-Type") == "application/json", "exchange omitted JSON content type")
        require((exchange.httpBody?.count ?? 0) <= NativeServiceLimits.exchangeRequestBytes, "exchange body exceeded 20KB")
        let decodedBody = try JSONSerialization.jsonObject(with: exchange.httpBody!) as! [String: String]
        require(decodedBody == ["identityToken": identityToken, "authorizationCode": authorizationCode, "rawNonce": rawNonce], "exchange body contract drifted")
        let activation = transport.requests[1].0
        require(activation.url?.path == "/api/auth/apple/native/activate", "wrong activation path")
        require(activation.httpMethod == "POST", "activation did not use POST")
        require(activation.value(forHTTPHeaderField: "Authorization") == "Bearer \(bearer)", "activation omitted its exact pending bearer")
        require(activation.httpBody == nil, "activation request was not empty")
        require(activation.value(forHTTPHeaderField: "Content-Type") == nil, "activation sent a content type for an empty body")
        require(activation.value(forHTTPHeaderField: "Cookie") == nil, "activation leaked ambient cookie state")

        try await controller.disconnect(now: now + 1)
        require(stored == nil, "disconnect retained the bearer")
        require(transport.requests.count == 3, "disconnect made an unexpected request")
        let revoke = transport.requests[2].0
        require(revoke.url?.path == "/api/auth/apple/native/revoke", "wrong revoke path")
        require(revoke.value(forHTTPHeaderField: "Authorization") == "Bearer \(bearer)", "revoke omitted bearer")
        require(revoke.httpBody == nil && revoke.value(forHTTPHeaderField: "Content-Type") == nil, "revoke was not an empty request")

        let expiredSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: bearer,
            expiresAt: now,
            accountMode: .linked
        )
        let expiredEncoding = String(decoding: try JSONEncoder().encode(expiredSession), as: UTF8.self)
        stored = expiredEncoding
        require(vault.load(now: now) == nil, "expired bearer remained available for hosted admission")
        require(stored == expiredEncoding, "availability read destroyed an expired bearer needed for grant retirement")
        let retainedExpiredSession = try vault.loadForRetirement()
        require(
            retainedExpiredSession?.token == bearer,
            "retirement read could not recover the preserved expired bearer"
        )

        let malformedEncoding = "{future-or-damaged-bearer-wrapper"
        stored = malformedEncoding
        require(vault.load(now: now) == nil, "malformed bearer became available for hosted admission")
        require(stored == malformedEncoding, "availability read mutated unrecognized bearer evidence")
        do {
            _ = try vault.loadChecked(now: now)
            fatalError("checked bearer read treated malformed retained evidence as missing")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_SESSION_INVALID", "checked malformed bearer returned the wrong error")
        }
        require(stored == malformedEncoding, "checked bearer read destroyed malformed retained evidence")

        let oldSession = NativeBearerSession(schemaVersion: 1, tokenType: "Bearer", token: bearer, expiresAt: now + 800, accountMode: .linked)
        let retainedEncoding = String(decoding: try JSONEncoder().encode(oldSession), as: UTF8.self)
        var failedStored: String? = retainedEncoding
        let failedVault = NativeBearerVault(read: { failedStored }, write: { failedStored = $0 }, delete: { failedStored = nil })
        let exchangeFailure = RecordingNativeTransport([
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]), headers: [:]),
        ])
        let failedController = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: endpoints, transport: exchangeFailure), vault: failedVault)
        do {
            _ = try await failedController.connect(identityToken: identityToken, authorizationCode: authorizationCode, rawNonce: rawNonce, targetAccountBinding: "failed-exchange-user", now: now)
            fatalError("failed exchange unexpectedly retained a session")
        } catch {}
        require(failedStored == retainedEncoding, "failed exchange cleared an unrelated valid bearer before server verification")

        var undeletableStored: String? = retainedEncoding
        let undeletableVault = NativeBearerVault(
            read: { undeletableStored },
            write: { undeletableStored = $0 },
            delete: { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
        )
        let cleanupFailure = RecordingNativeTransport([
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]), headers: [:]),
        ])
        let cleanupFailureController = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: endpoints, transport: cleanupFailure), vault: undeletableVault)
        do {
            _ = try await cleanupFailureController.connect(identityToken: identityToken, authorizationCode: authorizationCode, rawNonce: rawNonce, targetAccountBinding: "cleanup-failure-user", now: now)
            fatalError("failed exchange unexpectedly succeeded")
        } catch {}
        require(undeletableStored == retainedEncoding, "injected Keychain deletion failure did not retain its evidence")

        failedStored = String(decoding: try JSONEncoder().encode(oldSession), as: UTF8.self)
        let revokeFailure = RecordingNativeTransport([
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]), headers: [:]),
        ])
        let disconnectController = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: endpoints, transport: revokeFailure), vault: failedVault)
        do {
            try await disconnectController.disconnect(now: now)
            fatalError("failed revoke unexpectedly succeeded")
        } catch {}
        require(failedStored == nil, "durably queued failed revoke retained a second active bearer copy")

        var clearCount = 0
        var partiallyStoredBearer: String?
        let unwritableVault = NativeBearerVault(
            read: { partiallyStoredBearer },
            write: { value in partiallyStoredBearer = value;throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED") },
            delete: { clearCount += 1;partiallyStoredBearer = nil }
        )
        let saveFailureTransport = RecordingNativeTransport([
            .init(status: 200, data: exchangeBody, headers: [:]),
            .init(status: 200, data: revokeBody, headers: [:]),
        ])
        let saveFailureController = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: endpoints, transport: saveFailureTransport), vault: unwritableVault)
        do {
            _ = try await saveFailureController.connect(identityToken: identityToken, authorizationCode: authorizationCode, rawNonce: rawNonce, targetAccountBinding: "save-failure-user", now: now)
            fatalError("unwritable Keychain unexpectedly established a session")
        } catch {}
        require(
            clearCount == 0
                && partiallyStoredBearer?.contains(bearer) == true
                && saveFailureTransport.requests.compactMap { $0.0.url?.path }
                    == ["/api/auth/apple/native/exchange", "/api/auth/apple/native/activate"],
            "failed bearer persistence did not retain both active-token recovery records"
        )
        let saveFailurePending = try saveFailureController.pendingActivationVault.load()
        require(
            saveFailurePending?.pendingSession.token == bearer,
            "failed bearer persistence lost its exact activation journal"
        )

        var lateStoredBearer: String?
        let lateVault = NativeBearerVault(
            read: { lateStoredBearer },
            write: { lateStoredBearer = $0 },
            delete: { lateStoredBearer = nil }
        )
        let lateTransport = RecordingNativeTransport([
            .init(status: 200, data: exchangeBody, headers: ["Cache-Control": "no-store"]),
            .init(status: 200, data: revokeBody, headers: ["Cache-Control": "no-store"]),
        ])
        let lateController = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: endpoints, transport: lateTransport), vault: lateVault)
        var signInGeneration = NativeLifecycleGeneration()
        let capturedSignIn = signInGeneration.capture()
        let lateIssued = try await lateController.connect(identityToken: identityToken, authorizationCode: authorizationCode, rawNonce: rawNonce, targetAccountBinding: "late-user", now: now)
        signInGeneration.invalidate() // Models a background lock while the exchange was suspended.
        if !signInGeneration.isCurrent(capturedSignIn) {
            try await lateController.retireIssuedSession(lateIssued, pendingDeletion: false, now: now)
        }
        require(lateStoredBearer == nil, "a delayed exchange restored its bearer after background lock")
        require(lateTransport.requests.count == 3 && lateTransport.requests.last?.0.url?.path == "/api/auth/apple/native/revoke", "explicit stale-result retirement did not revoke the active bearer")
    }

    static func pendingActivationContract() async throws {
        let token = "v1." + String(repeating: "P", count: 43)
        let pending = NativeApplePendingSessionResponse(
            schemaVersion: 2,
            activationState: "pending",
            tokenType: "Bearer",
            token: token,
            expiresAt: now + 900,
            accountMode: .linked
        )
        let ordinaryContext = try NativeAppleActivationContext(
            targetAccountBinding: "pending-activation-user",
            purpose: .ordinary,
            transferRecoveryUser: nil
        )
        var journalStorage: String?
        var journalWrites = 0
        let journal = NativePendingActivationVault(
            read: { journalStorage },
            write: { journalWrites += 1; journalStorage = $0 },
            delete: { journalStorage = nil }
        )
        let saved = try journal.save(pending, context: ordinaryContext, now: now)
        require(journalWrites == 1, "pending activation was not written exactly once")
        let savedReadback = try journal.load()
        require(savedReadback == saved, "pending activation did not survive exact readback")
        let journalObject = try JSONSerialization.jsonObject(
            with: Data((journalStorage ?? "").utf8)
        ) as! [String: Any]
        require(
            Set(journalObject.keys) == Set([
                "schemaVersion",
                "targetAccountBindingHash",
                "purpose",
                "transferRecoveryAccountBindingHash",
                "pendingSession",
            ]),
            "pending activation journal keys drifted"
        )
        require(
            journalObject["transferRecoveryAccountBindingHash"] is NSNull,
            "ordinary activation did not encode an explicit null transfer context"
        )
        require(
            !(journalStorage ?? "").contains("pending-activation-user"),
            "pending activation journal stored the plaintext Apple account binding"
        )
        _ = try journal.save(pending, context: ordinaryContext, now: now)
        require(journalWrites == 1, "idempotent pending activation rewrote its exact record")
        let conflicting = NativeApplePendingSessionResponse(
            schemaVersion: 2,
            activationState: "pending",
            tokenType: "Bearer",
            token: "v1." + String(repeating: "Q", count: 43),
            expiresAt: now + 900,
            accountMode: .linked
        )
        do {
            _ = try journal.save(conflicting, context: ordinaryContext, now: now)
            fatalError("pending activation journal overwrote a distinct exact token")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT", "pending activation conflict returned the wrong error")
        }
        let conflictReadback = try journal.load()
        require(conflictReadback == saved, "pending activation conflict mutated retained evidence")

        journalStorage = "{future-or-damaged-pending-activation"
        do {
            _ = try journal.load()
            fatalError("invalid pending activation journal was treated as absent")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_INVALID", "invalid pending activation returned the wrong error")
        }
        require(journalStorage != nil, "invalid pending activation bytes were auto-deleted")
        require(journal.blocksAdmission(), "invalid pending activation bytes did not block admission")

        let pendingBody = try json([
            "schemaVersion": 2,
            "activationState": "pending",
            "tokenType": "Bearer",
            "token": token,
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        let activeBody = try json([
            "schemaVersion": 2,
            "activationState": "active",
            "tokenType": "Bearer",
            "token": token,
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        var activeStorage: String?
        let activeVault = NativeBearerVault(
            read: { activeStorage },
            readChecked: { activeStorage },
            write: { activeStorage = $0 },
            delete: { activeStorage = nil }
        )
        journalStorage = nil
        let handshakeTransport = RecordingNativeTransport([
            .init(status: 200, data: pendingBody, headers: ["Content-Type": "application/json"]),
            .init(status: 200, data: activeBody, headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let handshakeController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://activation.example.test")!),
                transport: handshakeTransport
            ),
            vault: activeVault,
            pendingActivationVault: journal
        )
        let activated = try await handshakeController.connect(
            identityToken: "header.payload.signature",
            authorizationCode: "activation-authorization-code",
            rawNonce: String(repeating: "n", count: 43),
            targetAccountBinding: "pending-activation-user",
            now: now
        )
        require(activated.token == token, "activation returned the wrong exact token")
        require(journalStorage == nil, "successful promotion retained its activation journal")
        require(activeVault.load(now: now)?.token == token, "active response was not converted to the legacy local bearer record")
        let handshakePaths = handshakeTransport.requests.compactMap { $0.0.url?.path }
        require(handshakePaths == ["/api/auth/apple/native/exchange", "/api/auth/apple/native/activate"], "two-phase handshake paths drifted")
        let activationRequest = handshakeTransport.requests[1].0
        require(activationRequest.httpMethod == "POST", "activation did not use POST")
        require(activationRequest.value(forHTTPHeaderField: "Authorization") == "Bearer \(token)", "activation did not use canonical bearer authorization")
        require(activationRequest.httpBody == nil, "activation request body was not empty")
        require(activationRequest.value(forHTTPHeaderField: "Content-Type") == nil, "empty activation request sent Content-Type")
        require(activationRequest.value(forHTTPHeaderField: "Cookie") == nil, "activation request leaked Cookie")

        let restartToken = "v1." + String(repeating: "S", count: 43)
        let restartPendingBody = try json([
            "schemaVersion": 2,
            "activationState": "pending",
            "tokenType": "Bearer",
            "token": restartToken,
            "expiresAt": now + 900,
            "accountMode": "standalone",
        ])
        let restartActiveBody = try json([
            "schemaVersion": 2,
            "activationState": "active",
            "tokenType": "Bearer",
            "token": restartToken,
            "expiresAt": now + 900,
            "accountMode": "standalone",
        ])
        activeStorage = nil
        journalStorage = nil
        let lostResponseTransport = RecordingNativeTransport([
            .init(status: 200, data: restartPendingBody, headers: ["Content-Type": "application/json"]),
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "lost"]), headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let interrupted = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://restart.example.test")!),
                transport: lostResponseTransport
            ),
            vault: activeVault,
            pendingActivationVault: journal
        )
        do {
            _ = try await interrupted.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "lost-response-authorization-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "restart-user",
                now: now
            )
            fatalError("lost activation response unexpectedly admitted a bearer")
        } catch { }
        let interruptedRecord = try journal.load()
        require(interruptedRecord?.pendingSession.token == restartToken, "lost activation response discarded the exact journal")
        require(activeStorage == nil, "lost activation response persisted an unconfirmed active bearer")

        let mismatchTransport = RecordingNativeTransport([], automaticActivation: false)
        let mismatchController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://restart.example.test")!),
                transport: mismatchTransport
            ),
            vault: activeVault,
            pendingActivationVault: journal
        )
        do {
            _ = try await mismatchController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "mismatched-transfer-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "restart-user",
                transferRecoveryUser: "old-transfer-user",
                now: now
            )
            fatalError("ordinary pending activation was replayed as a verified transfer")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_MISMATCH", "activation context mismatch returned the wrong error")
        }
        require(mismatchTransport.requests.isEmpty, "activation context mismatch reached exchange or activate")
        let mismatchReadback = try journal.load()
        require(mismatchReadback == interruptedRecord, "activation context mismatch mutated the journal")

        let replayTransport = RecordingNativeTransport([
            .init(status: 200, data: restartActiveBody, headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let restarted = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://restart.example.test")!),
                transport: replayTransport
            ),
            vault: activeVault,
            pendingActivationVault: journal
        )
        let resumed = try await restarted.resumeOrdinaryPendingActivation(
            accountBinding: "restart-user",
            persistenceGeneration: 1,
            now: now
        )
        require(resumed?.token == restartToken, "restart replay returned the wrong bearer")
        require(replayTransport.requests.compactMap { $0.0.url?.path } == ["/api/auth/apple/native/activate"], "restart replay consumed a second Apple authorization code")
        require(journalStorage == nil && activeVault.load(now: now)?.token == restartToken, "restart replay did not atomically finish promotion")

        var missingJournalStorage: String?
        var missingJournalReadCount = 0
        var missingActiveStorage: String?
        let missingJournal = NativePendingActivationVault(
            read: {
                missingJournalReadCount += 1
                if missingJournalReadCount == 5 {
                    missingJournalStorage = nil
                    return nil
                }
                return missingJournalStorage
            },
            write: { missingJournalStorage = $0 },
            delete: { missingJournalStorage = nil }
        )
        let missingJournalTransport = RecordingNativeTransport([
            .init(status: 200, data: pendingBody, headers: ["Content-Type": "application/json"]),
            .init(status: 200, data: activeBody, headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let missingJournalController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://missing-journal.example.test")!),
                transport: missingJournalTransport
            ),
            vault: NativeBearerVault(
                read: { missingActiveStorage },
                readChecked: { missingActiveStorage },
                write: { missingActiveStorage = $0 },
                delete: { missingActiveStorage = nil }
            ),
            pendingActivationVault: missingJournal
        )
        do {
            _ = try await missingJournalController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "missing-journal-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "pending-activation-user",
                now: now
            )
            fatalError("promotion succeeded without the exact pending journal")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT", "missing-journal promotion returned the wrong error")
        }
        require(missingActiveStorage == nil, "missing-journal promotion persisted an unproven active bearer")

        var fullQueueStorage: String?
        let fullQueue = NativePendingRevocationVault(
            read: { fullQueueStorage },
            write: { fullQueueStorage = $0 },
            delete: { fullQueueStorage = nil }
        )
        for marker in ["1", "2", "3", "4"] {
            try fullQueue.stage(
                NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: "v1." + String(repeating: marker, count: 43),
                    expiresAt: now + 900,
                    accountMode: .linked
                ),
                now: now
            )
        }
        let fullQueueTransport = RecordingNativeTransport([], automaticActivation: false)
        let fullQueueController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://full-queue.example.test")!),
                transport: fullQueueTransport
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}),
            pendingRevocationVault: fullQueue,
            pendingActivationVault: .transient()
        )
        do {
            _ = try await fullQueueController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "full-queue-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "full-queue-user",
                now: now
            )
            fatalError("full revocation queue consumed a new Apple authorization code")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL", "full queue preflight returned the wrong error")
        }
        let offlineFullQueuePaths = fullQueueTransport.requests.compactMap { $0.0.url?.path }
        require(
            offlineFullQueuePaths.count == 4
                && offlineFullQueuePaths.allSatisfy { $0 == "/api/auth/apple/native/revoke" },
            "full queue preflight consumed an Apple code instead of retrying only saved revocations"
        )

        let recoveredQueueTransport = RecordingNativeTransport(
            Array(repeating: .init(
                status: 200,
                data: try json(["revoked": true]),
                headers: ["Content-Type": "application/json"]
            ), count: 4) + [
                .init(status: 200, data: pendingBody, headers: ["Content-Type": "application/json"]),
                .init(status: 200, data: activeBody, headers: ["Content-Type": "application/json"]),
            ],
            automaticActivation: false
        )
        var recoveredActiveStorage: String?
        let recoveredQueueController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://full-queue.example.test")!),
                transport: recoveredQueueTransport
            ),
            vault: NativeBearerVault(
                read: { recoveredActiveStorage },
                readChecked: { recoveredActiveStorage },
                write: { recoveredActiveStorage = $0 },
                delete: { recoveredActiveStorage = nil }
            ),
            pendingRevocationVault: fullQueue,
            pendingActivationVault: .transient()
        )
        do {
            _ = try await recoveredQueueController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "recovered-full-queue-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "recovered-full-queue-user",
                now: now
            )
        } catch {
            fatalError("full-queue recovery failed after paths \(recoveredQueueTransport.requests.compactMap { $0.0.url?.path }): \(error.localizedDescription)")
        }
        let recoveredPaths = recoveredQueueTransport.requests.compactMap { $0.0.url?.path }
        require(
            Array(recoveredPaths.prefix(4)).allSatisfy { $0 == "/api/auth/apple/native/revoke" }
                && Array(recoveredPaths.suffix(2)) == [
                    "/api/auth/apple/native/exchange",
                    "/api/auth/apple/native/activate",
                ],
            "network recovery did not drain the full queue before consuming the Apple code"
        )

        var constrainedQueueStorage: String?
        let constrainedQueue = NativePendingRevocationVault(
            read: { constrainedQueueStorage },
            write: { constrainedQueueStorage = $0 },
            delete: { constrainedQueueStorage = nil }
        )
        for marker in ["5", "6", "7"] {
            try constrainedQueue.stage(
                NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: "v1." + String(repeating: marker, count: 43),
                    expiresAt: now + 900,
                    accountMode: .linked
                ),
                now: now
            )
        }
        let retainedActive = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "8", count: 43),
            expiresAt: now + 900,
            accountMode: .linked
        )
        var retainedActiveStorage: String? = String(
            decoding: try JSONEncoder().encode(retainedActive),
            as: UTF8.self
        )
        let constrainedTransport = RecordingNativeTransport([], automaticActivation: false)
        let constrainedController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://constrained-queue.example.test")!),
                transport: constrainedTransport
            ),
            vault: NativeBearerVault(
                read: { retainedActiveStorage },
                readChecked: { retainedActiveStorage },
                write: { retainedActiveStorage = $0 },
                delete: { retainedActiveStorage = nil }
            ),
            pendingRevocationVault: constrainedQueue,
            pendingActivationVault: .transient()
        )
        do {
            _ = try await constrainedController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "constrained-queue-code",
                rawNonce: String(repeating: "n", count: 43),
                targetAccountBinding: "constrained-queue-user",
                now: now
            )
            fatalError("three queued debts plus a distinct active bearer overcommitted retirement capacity")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL", "two-slot capacity preflight returned the wrong error")
        }
        require(
            !constrainedTransport.requests.contains { $0.0.url?.path == "/api/auth/apple/native/exchange" },
            "two-slot capacity preflight consumed an Apple code"
        )
    }

    static func activationAdversarialContract() async throws {
        let endpoints = try NativeServiceEndpoints(
            origin: URL(string: "https://activation-adversarial.example.test")!
        )
        let nonce = String(repeating: "n", count: 43)

        func pending(_ marker: Character, expiresAt: Int = now + 900) -> NativeApplePendingSessionResponse {
            NativeApplePendingSessionResponse(
                schemaVersion: 2,
                activationState: "pending",
                tokenType: "Bearer",
                token: "v1." + String(repeating: marker, count: 43),
                expiresAt: expiresAt,
                accountMode: .linked
            )
        }

        func body(
            _ session: NativeApplePendingSessionResponse,
            activationState: String
        ) throws -> Data {
            try json([
                "schemaVersion": 2,
                "activationState": activationState,
                "tokenType": "Bearer",
                "token": session.token,
                "expiresAt": session.expiresAt,
                "accountMode": session.accountMode.rawValue,
            ])
        }

        // A surviving journal is keyed to the complete authorization purpose, not just its target.
        let contextCases: [(NativeAppleActivationContext, NativeAppleActivationPurpose, String?, String)] = [
            (
                try NativeAppleActivationContext(
                    targetAccountBinding: "context-target",
                    purpose: .transferRecovery,
                    transferRecoveryUser: "old-user-a"
                ),
                .transferRecovery,
                "old-user-c",
                "transfer-old-account mismatch"
            ),
            (
                try NativeAppleActivationContext(
                    targetAccountBinding: "context-target",
                    purpose: .ordinary,
                    transferRecoveryUser: nil
                ),
                .deletionReauthorization,
                nil,
                "ordinary-to-deletion mismatch"
            ),
            (
                try NativeAppleActivationContext(
                    targetAccountBinding: "context-target",
                    purpose: .transferRecovery,
                    transferRecoveryUser: "old-user-a"
                ),
                .deletionReauthorization,
                "old-user-a",
                "transfer-to-deletion mismatch"
            ),
        ]
        for (index, item) in contextCases.enumerated() {
            var journalStorage: String?
            var activeStorage: String?
            let journal = NativePendingActivationVault(
                read: { journalStorage },
                write: { journalStorage = $0 },
                delete: { journalStorage = nil }
            )
            let retained = try journal.save(
                pending(Character(String(index + 1))),
                context: item.0,
                now: now
            )
            let transport = RecordingNativeTransport([], automaticActivation: false)
            let controller = NativeAppleAuthController(
                api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
                vault: NativeBearerVault(
                    read: { activeStorage },
                    readChecked: { activeStorage },
                    write: { activeStorage = $0 },
                    delete: { activeStorage = nil }
                ),
                pendingActivationVault: journal
            )
            do {
                _ = try await controller.connect(
                    identityToken: "header.payload.signature",
                    authorizationCode: "context-mismatch-code-\(index)",
                    rawNonce: nonce,
                    targetAccountBinding: "context-target",
                    transferRecoveryUser: item.2,
                    activationPurpose: item.1,
                    now: now
                )
                fatalError("\(item.3) replayed a journal")
            } catch let error as SandboxError {
                require(
                    error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_MISMATCH",
                    "\(item.3) returned the wrong error"
                )
            }
            require(transport.requests.isEmpty, "\(item.3) reached the network")
            let retainedReadback = try journal.load()
            require(retainedReadback == retained, "\(item.3) mutated the exact journal")
            require(activeStorage == nil, "\(item.3) installed an active bearer")
        }

        for purpose in [NativeAppleActivationPurpose.transferRecovery, .deletionReauthorization] {
            var journalStorage: String?
            var activeStorage: String?
            let journal = NativePendingActivationVault(
                read: { journalStorage },
                write: { journalStorage = $0 },
                delete: { journalStorage = nil }
            )
            let context = try NativeAppleActivationContext(
                targetAccountBinding: "resume-context-target",
                purpose: purpose,
                transferRecoveryUser: purpose == .transferRecovery ? "resume-old-user" : nil
            )
            let retained = try journal.save(pending("X"), context: context, now: now)
            let transport = RecordingNativeTransport([], automaticActivation: false)
            let controller = NativeAppleAuthController(
                api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
                vault: NativeBearerVault(
                    read: { activeStorage },
                    readChecked: { activeStorage },
                    write: { activeStorage = $0 },
                    delete: { activeStorage = nil }
                ),
                pendingActivationVault: journal
            )
            do {
                _ = try await controller.resumeOrdinaryPendingActivation(
                    accountBinding: "resume-context-target",
                    persistenceGeneration: 1,
                    now: now
                )
                fatalError("ordinary restart replay consumed an explicit-flow journal")
            } catch let error as SandboxError {
                require(
                    error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_EXPLICIT_FLOW_REQUIRED",
                    "ordinary restart replay returned the wrong purpose error"
                )
            }
            require(transport.requests.isEmpty, "ordinary restart replay reached the network")
            let retainedReadback = try journal.load()
            require(retainedReadback == retained, "ordinary restart replay mutated explicit-flow evidence")
            require(activeStorage == nil, "ordinary restart replay installed an explicit-flow bearer")
        }

        // Activation 401 is not revoke confirmation: the exact token moves to durable retirement debt.
        let rejectedPending = pending("J")
        var rejectedJournalStorage: String?
        var rejectedActiveStorage: String?
        var rejectedQueueStorage: String?
        let rejectedJournal = NativePendingActivationVault(
            read: { rejectedJournalStorage },
            write: { rejectedJournalStorage = $0 },
            delete: { rejectedJournalStorage = nil }
        )
        let rejectedQueue = NativePendingRevocationVault(
            read: { rejectedQueueStorage },
            write: { rejectedQueueStorage = $0 },
            delete: { rejectedQueueStorage = nil }
        )
        let rejectedTransport = RecordingNativeTransport([
            .init(status: 200, data: try body(rejectedPending, activationState: "pending"), headers: ["Content-Type": "application/json"]),
            .init(status: 401, data: try json(["code": "APPLE_NATIVE_SESSION_REQUIRED", "error": "rejected"]), headers: ["Content-Type": "application/json"]),
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]), headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let rejectedController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: rejectedTransport),
            vault: NativeBearerVault(
                read: { rejectedActiveStorage },
                readChecked: { rejectedActiveStorage },
                write: { rejectedActiveStorage = $0 },
                delete: { rejectedActiveStorage = nil }
            ),
            pendingRevocationVault: rejectedQueue,
            pendingActivationVault: rejectedJournal
        )
        do {
            _ = try await rejectedController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "activation-rejected-code",
                rawNonce: nonce,
                targetAccountBinding: "activation-rejected-user",
                now: now
            )
            fatalError("activation 401 admitted a pending bearer")
        } catch { }
        require(
            rejectedTransport.requests.compactMap { $0.0.url?.path } == [
                "/api/auth/apple/native/exchange",
                "/api/auth/apple/native/activate",
                "/api/auth/apple/native/revoke",
            ],
            "activation 401 was treated as authoritative revoke confirmation"
        )
        require(rejectedJournalStorage == nil && rejectedActiveStorage == nil, "activation 401 left an admitted local bearer")
        let rejectedDebt = try rejectedQueue.snapshot(now: now)
        require(
            rejectedDebt.map(\.bearerToken) == [rejectedPending.token],
            "activation 401 plus revoke outage lost the exact retirement token"
        )

        var failedJournalStorage: String?
        var failedQueueWrites = 0
        let failedJournal = NativePendingActivationVault(
            read: { failedJournalStorage },
            write: { failedJournalStorage = $0 },
            delete: { failedJournalStorage = nil }
        )
        let failedQueue = NativePendingRevocationVault(
            read: { nil },
            write: { _ in failedQueueWrites += 1; throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED") },
            delete: { }
        )
        let failedTransport = RecordingNativeTransport([
            .init(status: 200, data: try body(rejectedPending, activationState: "pending"), headers: ["Content-Type": "application/json"]),
            .init(status: 401, data: try json(["code": "APPLE_NATIVE_SESSION_REQUIRED", "error": "rejected"]), headers: ["Content-Type": "application/json"]),
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]), headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let failedController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: failedTransport),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            pendingRevocationVault: failedQueue,
            pendingActivationVault: failedJournal
        )
        do {
            _ = try await failedController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "activation-rejected-no-queue-code",
                rawNonce: nonce,
                targetAccountBinding: "activation-rejected-no-queue-user",
                now: now
            )
            fatalError("activation rejection hid a queue and network dual failure")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_WRITE_FAILED", "activation retirement dual failure returned the wrong error")
        }
        require(failedQueueWrites == 1, "activation retirement did not make one checked queue write")
        let failedJournalReadback = try failedJournal.load()
        require(failedJournalReadback?.pendingSession.token == rejectedPending.token, "activation retirement dual failure discarded the only client journal")

        // An expired journal is retired before either an explicit reauth requirement or a fresh exchange.
        let expiredSaveNow = now - 1_000
        let expiredPending = pending("E", expiresAt: now - 100)
        var expiredJournalStorage: String?
        var expiredQueueStorage: String?
        let expiredJournal = NativePendingActivationVault(
            read: { expiredJournalStorage },
            write: { expiredJournalStorage = $0 },
            delete: { expiredJournalStorage = nil }
        )
        _ = try expiredJournal.save(
            expiredPending,
            context: try NativeAppleActivationContext(
                targetAccountBinding: "expired-resume-user",
                purpose: .ordinary,
                transferRecoveryUser: nil
            ),
            now: expiredSaveNow
        )
        let expiredQueue = NativePendingRevocationVault(
            read: { expiredQueueStorage },
            write: { expiredQueueStorage = $0 },
            delete: { expiredQueueStorage = nil }
        )
        let expiredOfflineTransport = RecordingNativeTransport([
            .init(status: 503, data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]), headers: ["Content-Type": "application/json"]),
        ], automaticActivation: false)
        let expiredResumeController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: expiredOfflineTransport),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            pendingRevocationVault: expiredQueue,
            pendingActivationVault: expiredJournal
        )
        do {
            _ = try await expiredResumeController.resumeOrdinaryPendingActivation(
                accountBinding: "expired-resume-user",
                persistenceGeneration: 1,
                now: now
            )
            fatalError("expired ordinary journal was activated")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "APPLE_NATIVE_PENDING_ACTIVATION_REAUTHENTICATION_REQUIRED",
                "expired ordinary journal returned the wrong recovery state"
            )
        }
        require(expiredJournalStorage == nil, "expired ordinary journal was not detached after durable staging")
        let expiredDebt = try expiredQueue.snapshot(now: now)
        require(
            expiredDebt.map(\.bearerToken) == [expiredPending.token],
            "expired ordinary journal plus outage did not retain exact retirement debt"
        )

        for (index, revokeStatus) in [200, 401].enumerated() {
            let old = pending(Character(index == 0 ? "G" : "H"), expiresAt: now - 100)
            let fresh = pending(Character(index == 0 ? "K" : "L"))
            var journalStorage: String?
            var activeStorage: String?
            let journal = NativePendingActivationVault(
                read: { journalStorage },
                write: { journalStorage = $0 },
                delete: { journalStorage = nil }
            )
            _ = try journal.save(
                old,
                context: try NativeAppleActivationContext(
                    targetAccountBinding: "expired-connect-user-\(index)",
                    purpose: .ordinary,
                    transferRecoveryUser: nil
                ),
                now: expiredSaveNow
            )
            let revokeData = revokeStatus == 200
                ? try json(["revoked": true])
                : try json(["code": "APPLE_NATIVE_SESSION_REQUIRED", "error": "already retired"])
            let transport = RecordingNativeTransport([
                .init(status: revokeStatus, data: revokeData, headers: ["Content-Type": "application/json"]),
                .init(status: 200, data: try body(fresh, activationState: "pending"), headers: ["Content-Type": "application/json"]),
                .init(status: 200, data: try body(fresh, activationState: "active"), headers: ["Content-Type": "application/json"]),
            ], automaticActivation: false)
            let controller = NativeAppleAuthController(
                api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
                vault: NativeBearerVault(
                    read: { activeStorage },
                    readChecked: { activeStorage },
                    write: { activeStorage = $0 },
                    delete: { activeStorage = nil }
                ),
                pendingActivationVault: journal
            )
            let issued = try await controller.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "expired-connect-code-\(index)",
                rawNonce: nonce,
                targetAccountBinding: "expired-connect-user-\(index)",
                now: now
            )
            require(issued.token == fresh.token, "expired journal recovery installed the wrong fresh token")
            require(
                transport.requests.compactMap { $0.0.url?.path } == [
                    "/api/auth/apple/native/revoke",
                    "/api/auth/apple/native/exchange",
                    "/api/auth/apple/native/activate",
                ],
                "expired journal recovery did not retire before fresh exchange for revoke status \(revokeStatus)"
            )
        }

        // A generation-invalidated exchange retains exact debt even while revoke is offline.
        let supersededLegacyBody = try json([
            "schemaVersion": 1,
            "tokenType": "Bearer",
            "token": "v1." + String(repeating: "U", count: 43),
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        var supersededQueueStorage: String?
        var supersededJournalStorage: String?
        var supersededActiveStorage: String?
        let supersededQueue = NativePendingRevocationVault(
            read: { supersededQueueStorage },
            write: { supersededQueueStorage = $0 },
            delete: { supersededQueueStorage = nil }
        )
        let supersededJournal = NativePendingActivationVault(
            read: { supersededJournalStorage },
            write: { supersededJournalStorage = $0 },
            delete: { supersededJournalStorage = nil }
        )
        let supersededTransport = OutOfOrderNativeTransport(
            olderExchangeBody: supersededLegacyBody,
            newerExchangeBody: supersededLegacyBody,
            revokeBody: try json(["revoked": true]),
            revokeStatus: 503
        )
        let supersededController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: supersededTransport),
            vault: NativeBearerVault(
                read: { supersededActiveStorage },
                readChecked: { supersededActiveStorage },
                write: { supersededActiveStorage = $0 },
                delete: { supersededActiveStorage = nil }
            ),
            pendingRevocationVault: supersededQueue,
            pendingActivationVault: supersededJournal
        )
        let supersededTask = Task {
            try await supersededController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "superseded-offline-code",
                rawNonce: nonce,
                targetAccountBinding: "superseded-offline-user",
                persistenceGeneration: 10,
                now: now
            )
        }
        await supersededTransport.waitForFirstExchange()
        supersededController.invalidatePersistence(generation: 11)
        await supersededTransport.completeFirstExchange()
        do {
            _ = try await supersededTask.value
            fatalError("superseded offline exchange installed a bearer")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED", "superseded offline exchange returned the wrong error")
        }
        require(supersededActiveStorage == nil && supersededJournalStorage == nil, "superseded offline exchange left admitted state")
        let supersededDebt = try supersededQueue.snapshot(now: now)
        require(
            supersededDebt.map(\.bearerToken) == ["v1." + String(repeating: "U", count: 43)],
            "superseded offline exchange lost its exact pending token"
        )

        var unreadableQueueRequests = 0
        let unreadableQueueTransport = RecordingNativeTransport([], automaticActivation: false)
        let unreadableQueueController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: unreadableQueueTransport),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            pendingRevocationVault: NativePendingRevocationVault(
                read: { unreadableQueueRequests += 1; throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
                write: { _ in },
                delete: { }
            )
        )
        do {
            _ = try await unreadableQueueController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "unreadable-queue-code",
                rawNonce: nonce,
                targetAccountBinding: "unreadable-queue-user",
                now: now
            )
            fatalError("unreadable retirement queue consumed an Apple code")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "unreadable queue returned the wrong error")
        }
        require(unreadableQueueRequests == 1 && unreadableQueueTransport.requests.isEmpty, "queue preflight read failure reached exchange")

        // Active and pending tokens are capacity-checked and persisted as one retirement batch.
        var batchQueueStorage: String?
        let batchQueue = NativePendingRevocationVault(
            read: { batchQueueStorage },
            write: { batchQueueStorage = $0 },
            delete: { batchQueueStorage = nil }
        )
        for marker in ["a", "b", "c"] {
            try batchQueue.stage(
                NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: "v1." + String(repeating: marker, count: 43),
                    expiresAt: now + 900,
                    accountMode: .linked
                ),
                now: now
            )
        }
        let batchActive = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "m", count: 43),
            expiresAt: now + 900,
            accountMode: .linked
        )
        let batchPending = pending("n")
        var batchActiveStorage: String? = String(
            decoding: try JSONEncoder().encode(batchActive),
            as: UTF8.self
        )
        var batchJournalStorage: String?
        let batchJournal = NativePendingActivationVault(
            read: { batchJournalStorage },
            write: { batchJournalStorage = $0 },
            delete: { batchJournalStorage = nil }
        )
        _ = try batchJournal.save(
            batchPending,
            context: try NativeAppleActivationContext(
                targetAccountBinding: "batch-retirement-user",
                purpose: .ordinary,
                transferRecoveryUser: nil
            ),
            now: now
        )
        let batchController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: RecordingNativeTransport([], automaticActivation: false)
            ),
            vault: NativeBearerVault(
                read: { batchActiveStorage },
                readChecked: { batchActiveStorage },
                write: { batchActiveStorage = $0 },
                delete: { batchActiveStorage = nil }
            ),
            pendingRevocationVault: batchQueue,
            pendingActivationVault: batchJournal
        )
        let capturedBatch = try batchController.captureSessionsForRetirement()
        require(capturedBatch.sessions.count == 2, "retirement capture omitted active or pending exact token")
        let queueBeforeFailedBatch = try batchQueue.snapshot(now: now)
        do {
            _ = try batchController.stageSessionsForRetirement(capturedBatch, now: now)
            fatalError("two-session retirement partially used one remaining queue slot")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL", "batch capacity failure returned the wrong error")
        }
        let queueAfterFailedBatch = try batchQueue.snapshot(now: now)
        let batchJournalReadback = try batchJournal.load()
        require(queueAfterFailedBatch == queueBeforeFailedBatch, "failed retirement batch partially mutated the queue")
        require(batchActiveStorage != nil && batchJournalReadback?.pendingSession == batchPending, "failed retirement batch detached local evidence")

        var writeFaultQueueStorage: String?
        var writeFaultCount = 0
        let writeFaultQueue = NativePendingRevocationVault(
            read: { writeFaultQueueStorage },
            write: { _ in writeFaultCount += 1; throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED") },
            delete: { writeFaultQueueStorage = nil }
        )
        let writeFaultController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: RecordingNativeTransport([], automaticActivation: false)
            ),
            vault: batchController.vault,
            pendingRevocationVault: writeFaultQueue,
            pendingActivationVault: batchJournal
        )
        do {
            _ = try writeFaultController.stageSessionsForRetirement(capturedBatch, now: now)
            fatalError("retirement batch ignored its checked queue write failure")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_WRITE_FAILED", "batch write failure returned the wrong error")
        }
        require(writeFaultCount == 1 && writeFaultQueueStorage == nil, "batch write failure performed partial persistence")
        let writeFaultJournalReadback = try batchJournal.load()
        require(batchActiveStorage != nil && writeFaultJournalReadback?.pendingSession == batchPending, "batch write failure detached active or pending evidence")

        // Deletion reauthorization persists the replacement expiry, then explicit discard
        // hands every copy to durable revocation debt before removing the transaction.
        let deletionAccount = "delayed-deletion-account"
        let deletionCreatedAt = now - (10 * 24 * 60 * 60)
        let originalDeletionSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "d", count: 43),
            expiresAt: deletionCreatedAt + 900,
            accountMode: .linked
        )
        let replacementDeletionSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "e", count: 43),
            expiresAt: now + 900,
            accountMode: .linked
        )
        var deletionAttemptStorage: String?
        let deletionVault = NativeAccountDeletionAttemptVault(
            read: { _ in deletionAttemptStorage },
            write: { _, value in deletionAttemptStorage = value },
            delete: { _ in deletionAttemptStorage = nil },
            random: { _ in Data(repeating: 7, count: 32) }
        )
        _ = try deletionVault.attempt(
            accountBinding: deletionAccount,
            bearer: originalDeletionSession,
            now: deletionCreatedAt
        )
        try deletionVault.requireReauthentication(now: now)
        try deletionVault.replaceBearer(
            accountBinding: deletionAccount,
            bearer: replacementDeletionSession,
            now: now
        )
        let persistedDeletionObject = try JSONSerialization.jsonObject(
            with: Data((deletionAttemptStorage ?? "").utf8)
        ) as! [String: Any]
        require(
            persistedDeletionObject["schemaVersion"] as? Int == 3
                && persistedDeletionObject["bearerExpiresAt"] as? Int == replacementDeletionSession.expiresAt,
            "deletion reauthorization did not durably bind the replacement bearer's exact expiry"
        )
        var deletionActiveStorage: String? = String(
            decoding: try JSONEncoder().encode(replacementDeletionSession),
            as: UTF8.self
        )
        var deletionJournalStorage: String?
        var deletionQueueStorage: String?
        let deletionJournal = NativePendingActivationVault(
            read: { deletionJournalStorage },
            write: { deletionJournalStorage = $0 },
            delete: { deletionJournalStorage = nil }
        )
        let deletionPending = NativeApplePendingSessionResponse(
            schemaVersion: 2,
            activationState: "pending",
            tokenType: "Bearer",
            token: replacementDeletionSession.token,
            expiresAt: replacementDeletionSession.expiresAt,
            accountMode: replacementDeletionSession.accountMode
        )
        _ = try deletionJournal.save(
            deletionPending,
            context: try NativeAppleActivationContext(
                targetAccountBinding: deletionAccount,
                purpose: .deletionReauthorization,
                transferRecoveryUser: nil
            ),
            now: now
        )
        let deletionQueue = NativePendingRevocationVault(
            read: { deletionQueueStorage },
            write: { deletionQueueStorage = $0 },
            delete: { deletionQueueStorage = nil }
        )
        let deletionOfflineTransport = RecordingNativeTransport(
            [],
            injectedFailures: [.blocked("NETWORK_OFFLINE")],
            automaticActivation: false
        )
        let deletionController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: deletionOfflineTransport),
            vault: NativeBearerVault(
                read: { deletionActiveStorage },
                readChecked: { deletionActiveStorage },
                write: { deletionActiveStorage = $0 },
                delete: { deletionActiveStorage = nil }
            ),
            deletionVault: deletionVault,
            pendingRevocationVault: deletionQueue,
            pendingActivationVault: deletionJournal
        )
        let preparedDiscard = try deletionController.preparePendingAccountDeletionDiscard(now: now)
        require(deletionAttemptStorage != nil, "discard preparation cleared the transaction before durable handoff")
        require(deletionActiveStorage == nil && deletionJournalStorage == nil, "discard preparation retained an ordinary-admissible deletion bearer")
        try deletionController.discardPendingAccountDeletion()
        require(deletionAttemptStorage == nil, "checked discard retained its deletion transaction")
        do {
            try await deletionController.retirePreparedSessions(preparedDiscard, now: now)
            fatalError("offline deletion discard reported server revocation")
        } catch is NativeRevocationDeferredError { }
        let delayedDeletionDebt = try deletionQueue.snapshot(now: now)
        let grantTail = NativeServiceLimits.nativeGrantLifetimeSeconds
            - NativeServiceLimits.bearerLifetimeSeconds
        require(
            delayedDeletionDebt.count == 1
                && delayedDeletionDebt[0].bearerToken == replacementDeletionSession.token
                && delayedDeletionDebt[0].expiresAt == replacementDeletionSession.expiresAt + grantTail,
            "delayed deletion reauthorization used the original transaction time for retirement"
        )

        // Legacy v2 replacement timing is unknowable. Preserve that ambiguity through a 401
        // transition and reserve the full possible grant lifetime from explicit discard.
        let legacyToken = "v1." + String(repeating: "f", count: 43)
        let legacyHash = try NativeAccountBinding.hash("legacy-deletion-account")
        var legacyAttemptStorage: String? = String(decoding: try json([
            "schemaVersion": 2,
            "accountBindingHash": legacyHash,
            "idempotencyKey": "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "bearerToken": legacyToken,
            "accountMode": "linked",
            "requiresReauthentication": false,
            "createdAt": deletionCreatedAt,
            "expiresAt": deletionCreatedAt + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds,
        ]), as: UTF8.self)
        let legacyDeletionVault = NativeAccountDeletionAttemptVault(
            read: { _ in legacyAttemptStorage },
            write: { _, value in legacyAttemptStorage = value },
            delete: { _ in legacyAttemptStorage = nil }
        )
        try legacyDeletionVault.requireReauthentication(now: now)
        let legacyAfter401 = try JSONSerialization.jsonObject(
            with: Data((legacyAttemptStorage ?? "").utf8)
        ) as! [String: Any]
        require(
            legacyAfter401["schemaVersion"] as? Int == 2
                && legacyAfter401["bearerExpiresAt"] == nil,
            "legacy deletion 401 falsely converted ambiguous bearer timing into exact v3 state"
        )
        var legacyQueueStorage: String?
        let legacyQueue = NativePendingRevocationVault(
            read: { legacyQueueStorage },
            write: { legacyQueueStorage = $0 },
            delete: { legacyQueueStorage = nil }
        )
        let legacyTransport = RecordingNativeTransport(
            [],
            injectedFailures: [.blocked("NETWORK_OFFLINE")],
            automaticActivation: false
        )
        let legacyController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: legacyTransport),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            deletionVault: legacyDeletionVault,
            pendingRevocationVault: legacyQueue
        )
        let legacyPrepared = try legacyController.preparePendingAccountDeletionDiscard(now: now)
        try legacyController.discardPendingAccountDeletion()
        do {
            try await legacyController.retirePreparedSessions(legacyPrepared, now: now)
            fatalError("offline legacy deletion discard reported server revocation")
        } catch is NativeRevocationDeferredError { }
        let legacyDebt = try legacyQueue.snapshot(now: now)
        require(
            legacyDebt.count == 1
                && legacyDebt[0].bearerToken == legacyToken
                && legacyDebt[0].schemaVersion == 3
                && legacyDebt[0].expiresAt
                    == deletionCreatedAt
                        + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
                        + NativeServiceLimits.nativeGrantLifetimeSeconds
                        + NativeServiceLimits.nativeResponseClockSkewSeconds,
            "legacy ambiguous replacement timing produced an early revocation-debt horizon"
        )

        var rollbackAttemptStorage: String? = String(decoding: try json([
            "schemaVersion": 2,
            "accountBindingHash": legacyHash,
            "idempotencyKey": "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "bearerToken": legacyToken,
            "accountMode": "linked",
            "requiresReauthentication": true,
            "createdAt": deletionCreatedAt,
            "expiresAt": deletionCreatedAt + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds,
        ]), as: UTF8.self)
        let rollbackDeletionVault = NativeAccountDeletionAttemptVault(
            read: { _ in rollbackAttemptStorage },
            write: { _, value in rollbackAttemptStorage = value },
            delete: { _ in rollbackAttemptStorage = nil }
        )
        let rollbackController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: RecordingNativeTransport([], automaticActivation: false)
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            deletionVault: rollbackDeletionVault
        )
        do {
            _ = try rollbackController.preparePendingAccountDeletionDiscard(
                now: deletionCreatedAt - 1
            )
            fatalError("clock rollback converted ambiguous legacy timing into short debt")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID", "clock rollback returned the wrong legacy error")
        }
        require(rollbackAttemptStorage != nil, "clock rollback discarded the ambiguous legacy transaction")

        var invalidAttemptStorage: String? = String(decoding: try json([
            "schemaVersion": 4,
            "accountBindingHash": legacyHash,
            "idempotencyKey": "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "bearerToken": legacyToken,
            "bearerExpiresAt": now + 900,
            "accountMode": "linked",
            "requiresReauthentication": false,
            "createdAt": now,
            "expiresAt": now + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds,
        ]), as: UTF8.self)
        var invalidDeletionDeleteCount = 0
        let invalidDeletionVault = NativeAccountDeletionAttemptVault(
            read: { _ in invalidAttemptStorage },
            write: { _, value in invalidAttemptStorage = value },
            delete: { _ in invalidDeletionDeleteCount += 1; invalidAttemptStorage = nil }
        )
        do {
            _ = try invalidDeletionVault.load(now: now)
            fatalError("unknown deletion-attempt schema was accepted")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID", "unknown deletion schema returned the wrong error")
        }
        require(invalidAttemptStorage != nil, "unknown deletion-attempt bytes were auto-deleted")
        let invalidDeletionController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: RecordingNativeTransport([], automaticActivation: false)
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            deletionVault: invalidDeletionVault
        )
        do {
            _ = try invalidDeletionController.preparePendingAccountDeletionDiscard(now: now)
            fatalError("explicit discard prepared an unknown deletion-attempt schema")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID",
                "unknown deletion discard returned the wrong fail-closed error"
            )
        }
        require(
            invalidAttemptStorage != nil && invalidDeletionDeleteCount == 0,
            "explicit discard deleted unknown exact-token evidence before retirement"
        )

        // Authoritative deletion for B cannot clear unrelated offline retirement debt for A,
        // and an expired-but-structural attempt can still finalize from its durable outcome.
        let unrelatedSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "g", count: 43),
            expiresAt: now + 900,
            accountMode: .linked
        )
        var finalizerQueueStorage: String?
        let finalizerQueue = NativePendingRevocationVault(
            read: { finalizerQueueStorage },
            write: { finalizerQueueStorage = $0 },
            delete: { finalizerQueueStorage = nil }
        )
        try finalizerQueue.stage(unrelatedSession, now: now)
        let finalizedAccount = "finalized-account-b"
        let finalizedHash = try NativeAccountBinding.hash(finalizedAccount)
        let expiredAttemptCreatedAt = now - NativeServiceLimits.accountDeletionAttemptLifetimeSeconds - 1
        var finalizerAttemptStorage: String? = String(
            decoding: try JSONEncoder().encode(NativeAccountDeletionAttempt(
                accountBindingHash: finalizedHash,
                idempotencyKey: "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                bearerToken: "v1." + String(repeating: "h", count: 43),
                bearerExpiresAt: expiredAttemptCreatedAt + 900,
                accountMode: .standalone,
                createdAt: expiredAttemptCreatedAt,
                expiresAt: expiredAttemptCreatedAt + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
            )),
            as: UTF8.self
        )
        let finalizerDeletionVault = NativeAccountDeletionAttemptVault(
            read: { _ in finalizerAttemptStorage },
            write: { _, value in finalizerAttemptStorage = value },
            delete: { _ in finalizerAttemptStorage = nil }
        )
        var finalizerJournalStorage: String?
        let finalizerJournal = NativePendingActivationVault(
            read: { finalizerJournalStorage },
            write: { finalizerJournalStorage = $0 },
            delete: { finalizerJournalStorage = nil }
        )
        _ = try finalizerJournal.save(
            pending("i"),
            context: try NativeAppleActivationContext(
                targetAccountBinding: finalizedAccount,
                purpose: .deletionReauthorization,
                transferRecoveryUser: nil
            ),
            now: now
        )
        let finalizerController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: RecordingNativeTransport([], automaticActivation: false)
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            deletionVault: finalizerDeletionVault,
            pendingRevocationVault: finalizerQueue,
            pendingActivationVault: finalizerJournal
        )
        try finalizerController.finalizeConfirmedAccountDeletion(accountBindingHash: finalizedHash)
        require(finalizerAttemptStorage == nil && finalizerJournalStorage == nil, "confirmed deletion did not finish its exact local transaction")
        let unrelatedDebtAfterFinalization = try finalizerQueue.snapshot(now: now)
        require(
            unrelatedDebtAfterFinalization.map(\.bearerToken) == [unrelatedSession.token],
            "one account's confirmed deletion cleared another account's revocation debt"
        )

        // A held refresh that loses to Lock must extend same-token debt to the refreshed grant.
        let racingToken = "v1." + String(repeating: "r", count: 43)
        let preRefreshSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: racingToken,
            expiresAt: now + 100,
            accountMode: .linked
        )
        let refreshedExpiry = now + 900
        let refreshedBody = try json([
            "schemaVersion": 2,
            "activationState": "active",
            "tokenType": "Bearer",
            "token": racingToken,
            "expiresAt": refreshedExpiry,
            "accountMode": "linked",
        ])
        var racingActiveStorage: String? = String(
            decoding: try JSONEncoder().encode(preRefreshSession),
            as: UTF8.self
        )
        var racingQueueStorage: String?
        let racingQueue = NativePendingRevocationVault(
            read: { racingQueueStorage },
            write: { racingQueueStorage = $0 },
            delete: { racingQueueStorage = nil }
        )
        let heldRefreshTransport = HeldNativeRefreshTransport(
            refreshedBody: refreshedBody,
            revokeStatus: 503
        )
        let racingVault = NativeBearerVault(
            read: { racingActiveStorage },
            readChecked: { racingActiveStorage },
            write: { racingActiveStorage = $0 },
            delete: { racingActiveStorage = nil },
            retirementBlocked: { token, checkedNow in
                racingQueue.blocksAdmission(bearerToken: token, now: checkedNow)
            }
        )
        let racingController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: heldRefreshTransport),
            vault: racingVault,
            pendingRevocationVault: racingQueue
        )
        let refreshTask = Task {
            try await racingController.refreshIfNeeded(
                minimumRemainingSeconds: 300,
                now: now
            )
        }
        await heldRefreshTransport.waitUntilRefreshHeld()
        let racingCaptured = try racingController.captureSessionsForRetirement()
        let racingPrepared = try racingController.stageSessionsForRetirement(racingCaptured, now: now)
        try racingController.handoffPreparedSessionsForRetirement(racingPrepared, now: now)
        await heldRefreshTransport.releaseRefresh()
        do {
            _ = try await refreshTask.value
            fatalError("refresh restored authority after Lock retirement handoff")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED", "refresh-vs-Lock returned the wrong error")
        }
        let racingDebt = try racingQueue.snapshot(now: now)
        require(
            racingDebt.count == 1
                && racingDebt[0].bearerToken == racingToken
                && racingDebt[0].expiresAt == refreshedExpiry + grantTail,
            "refresh-vs-Lock retained the pre-refresh grant horizon"
        )
        require(racingVault.load(now: now) == nil, "refresh-vs-Lock re-admitted the retired bearer")
        let heldRefreshPaths = await heldRefreshTransport.paths()
        require(
            heldRefreshPaths == [
                "/api/auth/apple/native/refresh",
            ],
            "refresh-vs-Lock launched a competing revoke instead of extending the existing retirement transaction"
        )
    }

    static func responseTimingAndRefreshAdversarialContract() async throws {
        let endpoints = try NativeServiceEndpoints(
            origin: URL(string: "https://response-timing.example.test")!
        )
        let start = now + 100
        let receivedAt = start + 45
        let maximumAcceptedExpiry = receivedAt
            + NativeServiceLimits.bearerLifetimeSeconds
            + NativeServiceLimits.nativeResponseClockSkewSeconds
        let nonce = String(repeating: "n", count: 43)

        func sessionBody(
            token: String,
            expiresAt: Any,
            accountMode: Any = "linked",
            activationState: String = "pending",
            extra: Bool = false
        ) throws -> Data {
            var payload: [String: Any] = [
                "schemaVersion": 2,
                "activationState": activationState,
                "tokenType": "Bearer",
                "token": token,
                "expiresAt": expiresAt,
                "accountMode": accountMode,
            ]
            if extra { payload["unexpected"] = true }
            return try json(payload)
        }

        func decodedBearer(_ encoded: String?) -> NativeBearerSession? {
            guard let encoded, let data = encoded.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(NativeBearerSession.self, from: data)
        }

        // Request latency and bounded server skew are measured from one immutable receive sample.
        let boundaryToken = "v1." + String(repeating: "t", count: 43)
        var boundaryActive: String?
        let boundaryClock = ReceivedClockProbe(expectedValue: receivedAt)
        let boundaryTransport = RecordingNativeTransport([
            .init(
                status: 200,
                data: try sessionBody(
                    token: boundaryToken,
                    expiresAt: maximumAcceptedExpiry
                ),
                headers: ["Content-Type": "application/json"]
            ),
        ])
        let boundaryController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: boundaryTransport,
                clock: boundaryClock.sample
            ),
            vault: NativeBearerVault(
                read: { boundaryActive },
                readChecked: { boundaryActive },
                write: { boundaryActive = $0 },
                delete: { boundaryActive = nil }
            )
        )
        let boundarySession = try await boundaryController.connect(
            identityToken: "header.payload.signature",
            authorizationCode: "forty-five-second-boundary-code",
            rawNonce: nonce,
            targetAccountBinding: "timing-boundary-user",
            now: start
        )
        require(
            boundarySession.expiresAt == maximumAcceptedExpiry
                && decodedBearer(boundaryActive)?.expiresAt == maximumAcceptedExpiry
                && boundaryClock.count() == 2,
            "receive-time validation changed the exact expiry or sampled a response twice"
        )

        // Excessive-future and already-expired responses are never admitted and retain exact debt.
        for (index, rejectedExpiry) in [maximumAcceptedExpiry + 1, receivedAt].enumerated() {
            let token = "v1." + String(repeating: index == 0 ? "u" : "v", count: 43)
            var active: String?
            var debtStorage: String?
            let debt = NativePendingRevocationVault(
                read: { debtStorage },
                write: { debtStorage = $0 },
                delete: { debtStorage = nil }
            )
            let transport = RecordingNativeTransport([
                .init(
                    status: 200,
                    data: try sessionBody(token: token, expiresAt: rejectedExpiry),
                    headers: ["Content-Type": "application/json"]
                ),
            ], automaticActivation: false)
            let controller = NativeAppleAuthController(
                api: NativeAppleAuthAPI(
                    endpoints: endpoints,
                    transport: transport,
                    clock: { receivedAt }
                ),
                vault: NativeBearerVault(
                    read: { active },
                    readChecked: { active },
                    write: { active = $0 },
                    delete: { active = nil }
                ),
                pendingRevocationVault: debt
            )
            do {
                _ = try await controller.connect(
                    identityToken: "header.payload.signature",
                    authorizationCode: "rejected-time-code-\(index)",
                    rawNonce: nonce,
                    targetAccountBinding: "rejected-time-user-\(index)",
                    now: start
                )
                fatalError("time-invalid exchange response was admitted")
            } catch let error as NativeAppleSessionResponseRejected {
                require(error.session.token == token, "time rejection lost the exact exchange token")
            }
            let retained = try debt.snapshot(now: receivedAt)
            require(
                active == nil
                    && retained.count == 1
                    && retained[0].schemaVersion == 4
                    && retained[0].bearerToken == token
                    && retained[0].expiresAt == receivedAt
                        + NativeServiceLimits.nativeGrantLifetimeSeconds
                        + NativeServiceLimits.nativeResponseClockSkewSeconds,
                "time-invalid exchange response was not conservatively quarantined"
            )
        }

        // A bounded 2xx body salvages a regex-valid token even when strict wire validation fails.
        let strictCases: [(Data, String)] = [
            (
                try sessionBody(
                    token: "v1." + String(repeating: "w", count: 43),
                    expiresAt: maximumAcceptedExpiry,
                    extra: true
                ),
                "application/json"
            ),
            (
                try sessionBody(
                    token: "v1." + String(repeating: "x", count: 43),
                    expiresAt: "invalid",
                    accountMode: "invalid"
                ),
                "application/json"
            ),
            (
                try sessionBody(
                    token: "v1." + String(repeating: "y", count: 43),
                    expiresAt: maximumAcceptedExpiry
                ),
                "text/plain"
            ),
        ]
        for (index, strictCase) in strictCases.enumerated() {
            let expectedToken = (try JSONSerialization.jsonObject(with: strictCase.0) as! [String: Any])["token"] as! String
            var debtStorage: String?
            let debt = NativePendingRevocationVault(
                read: { debtStorage },
                write: { debtStorage = $0 },
                delete: { debtStorage = nil }
            )
            let transport = RecordingNativeTransport([
                .init(status: 200, data: strictCase.0, headers: ["Content-Type": strictCase.1]),
            ], automaticActivation: false)
            let controller = NativeAppleAuthController(
                api: NativeAppleAuthAPI(
                    endpoints: endpoints,
                    transport: transport,
                    clock: { receivedAt }
                ),
                vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
                pendingRevocationVault: debt
            )
            do {
                _ = try await controller.connect(
                    identityToken: "header.payload.signature",
                    authorizationCode: "strict-rejection-code-\(index)",
                    rawNonce: nonce,
                    targetAccountBinding: "strict-rejection-user-\(index)",
                    now: start
                )
                fatalError("strictly invalid exchange response was admitted")
            } catch let error as NativeAppleSessionResponseRejected {
                require(
                    error.observedResponseToken == expectedToken,
                    "strict exchange rejection lost its bounded recovery token"
                )
            }
            let strictDebtTokens = try debt.snapshot(now: receivedAt).map(\.bearerToken)
            require(
                strictDebtTokens == [expectedToken],
                "strict exchange rejection did not preserve exact retirement debt"
            )
        }

        let unrecoverableTransport = RecordingNativeTransport([
            .init(
                status: 200,
                data: try json(["schemaVersion": 2, "activationState": "pending"]),
                headers: ["Content-Type": "application/json"]
            ),
        ], automaticActivation: false)
        do {
            _ = try await NativeAppleAuthController(
                api: NativeAppleAuthAPI(
                    endpoints: endpoints,
                    transport: unrecoverableTransport,
                    clock: { receivedAt }
                ),
                vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { })
            ).connect(
                identityToken: "header.payload.signature",
                authorizationCode: "unrecoverable-exchange-code",
                rawNonce: nonce,
                targetAccountBinding: "unrecoverable-exchange-user",
                now: start
            )
            fatalError("unrecoverable exchange response was admitted")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED",
                "unrecoverable exchange response overstated local recovery"
            )
        }

        // Activation mismatch retires the authority named by the pending request, never an arbitrary reply token.
        let pendingToken = "v1." + String(repeating: "a", count: 43)
        let unexpectedActivationToken = "v1." + String(repeating: "b", count: 43)
        var mismatchJournalStorage: String?
        var mismatchDebtStorage: String?
        let mismatchJournal = NativePendingActivationVault(
            read: { mismatchJournalStorage },
            write: { mismatchJournalStorage = $0 },
            delete: { mismatchJournalStorage = nil }
        )
        let mismatchDebt = NativePendingRevocationVault(
            read: { mismatchDebtStorage },
            write: { mismatchDebtStorage = $0 },
            delete: { mismatchDebtStorage = nil }
        )
        let mismatchTransport = RecordingNativeTransport([
            .init(
                status: 200,
                data: try sessionBody(token: pendingToken, expiresAt: maximumAcceptedExpiry),
                headers: ["Content-Type": "application/json"]
            ),
            .init(
                status: 200,
                data: try sessionBody(
                    token: unexpectedActivationToken,
                    expiresAt: maximumAcceptedExpiry,
                    activationState: "active"
                ),
                headers: ["Content-Type": "application/json"]
            ),
        ], automaticActivation: false)
        let mismatchController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: mismatchTransport,
                clock: { receivedAt }
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: { }),
            pendingRevocationVault: mismatchDebt,
            pendingActivationVault: mismatchJournal
        )
        do {
            _ = try await mismatchController.connect(
                identityToken: "header.payload.signature",
                authorizationCode: "activation-mismatch-code",
                rawNonce: nonce,
                targetAccountBinding: "activation-mismatch-user",
                now: start
            )
            fatalError("activation mismatch was admitted")
        } catch let error as NativeAppleSessionResponseRejected {
            require(
                error.observedResponseToken == nil || error.observedResponseToken == unexpectedActivationToken,
                "activation mismatch lost its protocol evidence"
            )
        }
        let mismatchDebtTokens = try mismatchDebt.snapshot(now: receivedAt).map(\.bearerToken)
        require(
            mismatchDebtTokens == [pendingToken],
            "activation mismatch retired the response token instead of the requested pending authority"
        )
        require(mismatchJournalStorage != nil, "activation mismatch discarded its exact pending journal")

        func makeRefreshController(
            token: String,
            expiry: Int,
            transport: NativeHTTPPerforming,
            queue: NativePendingRevocationVault,
            activeStorage: @escaping () -> String?,
            setActiveStorage: @escaping (String?) -> Void
        ) -> NativeAppleAuthController {
            NativeAppleAuthController(
                api: NativeAppleAuthAPI(
                    endpoints: endpoints,
                    transport: transport,
                    clock: { receivedAt }
                ),
                vault: NativeBearerVault(
                    read: activeStorage,
                    readChecked: activeStorage,
                    write: { setActiveStorage($0) },
                    delete: { setActiveStorage(nil) },
                    retirementBlocked: { checkedToken, checkedNow in
                        queue.blocksAdmission(bearerToken: checkedToken, now: checkedNow)
                    }
                ),
                pendingRevocationVault: queue
            )
        }

        // Any uncertain refresh outcome retains conservative debt for the requested token.
        for (index, transport) in [
            RecordingNativeTransport([], injectedFailures: [.blocked("NETWORK_RESPONSE_LOST")]),
            RecordingNativeTransport([
                .init(status: 200, data: Data("not-json".utf8), headers: ["Content-Type": "application/json"]),
            ]),
            RecordingNativeTransport([
                .init(status: 401, data: try json(["code": "APPLE_NATIVE_SESSION_REQUIRED", "error": "expired"]), headers: ["Content-Type": "application/json"]),
            ]),
        ].enumerated() {
            let token = "v1." + String(repeating: index == 0 ? "c" : index == 1 ? "d" : "e", count: 43)
            let initial = NativeBearerSession(
                schemaVersion: 1,
                tokenType: "Bearer",
                token: token,
                expiresAt: start + 100,
                accountMode: .linked
            )
            var active: String? = String(decoding: try JSONEncoder().encode(initial), as: UTF8.self)
            var debtStorage: String?
            let debt = NativePendingRevocationVault(
                read: { debtStorage },
                write: { debtStorage = $0 },
                delete: { debtStorage = nil }
            )
            let controller = makeRefreshController(
                token: token,
                expiry: initial.expiresAt,
                transport: transport,
                queue: debt,
                activeStorage: { active },
                setActiveStorage: { active = $0 }
            )
            do {
                _ = try await controller.refreshIfNeeded(now: start)
                fatalError("uncertain refresh remained admitted")
            } catch is NativeAppleSessionResponseRejected { }
            let queued = try debt.snapshot(now: receivedAt)
            require(
                queued.count == 1
                    && queued[0].schemaVersion == 4
                    && queued[0].bearerToken == token
                    && queued[0].expiresAt == receivedAt
                        + NativeServiceLimits.nativeGrantLifetimeSeconds
                        + NativeServiceLimits.nativeResponseClockSkewSeconds,
                "uncertain refresh did not retain its requested-token horizon"
            )
            require(
                controller.vault.load(now: receivedAt) == nil && active != nil,
                "uncertain refresh left its queued token admitted or destroyed exact evidence"
            )
        }

        // A changed token is protocol evidence only; the refresh request's current token owns the debt.
        let requestedToken = "v1." + String(repeating: "f", count: 43)
        let observedToken = "v1." + String(repeating: "g", count: 43)
        let current = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: requestedToken,
            expiresAt: start + 100,
            accountMode: .linked
        )
        var changedActive: String? = String(decoding: try JSONEncoder().encode(current), as: UTF8.self)
        var changedDebtStorage: String?
        let changedDebt = NativePendingRevocationVault(
            read: { changedDebtStorage },
            write: { changedDebtStorage = $0 },
            delete: { changedDebtStorage = nil }
        )
        let changedTransport = RecordingNativeTransport([
            .init(
                status: 200,
                data: try sessionBody(
                    token: observedToken,
                    expiresAt: maximumAcceptedExpiry,
                    activationState: "active"
                ),
                headers: ["Content-Type": "application/json"]
            ),
        ], automaticActivation: false)
        let changedController = makeRefreshController(
            token: requestedToken,
            expiry: current.expiresAt,
            transport: changedTransport,
            queue: changedDebt,
            activeStorage: { changedActive },
            setActiveStorage: { changedActive = $0 }
        )
        do {
            _ = try await changedController.refreshIfNeeded(now: start)
            fatalError("changed-token refresh was admitted")
        } catch let error as NativeAppleSessionResponseRejected {
            require(error.observedResponseToken == observedToken, "changed-token refresh lost protocol evidence")
        }
        let changedDebtTokens = try changedDebt.snapshot(now: receivedAt).map(\.bearerToken)
        require(
            changedDebtTokens == [requestedToken],
            "changed-token refresh retired an arbitrary response token"
        )
        require(
            changedTransport.requests.compactMap { $0.0.url?.path } == ["/api/auth/apple/native/refresh"],
            "changed-token refresh revoked a shared or arbitrary token"
        )

        // A same-token response cannot change the account owner mode.
        let modeToken = "v1." + String(repeating: "s", count: 43)
        let modeCurrent = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: modeToken,
            expiresAt: start + 100,
            accountMode: .linked
        )
        var modeActive: String? = String(decoding: try JSONEncoder().encode(modeCurrent), as: UTF8.self)
        var modeDebtStorage: String?
        let modeDebt = NativePendingRevocationVault(
            read: { modeDebtStorage },
            write: { modeDebtStorage = $0 },
            delete: { modeDebtStorage = nil }
        )
        let modeTransport = RecordingNativeTransport([
            .init(
                status: 200,
                data: try sessionBody(
                    token: modeToken,
                    expiresAt: maximumAcceptedExpiry,
                    accountMode: "standalone",
                    activationState: "active"
                ),
                headers: ["Content-Type": "application/json"]
            ),
        ], automaticActivation: false)
        let modeController = makeRefreshController(
            token: modeToken,
            expiry: modeCurrent.expiresAt,
            transport: modeTransport,
            queue: modeDebt,
            activeStorage: { modeActive },
            setActiveStorage: { modeActive = $0 }
        )
        do {
            _ = try await modeController.refreshIfNeeded(now: start)
            fatalError("refresh changed the durable account ownership mode")
        } catch let error as NativeAppleSessionResponseRejected {
            require(
                error.observedResponseToken == modeToken,
                "account-mode mismatch lost its same-token protocol evidence"
            )
        }
        let modeDebtTokens = try modeDebt.snapshot(now: receivedAt).map(\.bearerToken)
        require(
            modeDebtTokens == [modeToken]
                && decodedBearer(modeActive)?.accountMode == .linked,
            "account-mode mismatch was persisted or failed to retain requested-token debt"
        )

        // Full retirement storage never turns a synthetic recovery horizon into
        // bearer authority. A foreground credential recheck must force a fresh
        // server refresh before it may reopen admission.
        let fullToken = "v1." + String(repeating: "h", count: 43)
        let fullInitial = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: fullToken,
            expiresAt: start + 600,
            accountMode: .linked
        )
        var fullActive: String? = String(decoding: try JSONEncoder().encode(fullInitial), as: UTF8.self)
        var fullDebtStorage: String?
        let fullDebt = NativePendingRevocationVault(
            read: { fullDebtStorage },
            write: { fullDebtStorage = $0 },
            delete: { fullDebtStorage = nil }
        )
        var fullQueueTokens: [String] = []
        for marker in ["i", "j", "k", "l"] {
            let token = "v1." + String(repeating: Character(marker), count: 43)
            fullQueueTokens.append(token)
            try fullDebt.stage(
                NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: token,
                    expiresAt: start + 500,
                    accountMode: .linked
                ),
                now: start
            )
        }
        let fullTransport = RecordingNativeTransport([], injectedFailures: [.blocked("NETWORK_RESPONSE_LOST")])
        let fullController = makeRefreshController(
            token: fullToken,
            expiry: fullInitial.expiresAt,
            transport: fullTransport,
            queue: fullDebt,
            activeStorage: { fullActive },
            setActiveStorage: { fullActive = $0 }
        )
        do {
            _ = try await fullController.refreshIfNeeded(
                minimumRemainingSeconds: 1_000,
                now: start
            )
            fatalError("full queue accepted an uncertain refresh")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL",
                "full queue did not stop refresh before crossing the server boundary"
            )
        }
        require(
            decodedBearer(fullActive)?.expiresAt == fullInitial.expiresAt,
            "full queue manufactured bearer authority from an uncertain refresh"
        )
        require(
            fullTransport.requests.isEmpty,
            "full queue consumed a refresh request without retirement capacity"
        )
        try fullDebt.remove(bearerToken: fullQueueTokens[0], now: receivedAt)
        let recoveryTransport = RecordingNativeTransport([
            .init(
                status: 200,
                data: try sessionBody(
                    token: fullToken,
                    expiresAt: maximumAcceptedExpiry,
                    activationState: "active"
                ),
                headers: ["Content-Type": "application/json"]
            ),
        ], automaticActivation: false)
        let recoveryController = makeRefreshController(
            token: fullToken,
            expiry: fullInitial.expiresAt,
            transport: recoveryTransport,
            queue: fullDebt,
            activeStorage: { fullActive },
            setActiveStorage: { fullActive = $0 }
        )
        let recovered = try await recoveryController.refreshIfNeeded(
            allowWhileHostedAdmissionBlocked: true,
            now: start
        )
        require(
            recovered?.expiresAt == maximumAcceptedExpiry
                && recoveryTransport.requests.compactMap { $0.0.url?.path }
                    == ["/api/auth/apple/native/refresh"],
            "blocked foreground recovery trusted retained local expiry instead of forcing refresh"
        )
        let fullPrepared = try recoveryController.prepareSessionsForRetirement(now: receivedAt)
        let fullAfterRetirement = try fullDebt.snapshot(now: receivedAt)
        require(
            fullPrepared.sessions.map(\.token) == [fullToken]
                && fullAfterRetirement.contains {
                    $0.bearerToken == fullToken
                        && $0.expiresAt == maximumAcceptedExpiry
                            + NativeServiceLimits.nativeGrantLifetimeSeconds
                            - NativeServiceLimits.bearerLifetimeSeconds
                },
            "later retirement did not preserve the conservative refresh horizon"
        )

        // Concurrent same-token refreshes persist the maximum expiry regardless of response order.
        let orderedToken = "v1." + String(repeating: "m", count: 43)
        let orderedInitial = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: orderedToken,
            expiresAt: start + 100,
            accountMode: .linked
        )
        var orderedActive: String? = String(decoding: try JSONEncoder().encode(orderedInitial), as: UTF8.self)
        let pairedTransport = PairedHeldRefreshTransport()
        let orderedController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: pairedTransport,
                clock: { receivedAt }
            ),
            vault: NativeBearerVault(
                read: { orderedActive },
                readChecked: { orderedActive },
                write: { orderedActive = $0 },
                delete: { orderedActive = nil }
            )
        )
        let olderRefresh = Task { try await orderedController.refreshIfNeeded(now: start) }
        await pairedTransport.waitUntilHeld(count: 1)
        let newerRefresh = Task { try await orderedController.refreshIfNeeded(now: start) }
        await pairedTransport.waitUntilHeld(count: 2)
        let newerExpiry = receivedAt + 900
        try await pairedTransport.release(
            index: 1,
            body: sessionBody(
                token: orderedToken,
                expiresAt: newerExpiry,
                activationState: "active"
            )
        )
        let newerResult = try await newerRefresh.value
        try await pairedTransport.release(
            index: 0,
            body: sessionBody(
                token: orderedToken,
                expiresAt: receivedAt + 800,
                activationState: "active"
            )
        )
        let olderResult = try await olderRefresh.value
        require(
            newerResult?.expiresAt == newerExpiry
                && olderResult?.expiresAt == newerExpiry
                && decodedBearer(orderedActive)?.expiresAt == newerExpiry,
            "out-of-order same-token refresh shortened the saved expiry"
        )
        let pairedPaths = await pairedTransport.paths()
        require(
            pairedPaths == [
                "/api/auth/apple/native/refresh",
                "/api/auth/apple/native/refresh",
            ],
            "out-of-order same-token refresh launched a revoke"
        )

        // Background generation invalidation retains max metadata but never reopens admission.
        let backgroundToken = "v1." + String(repeating: "n", count: 43)
        let backgroundInitial = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: backgroundToken,
            expiresAt: start + 100,
            accountMode: .linked
        )
        var backgroundActive: String? = String(decoding: try JSONEncoder().encode(backgroundInitial), as: UTF8.self)
        let backgroundBody = try sessionBody(
            token: backgroundToken,
            expiresAt: receivedAt + 900,
            activationState: "active"
        )
        let backgroundTransport = HeldNativeRefreshTransport(
            refreshedBody: backgroundBody,
            revokeStatus: 503
        )
        let admissionWasBlocked = NativeHostedAccessAdmission.isBlocked()
        defer {
            if admissionWasBlocked { NativeHostedAccessAdmission.block() }
            else { NativeHostedAccessAdmission.allowAfterCredentialVerification() }
        }
        NativeHostedAccessAdmission.allowAfterCredentialVerification()
        let backgroundVault = NativeBearerVault(
            read: { backgroundActive },
            readChecked: { backgroundActive },
            write: { backgroundActive = $0 },
            delete: { backgroundActive = nil },
            admissionBlocked: { NativeHostedAccessAdmission.isBlocked() }
        )
        let backgroundController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: backgroundTransport,
                clock: { receivedAt }
            ),
            vault: backgroundVault
        )
        let backgroundRefresh = Task {
            try await backgroundController.refreshIfNeeded(
                persistenceGeneration: 10,
                now: start
            )
        }
        await backgroundTransport.waitUntilRefreshHeld()
        NativeHostedAccessAdmission.block()
        backgroundController.invalidatePersistence(generation: 11)
        await backgroundTransport.releaseRefresh()
        do {
            _ = try await backgroundRefresh.value
            fatalError("background-invalidated refresh restored authority")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED", "background refresh returned the wrong error")
        }
        require(
            decodedBearer(backgroundActive)?.expiresAt == receivedAt + 900
                && backgroundVault.load(now: receivedAt) == nil,
            "background refresh failed to retain max metadata while keeping admission blocked"
        )
        let backgroundPaths = await backgroundTransport.paths()
        require(
            backgroundPaths == ["/api/auth/apple/native/refresh"],
            "background refresh revoked the preserved same-token bearer"
        )

        // Disconnect serializes retirement against a held refresh and keeps the extended horizon on outage.
        let disconnectToken = "v1." + String(repeating: "o", count: 43)
        let disconnectInitial = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: disconnectToken,
            expiresAt: start + 100,
            accountMode: .linked
        )
        var disconnectActive: String? = String(decoding: try JSONEncoder().encode(disconnectInitial), as: UTF8.self)
        var disconnectDebtStorage: String?
        let disconnectDebt = NativePendingRevocationVault(
            read: { disconnectDebtStorage },
            write: { disconnectDebtStorage = $0 },
            delete: { disconnectDebtStorage = nil }
        )
        let disconnectTransport = HeldNativeRefreshTransport(
            refreshedBody: try sessionBody(
                token: disconnectToken,
                expiresAt: receivedAt + 900,
                activationState: "active"
            ),
            revokeStatus: 503,
            holdFirstRevoke: true
        )
        let disconnectController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: disconnectTransport,
                clock: { receivedAt }
            ),
            vault: NativeBearerVault(
                read: { disconnectActive },
                readChecked: { disconnectActive },
                write: { disconnectActive = $0 },
                delete: { disconnectActive = nil },
                retirementBlocked: { token, checkedNow in
                    disconnectDebt.blocksAdmission(bearerToken: token, now: checkedNow)
                }
            ),
            pendingRevocationVault: disconnectDebt
        )
        let disconnectRefresh = Task { try await disconnectController.refreshIfNeeded(now: start) }
        await disconnectTransport.waitUntilRefreshHeld()
        let disconnectTask = Task { try await disconnectController.disconnect(now: start) }
        await disconnectTransport.waitUntilRevokeHeld()
        await disconnectTransport.releaseRefresh()
        do {
            _ = try await disconnectRefresh.value
            fatalError("disconnect interleave re-admitted a refreshed token")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED", "disconnect refresh returned the wrong error")
        }
        await disconnectTransport.releaseRevoke()
        do {
            try await disconnectTask.value
            fatalError("offline disconnect unexpectedly completed")
        } catch is NativeRevocationDeferredError { }
        let disconnectQueued = try disconnectDebt.snapshot(now: receivedAt)
        require(
            disconnectActive == nil
                && disconnectQueued.count == 1
                && disconnectQueued[0].bearerToken == disconnectToken
                && disconnectQueued[0].expiresAt == receivedAt
                    + NativeServiceLimits.nativeGrantLifetimeSeconds,
            "disconnect interleave retained a shortened refresh horizon"
        )

        // Forward and restored wall clocks cannot delete or unblock schemas 2, 3, or 4.
        var clockDebtStorage: String?
        let clockDebt = NativePendingRevocationVault(
            read: { clockDebtStorage },
            write: { clockDebtStorage = $0 },
            delete: { clockDebtStorage = nil }
        )
        let schemaTwoToken = "v1." + String(repeating: "p", count: 43)
        let schemaThreeToken = "v1." + String(repeating: "q", count: 43)
        let schemaFourToken = "v1." + String(repeating: "r", count: 43)
        try clockDebt.stage(
            NativeBearerSession(
                schemaVersion: 1,
                tokenType: "Bearer",
                token: schemaTwoToken,
                expiresAt: start + 500,
                accountMode: .linked
            ),
            now: start
        )
        let legacyCreatedAt = start - 100
        let legacyAttempt = NativeAccountDeletionAttempt(
            schemaVersion: 2,
            accountBindingHash: try NativeAccountBinding.hash("clock-schema-three"),
            idempotencyKey: "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            bearerToken: schemaThreeToken,
            bearerExpiresAt: legacyCreatedAt + NativeServiceLimits.bearerLifetimeSeconds,
            accountMode: .linked,
            requiresReauthentication: true,
            createdAt: legacyCreatedAt,
            expiresAt: legacyCreatedAt + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
        )
        _ = try clockDebt.stage([], legacyDeletionAttempt: legacyAttempt, now: start)
        try clockDebt.stageRejectedSession(
            NativeBearerSession(
                schemaVersion: 1,
                tokenType: "Bearer",
                token: schemaFourToken,
                expiresAt: maximumAcceptedExpiry,
                accountMode: .linked
            ),
            receivedAt: receivedAt
        )
        let rawClockDebt = clockDebtStorage
        let jumped = start + 365 * 24 * 60 * 60
        let jumpedClockDebt = try clockDebt.snapshot(now: jumped)
        require(
            jumpedClockDebt.count == 3
                && clockDebtStorage == rawClockDebt
                && clockDebt.blocksAdmission(bearerToken: schemaTwoToken, now: jumped)
                && clockDebt.blocksAdmission(bearerToken: schemaThreeToken, now: jumped)
                && clockDebt.blocksAdmission(bearerToken: schemaFourToken, now: jumped),
            "forward clock jump deleted or unblocked unconfirmed revocation debt"
        )
        let restoredClockDebt = try clockDebt.snapshot(now: start)
        require(
            restoredClockDebt.count == 3
                && clockDebt.blocksAdmission(bearerToken: schemaTwoToken, now: start),
            "clock restoration re-admitted an unconfirmed retired bearer"
        )
    }

    static func revocationFollowUpContract() async throws {
        let endpoints = try NativeServiceEndpoints(origin: URL(string: "https://revocation.example.test")!)
        let revokeBody = try json(["revoked": true])
        let oldToken = "v1." + String(repeating: "R", count: 43)
        let oldSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: oldToken,
            expiresAt: now + 600,
            accountMode: .linked
        )
        let retryExpiry = oldSession.expiresAt
            + NativeServiceLimits.nativeGrantLifetimeSeconds
            - NativeServiceLimits.bearerLifetimeSeconds

        var queueStorage: String?
        let queue = NativePendingRevocationVault(
            read: { queueStorage },
            write: { queueStorage = $0 },
            delete: { queueStorage = nil }
        )

        let legacyQueue = try JSONSerialization.data(withJSONObject: [
            "schemaVersion": 1,
            "entries": [[
                "schemaVersion": 1,
                "bearerToken": oldToken,
                "queuedAt": now,
                "expiresAt": oldSession.expiresAt,
            ]],
        ])
        queueStorage = String(decoding: legacyQueue, as: UTF8.self)
        let upgradedLegacy = try queue.snapshot(now: now + 601)
        let expectedLegacyUpgrade = try NativePendingRevocation(
            session: oldSession,
            now: now
        )
        require(
            upgradedLegacy == [expectedLegacyUpgrade],
            "legacy revocation follow-up was not upgraded beyond bearer expiry"
        )
        let persistedLegacy = try JSONSerialization.jsonObject(
            with: Data(queueStorage!.utf8)
        ) as! [String: Any]
        let persistedLegacyEntries = persistedLegacy["entries"] as! [[String: Any]]
        require(
            persistedLegacyEntries.first?["schemaVersion"] as? Int == 2
                && persistedLegacyEntries.first?["expiresAt"] as? Int == retryExpiry,
            "legacy revocation follow-up did not persist its bounded v2 upgrade"
        )
        try queue.remove(bearerToken: oldToken, now: now + 601)
        require(queueStorage == nil, "upgraded legacy revocation follow-up was not removable")

        try queue.stage(oldSession, now: now)
        try queue.stage(oldSession, now: now)
        let deduplicated = try queue.snapshot(now: now)
        require(deduplicated.count == 1, "revocation follow-up did not deduplicate the same bearer")
        require(queueStorage?.contains(oldToken) == true, "revocation follow-up did not retain the bearer needed for retry")
        var retirementAwareStorage: String? = String(
            decoding: try JSONEncoder().encode(oldSession),
            as: UTF8.self
        )
        let retirementAwareVault = NativeBearerVault(
            read: { retirementAwareStorage },
            write: { retirementAwareStorage = $0 },
            delete: { retirementAwareStorage = nil },
            retirementBlocked: { token, instant in
                queue.blocksAdmission(bearerToken: token, now: instant)
            }
        )
        require(
            retirementAwareVault.load(now: now) == nil,
            "an exact bearer queued for retirement remained available for hosted admission"
        )
        let unrelatedActiveSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: "v1." + String(repeating: "U", count: 43),
            expiresAt: now + 600,
            accountMode: .linked
        )
        retirementAwareStorage = String(
            decoding: try JSONEncoder().encode(unrelatedActiveSession),
            as: UTF8.self
        )
        require(
            retirementAwareVault.load(now: now)?.token == unrelatedActiveSession.token,
            "an old queued bearer blocked a distinct active replacement"
        )
        let initialStatus = try queue.status(now: now)
        require(
            initialStatus == NativePendingRevocationStatus(count: 1, expiresAt: retryExpiry),
            "revocation follow-up status lost its bound"
        )
        try queue.remove(bearerToken: oldToken, now: now)
        require(queueStorage == nil, "completed revocation retained raw bearer material")

        queueStorage = "{unreadable"
        require(
            queue.blocksAdmission(bearerToken: oldToken, now: now),
            "unreadable retirement state failed open for bearer admission"
        )
        require(queueStorage == "{unreadable", "admission check mutated unreadable retirement evidence")
        do {
            _ = try queue.status(now: now)
            fatalError("invalid revocation storage was treated as an empty queue")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID",
                "invalid revocation storage returned the wrong error"
            )
        }
        require(queueStorage == "{unreadable", "checked queue load destroyed invalid retirement evidence")
        try queue.clearChecked()
        require(queueStorage == nil, "explicit invalid-queue discard was not verified")
        for marker in ["A", "B", "C", "D"] {
            try queue.stage(
                NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: "v1." + String(repeating: marker, count: 43),
                    expiresAt: now + 600,
                    accountMode: .standalone
                ),
                now: now
            )
        }
        do {
            try queue.stage(
                NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: "v1." + String(repeating: "E", count: 43),
                    expiresAt: now + 600,
                    accountMode: .standalone
                ),
                now: now
            )
            fatalError("revocation follow-up exceeded its record cap")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL", "full revocation queue returned the wrong error")
        }
        let fullQueue = try queue.snapshot(now: now)
        require(fullQueue.count == NativeServiceLimits.pendingRevocationRecords, "full revocation queue mutated unexpectedly")
        let retainedStatus = try queue.status(now: now + 601)
        require(
            retainedStatus?.count == NativeServiceLimits.pendingRevocationRecords,
            "revocation follow-up ended when the bearer expired instead of when the grant expired"
        )
        let expiredStatus = try queue.status(now: retryExpiry)
        require(
            expiredStatus?.count == NativeServiceLimits.pendingRevocationRecords
                && queueStorage != nil,
            "local wall-clock expiry deleted unconfirmed revocation debt"
        )
        try queue.clearChecked()

        let recentlyExpiredToken = "v1." + String(repeating: "X", count: 43)
        let recentlyExpiredSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: recentlyExpiredToken,
            expiresAt: now - 10,
            accountMode: .linked
        )
        try queue.stage(recentlyExpiredSession, now: now)
        let recentlyExpiredEntries = try queue.snapshot(now: now)
        require(
            recentlyExpiredEntries.map(\.bearerToken) == [recentlyExpiredToken],
            "a recently expired bearer could not retain its durable grant revocation follow-up"
        )
        try queue.remove(bearerToken: recentlyExpiredToken, now: now)
        require(queueStorage == nil, "expired-bearer revocation completion retained raw bearer material")

        var activeStorage: String? = String(decoding: try JSONEncoder().encode(oldSession), as: UTF8.self)
        var deferredStorage: String?
        let activeVault = NativeBearerVault(
            read: { activeStorage },
            write: { activeStorage = $0 },
            delete: { activeStorage = nil }
        )
        let deferredVault = NativePendingRevocationVault(
            read: { deferredStorage },
            write: { deferredStorage = $0 },
            delete: { deferredStorage = nil }
        )
        let offline = RecordingNativeTransport([], injectedFailures: [.blocked("NETWORK_OFFLINE")])
        let disconnectController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: offline),
            vault: activeVault,
            pendingRevocationVault: deferredVault
        )
        do {
            try await disconnectController.disconnect(now: now)
            fatalError("offline revocation unexpectedly completed")
        } catch let error as NativeRevocationDeferredError {
            require(error.expiresAt == retryExpiry, "deferred revocation lost its hard expiry")
        }
        require(activeStorage == nil, "offline disconnect retained the active bearer")
        let deferredEntries = try deferredVault.snapshot(now: now)
        require(deferredEntries.map(\.bearerToken) == [oldToken], "offline disconnect did not persist one retryable bearer")
        require(offline.requests.count == 1, "offline disconnect retried within one user operation")

        let newToken = "v1." + String(repeating: "N", count: 43)
        let exchangeBody = try json([
            "schemaVersion": 1,
            "tokenType": "Bearer",
            "token": newToken,
            "expiresAt": now + 900,
            "accountMode": "linked",
        ])
        let reconnectTransport = RecordingNativeTransport([
            .init(status: 200, data: revokeBody, headers: ["Cache-Control": "no-store"]),
            .init(status: 200, data: exchangeBody, headers: ["Cache-Control": "no-store"]),
        ])
        let reconnectController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: reconnectTransport),
            vault: activeVault,
            pendingRevocationVault: deferredVault
        )
        _ = try await reconnectController.connect(
            identityToken: "header.payload.signature",
            authorizationCode: "reconnect-authorization-code",
            rawNonce: String(repeating: "n", count: 43),
            targetAccountBinding: "reconnect-user",
            now: now
        )
        require(reconnectTransport.requests.map { $0.0.url?.path } == ["/api/auth/apple/native/revoke", "/api/auth/apple/native/exchange", "/api/auth/apple/native/activate"], "the next sign-in did not drain deferred revocation before consuming its Apple code")
        require(reconnectTransport.requests.first?.0.value(forHTTPHeaderField: "Authorization") == "Bearer \(oldToken)", "deferred retry used the new bearer instead of the retired bearer")
        let completedStatus = try deferredVault.status(now: now)
        require(completedStatus == nil && deferredStorage == nil, "confirmed deferred revocation retained raw bearer material")

        activeStorage = String(decoding: try JSONEncoder().encode(oldSession), as: UTF8.self)
        let unavailableQueue = NativePendingRevocationVault(
            read: { nil },
            write: { _ in throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED") },
            delete: {}
        )
        let unavailableTransport = RecordingNativeTransport([], injectedFailures: [.blocked("NETWORK_OFFLINE")])
        let unavailableController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: unavailableTransport),
            vault: activeVault,
            pendingRevocationVault: unavailableQueue
        )
        do {
            try await unavailableController.disconnect(now: now)
            fatalError("disconnect hid unavailable revocation follow-up storage")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_NATIVE_REVOCATION_FOLLOW_UP_NOT_SAVED", "unavailable follow-up storage returned the wrong error")
        }
        require(
            activeStorage?.contains(oldToken) == true,
            "combined follow-up persistence and network failure destroyed the only exact bearer"
        )
        require(unavailableTransport.requests.count == 1, "combined retirement failure did not make exactly one revoke attempt")
    }

    static func accountDeletionRecoveryContract() throws {
        let accountBindingHash = try NativeAccountBinding.hash("recovery-account")
        let retryKey = "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        let bearerToken = "v1." + String(repeating: "B", count: 43)
        func encodedAttempt(createdAt: Int, expiresAt: Int) throws -> String {
            String(decoding: try json([
                "schemaVersion": 2,
                "accountBindingHash": accountBindingHash,
                "idempotencyKey": retryKey,
                "bearerToken": bearerToken,
                "accountMode": "standalone",
                "requiresReauthentication": true,
                "createdAt": createdAt,
                "expiresAt": expiresAt,
            ]), as: UTF8.self)
        }

        var storedAttempt: String? = "{unreadable"
        var rejectDeletion = false
        let deletionVault = NativeAccountDeletionAttemptVault(
            read: { _ in storedAttempt },
            write: { _, value in storedAttempt = value },
            delete: { _ in
                if rejectDeletion { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
                storedAttempt = nil
            }
        )
        let recoveryTransport = RecordingNativeTransport([])
        let controller = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: try NativeServiceEndpoints(origin: URL(string: "https://recovery.example.test")!),
                transport: recoveryTransport
            ),
            vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}),
            deletionVault: deletionVault
        )

        require(
            controller.accountDeletionRecoveryState(now: now) == .requiresExplicitDiscard,
            "corrupt account-deletion recovery did not expose an explicit discard state"
        )
        rejectDeletion = true
        do {
            try controller.discardPendingAccountDeletion()
            fatalError("failed Keychain deletion reported that recovery was discarded")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_DELETE_FAILED", "recovery discard returned the wrong Keychain error")
        }
        require(storedAttempt != nil, "failed recovery discard removed its diagnostic evidence")

        rejectDeletion = false
        try controller.discardPendingAccountDeletion()
        require(
            controller.accountDeletionRecoveryState(now: now) == .none,
            "explicit recovery discard did not unblock a fresh sign-in"
        )

        let expiredCreatedAt = now - NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
        storedAttempt = try encodedAttempt(createdAt: expiredCreatedAt, expiresAt: now)
        require(
            controller.accountDeletionRecoveryState(now: now) == .requiresExplicitDiscard,
            "expired account-deletion recovery was presented as retryable"
        )

        let validCreatedAt = now - 1
        let validExpiresAt = validCreatedAt + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
        let validEncoding = try encodedAttempt(createdAt: validCreatedAt, expiresAt: validExpiresAt)
        storedAttempt = validEncoding
        let expected = try deletionVault.load(now: now)
        require(
            expected != nil && controller.accountDeletionRecoveryState(now: now) == .recoverable(expected!),
            "valid account-deletion recovery was not preserved for retry"
        )
        require(storedAttempt == validEncoding, "recovery inspection mutated a valid retry transaction")
        try controller.discardPendingAccountDeletion()
        require(storedAttempt == nil, "confirmed recovery discard retained a valid retry record")
        require(recoveryTransport.requests.isEmpty, "local recovery inspection or discard contacted the hosted service")
    }

    static func accountDeletionContract() async throws {
        let deterministicBytes = Data((0..<32).map(UInt8.init))
        let expectedKey = "v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        let deterministicKey = try NativeAccountDeletionKey.make { _ in deterministicBytes }
        require(deterministicKey == expectedKey, "account deletion key encoding drifted")

        let accountBinding = "apple-user-for-deletion"
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        var corruptAttempt = String(decoding: try json([
            "schemaVersion": 2,
            "accountBindingHash": accountBindingHash,
            "idempotencyKey": expectedKey,
            "bearerToken": bearer,
            "accountMode": "linked",
            "requiresReauthentication": false,
            "createdAt": Int.max,
            "expiresAt": Int.max,
        ]), as: UTF8.self)
        let corruptAttemptVault = NativeAccountDeletionAttemptVault(
            read: { _ in corruptAttempt },
            write: { _, value in corruptAttempt = value },
            delete: { _ in corruptAttempt = "" }
        )
        for timestamp in [Int.max, Int.min] {
            corruptAttempt = String(decoding: try json([
                "schemaVersion": 2,
                "accountBindingHash": accountBindingHash,
                "idempotencyKey": expectedKey,
                "bearerToken": bearer,
                "accountMode": "linked",
                "requiresReauthentication": false,
                "createdAt": timestamp,
                "expiresAt": Int.max,
            ]), as: UTF8.self)
            do {
                _ = try corruptAttemptVault.load(now: now)
                fatalError("an extreme deletion-attempt timestamp passed validation")
            } catch let error as SandboxError {
                require(error.localizedDescription == "APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID", "extreme timestamp did not fail closed")
            }
        }

        let bearerSession = NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: bearer,
            expiresAt: now + 900,
            accountMode: .linked
        )
        var storedBearer: String? = String(decoding: try JSONEncoder().encode(bearerSession), as: UTF8.self)
        let bearerVault = NativeBearerVault(
            read: { storedBearer },
            write: { storedBearer = $0 },
            delete: { storedBearer = nil }
        )
        var attempts: [String: String] = [:]
        var failAttemptDelete = false
        var randomCalls = 0
        let deletionVault = NativeAccountDeletionAttemptVault(
            read: { attempts[$0] },
            write: { attempts[$0] = $1 },
            delete: { key in
                if failAttemptDelete { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
                attempts.removeValue(forKey: key)
            },
            random: { count in
                randomCalls += 1
                require(count == 32, "account deletion did not request 256 random bits")
                return deterministicBytes
            }
        )
        let success = try json([
            "deleted": true,
            "idempotent": true,
            "providerCredentials": [
                "credentialsFound": 0,
                "credentialsRevoked": 0,
                "unreadableSessions": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": true,
            ],
            "originConnections": [
                "installationsFound": 1,
                "installationsRevoked": 0,
                "unreadableInstallations": 0,
                "failedRevocations": 1,
                "manualRevocationRequired": true,
            ],
        ])
        let transport = RecordingNativeTransport([
            .init(
                status: 503,
                data: try json(["code": "SERVICE_UNAVAILABLE", "error": "offline"]),
                headers: ["Content-Type": "application/json"]
            ),
            .init(status: 200, data: success, headers: ["Content-Type": "application/json; charset=utf-8"]),
        ], injectedFailures: [.blocked("NETWORK_UNCERTAIN")])
        let endpoints = try NativeServiceEndpoints(origin: URL(string: "https://sandbox.example.test")!)
        let controller = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
            vault: bearerVault,
            deletionVault: deletionVault
        )

        do {
            _ = try await controller.deleteAccount(accountBinding: accountBinding, now: now)
            fatalError("uncertain account deletion unexpectedly succeeded")
        } catch {
            require(error.localizedDescription == "NETWORK_UNCERTAIN", "account deletion surfaced an unexpected network failure")
        }
        require(storedBearer != nil, "unconfirmed deletion scrubbed the normal native bearer before lock")
        require(deletionVault.hasPending(accountBinding: accountBinding), "unconfirmed deletion lost its transaction record")

        // Simulate an ordinary background lock and a fresh process. The normal bearer is gone,
        // but the deletion transaction retains the original bearer solely for receipt recovery.
        storedBearer = nil
        let restartedController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
            vault: bearerVault,
            deletionVault: deletionVault
        )
        do {
            _ = try await restartedController.deleteAccount(accountBinding: accountBinding, now: now + 901)
            fatalError("HTTP account deletion failure unexpectedly succeeded")
        } catch {
            require(error.localizedDescription == "SERVICE_UNAVAILABLE: offline", "account deletion surfaced an unexpected HTTP failure")
        }
        require(storedBearer == nil, "restart recreated the cleared normal bearer")
        require(deletionVault.hasPending(accountBinding: accountBinding), "restart lost the deletion transaction bearer or retry key")

        let secondRestart = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
            vault: bearerVault,
            deletionVault: deletionVault
        )
        let response = try await secondRestart.deleteAccount(now: now + 902)
        require(response.deleted && response.idempotent, "account deletion success was not decoded")
        require(storedBearer == nil, "restart recreated the cleared normal bearer")
        require(deletionVault.hasPending(accountBinding: accountBinding), "validated response cleared retry state before the app could scrub its profile")

        // Simulate iOS terminating after a validated response but before AppModel scrub/finalize.
        // A new controller can still replay the completed server receipt with the same transaction.
        transport.append(.init(status: 200, data: success, headers: ["Content-Type": "application/json"]))
        let interruptedReturnController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: transport),
            vault: bearerVault,
            deletionVault: deletionVault
        )
        _ = try await interruptedReturnController.deleteAccount(now: now + 903)
        require(deletionVault.hasPending(accountBinding: accountBinding), "crash-window replay state disappeared before profile scrub")
        failAttemptDelete = true
        do {
            try interruptedReturnController.finalizeConfirmedAccountDeletion(
                accountBindingHash:accountBindingHash
            )
            fatalError("failed checked deletion unexpectedly finalized the transaction")
        } catch {}
        require(deletionVault.hasPending(), "failed checked deletion discarded the restart recovery transaction")
        failAttemptDelete = false
        try interruptedReturnController.finalizeConfirmedAccountDeletion(
            accountBindingHash:accountBindingHash
        )
        require(!deletionVault.hasPending(), "post-scrub finalization retained its transaction credential")
        require(randomCalls == 1, "one logical account deletion generated more than one key")
        require(transport.requests.count == 4, "account deletion retry count drifted")
        for (request, responseBound) in transport.requests {
            require(request.httpMethod == "POST" && request.url?.path == "/api/auth/apple/delete", "account deletion used the wrong route")
            require(request.value(forHTTPHeaderField: "Authorization") == "Bearer \(bearer)", "native deletion omitted its bearer")
            require(request.value(forHTTPHeaderField: "Idempotency-Key") == expectedKey, "uncertain deletion retry changed its idempotency key")
            require(request.value(forHTTPHeaderField: "Cookie") == nil, "native deletion sent a browser cookie")
            require(request.httpBody == nil && request.value(forHTTPHeaderField: "Content-Type") == nil, "native deletion did not send an empty body")
            require(responseBound == NativeServiceLimits.accountDeletionResponseBytes, "account deletion response was not bounded")
        }
        require(attempts.keys.allSatisfy { !$0.contains(accountBinding) }, "account identifier leaked into deletion-attempt storage")

        var storedMode: String?
        let modeVault = NativeAppleAccountModeVault(
            read: { storedMode },
            write: { storedMode = $0 },
            delete: { storedMode = nil }
        )
        try modeVault.save(.linked, accountBinding: accountBinding)
        let relaunchedMode = try modeVault.load(accountBinding: accountBinding)
        require(relaunchedMode == .linked, "linked account mode did not survive a process restart")
        do {
            _ = try modeVault.load(accountBinding: "different-apple-user")
            fatalError("profile-bound account mode crossed Apple identities")
        } catch {}

        var storedOutcome: String?
        let outcomeVault = NativeAccountDeletionOutcomeVault(
            read: { storedOutcome },
            write: { storedOutcome = $0 },
            delete: { storedOutcome = nil }
        )
        let manualOutcome = NativeAccountDeletionOutcome(
            accountBindingHash: accountBindingHash,
            accountMode: .linked,
            manualRevocationRequired: true,
            manualOriginRevocationRequired: true
        )
        try outcomeVault.save(manualOutcome)
        let relaunchedOutcomeVault = NativeAccountDeletionOutcomeVault(
            read: { storedOutcome },
            write: { storedOutcome = $0 },
            delete: { storedOutcome = nil }
        )
        let relaunchedOutcome = try relaunchedOutcomeVault.load()
        require(relaunchedOutcome == manualOutcome, "manual Apple removal guidance did not survive relaunch")

        // Exercise the exact completion coordinator used by AppModel. A process can stop after the
        // result is recorded, or cleanup can fail, without losing either the retry transaction or
        // the manual-removal outcome needed on the next launch.
        var completionScrubs = 0
        var completionFinalizations = 0
        var failCompletionScrub = true
        let relaunchedCompletion = NativeAccountDeletionCompletionRecovery(
            outcomeVault: relaunchedOutcomeVault
        )
        do {
            _ = try relaunchedCompletion.resume(
                scrub: { outcome in
                    require(outcome == manualOutcome, "relaunch loaded the wrong deletion outcome")
                    completionScrubs += 1
                    if failCompletionScrub { throw SandboxError.blocked("INJECTED_SCRUB_FAILURE") }
                },
                finalizeTransaction: { completionFinalizations += 1 }
            )
            fatalError("relaunch ignored a local cleanup failure")
        } catch {}
        require(storedOutcome != nil && completionFinalizations == 0, "failed relaunch cleanup discarded or finalized the transaction")
        failCompletionScrub = false
        let completedOnRelaunch = try relaunchedCompletion.resume(
            scrub: { outcome in
                require(outcome == manualOutcome, "retry loaded the wrong deletion outcome")
                completionScrubs += 1
            },
            finalizeTransaction: { completionFinalizations += 1 }
        )
        require(completedOnRelaunch == manualOutcome, "relaunch did not finish confirmed deletion cleanup")
        require(completionScrubs == 2 && completionFinalizations == 1, "completion recovery did not retry only the unfinished stages")
        require(storedOutcome != nil, "manual-removal guidance disappeared before acknowledgement")
        try relaunchedOutcomeVault.clearChecked()
        require(storedOutcome == nil, "acknowledged deletion guidance remained in Keychain")

        var scrubBearer: String? = String(decoding: try JSONEncoder().encode(bearerSession), as: UTF8.self)
        var scrubMode = storedMode
        var scrubWorkspaceBinding: String?
        var localCredentials = [
            "appleUser": accountBinding,
            "openaiKey": "legacy",
            "openaiModel": "legacy",
            "githubToken": "secret",
        ]
        var failCredentialDelete = true
        var activeRecoveryBinding = accountBinding
        var recoveryItems: [String: String] = [:]
        var recoveryRegistrations: [String: String] = [:]
        var failRecoveryDelete = false
        let recoveryVault = NativeRecoverySecretVault(
            read: { recoveryItems[$0] },
            write: { recoveryItems[$0] = $1 },
            delete: { key in
                if key == String(repeating: "W", count: 32) && failRecoveryDelete {
                    throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
                }
                recoveryItems.removeValue(forKey: key)
            },
            readRegistration: { recoveryRegistrations[$0] },
            writeRegistration: { recoveryRegistrations[$0] = $1 },
            deleteRegistration: { recoveryRegistrations.removeValue(forKey: $0) },
            listRegistrations: { recoveryRegistrations },
            accountBinding: { activeRecoveryBinding }
        )
        let recoverySecret = String(expectedKey.dropFirst(3))
        let deletedWorkspace = String(repeating: "W", count: 32)
        let retainedWorkspace = String(repeating: "Z", count: 32)
        try recoveryVault.save(recoverySecret, workspaceId: deletedWorkspace)
        let stagedRecoverySecret = try recoveryVault.newSecret { Data(repeating: 8, count: $0) }
        try recoveryVault.stageReplacement(stagedRecoverySecret, workspaceId: deletedWorkspace)
        activeRecoveryBinding = "different-apple-user"
        try recoveryVault.save(recoverySecret, workspaceId: retainedWorkspace)
        let scrubWorkspaceVault = NativeLocalWorkspaceBindingVault(
            read: { scrubWorkspaceBinding },
            write: { scrubWorkspaceBinding = $0 },
            delete: { scrubWorkspaceBinding = nil }
        )
        _ = try scrubWorkspaceVault.directoryName(accountBinding: accountBinding)

        let scrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: NativeBearerVault(
                read: { scrubBearer },
                write: { scrubBearer = $0 },
                delete: { scrubBearer = nil }
            ),
            accountModeVault: NativeAppleAccountModeVault(
                read: { scrubMode },
                write: { scrubMode = $0 },
                delete: { scrubMode = nil }
            ),
            workspaceBindingVault: scrubWorkspaceVault,
            recoveryVault: recoveryVault,
            read: { localCredentials[$0] },
            write: { localCredentials[$0] = $1 },
            delete: { key in
                if key == "githubToken" && failCredentialDelete {
                    throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
                }
                localCredentials.removeValue(forKey: key)
            }
        )
        failRecoveryDelete = true
        do {
            try scrubber.scrub(
                accountBindingHash: accountBindingHash,
                includeRecoverySecrets: true
            )
            fatalError("hosted deletion ignored a recovery-key deletion failure")
        } catch {}
        require(recoveryItems[deletedWorkspace] == recoverySecret, "failed recovery-key deletion reported success")
        require(recoveryItems.values.contains(stagedRecoverySecret), "failed recovery-key deletion lost its staged replacement")
        failRecoveryDelete = false
        do {
            try scrubber.scrub(
                accountBindingHash: accountBindingHash,
                includeRecoverySecrets: true
            )
            fatalError("profile scrub ignored a Keychain deletion failure")
        } catch {}
        require(recoveryItems[deletedWorkspace] == nil, "hosted deletion retained its workspace recovery key")
        require(!recoveryItems.values.contains(stagedRecoverySecret), "hosted deletion retained its staged recovery replacement")
        require(recoveryItems[retainedWorkspace] == recoverySecret, "hosted deletion crossed into another profile's workspace key")
        require(localCredentials["githubToken"] == "secret", "failing credential deletion reported success")
        require(
            scrubBearer?.contains(bearerSession.token) == true,
            "a later profile-scrub failure destroyed the captured bearer before retirement"
        )
        failCredentialDelete = false
        try scrubber.scrub()
        require(
            scrubBearer == nil && scrubMode == nil && scrubWorkspaceBinding == nil && localCredentials.isEmpty,
            "verified profile scrub retained credentials or its local workspace binding"
        )

        var identityStore = ["appleUser": "identity-last-user"]
        var identityReadCount = 0
        let identityScrubber = NativeLocalProfileCredentialScrubber(
            bearerVault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}),
            accountModeVault: NativeAppleAccountModeVault(read: { nil }, write: { _ in }, delete: {}),
            workspaceBindingVault: NativeLocalWorkspaceBindingVault(
                read: { nil }, write: { _ in }, delete: {}
            ),
            recoveryVault: recoveryVault,
            read: { key in
                guard key == "appleUser" else { return identityStore[key] }
                identityReadCount += 1
                if identityReadCount == 2 {
                    throw SandboxError.blocked("KEYCHAIN_READ_FAILED")
                }
                return identityStore[key]
            },
            write: { identityStore[$0] = $1 },
            delete: { identityStore.removeValue(forKey: $0) }
        )
        do {
            try identityScrubber.clearIdentity()
            fatalError("identity delete readback failure reported a committed profile scrub")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "KEYCHAIN_READ_FAILED",
                "identity delete readback failure returned the wrong error"
            )
        }
        require(
            identityStore["appleUser"] == "identity-last-user" && identityReadCount == 3,
            "unproven final identity deletion did not restore and verify the exact identity"
        )

        let refreshedBearer = "v1." + String(repeating: "R", count: 43)
        let refreshedExchange = try json([
            "schemaVersion": 1,
            "tokenType": "Bearer",
            "token": refreshedBearer,
            "expiresAt": now + 1_802,
            "accountMode": "linked",
        ])
        var reauthStoredBearer: String? = String(decoding: try JSONEncoder().encode(bearerSession), as: UTF8.self)
        var reauthAttempts: [String: String] = [:]
        let reauthVault = NativeAccountDeletionAttemptVault(
            read: { reauthAttempts[$0] },
            write: { reauthAttempts[$0] = $1 },
            delete: { reauthAttempts.removeValue(forKey: $0) },
            random: { _ in deterministicBytes }
        )
        let reauthTransport = RecordingNativeTransport([
            .init(status: 401, data: try json(["code": "APPLE_NATIVE_SESSION_REQUIRED", "error": "expired"]), headers: ["Content-Type": "application/json"]),
            .init(status: 200, data: refreshedExchange, headers: ["Content-Type": "application/json"]),
            .init(status: 200, data: success, headers: ["Content-Type": "application/json"]),
        ], injectedFailures: [.blocked("NETWORK_OFFLINE_BEFORE_SEND")])
        let reauthController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(
                endpoints: endpoints,
                transport: reauthTransport,
                clock: { now + 902 }
            ),
            vault: NativeBearerVault(
                read: { reauthStoredBearer },
                write: { reauthStoredBearer = $0 },
                delete: { reauthStoredBearer = nil }
            ),
            deletionVault: reauthVault
        )
        do {
            _ = try await reauthController.deleteAccount(accountBinding: accountBinding, now: now)
            fatalError("offline pre-send deletion unexpectedly succeeded")
        } catch {}
        reauthStoredBearer = nil
        do {
            _ = try await reauthController.deleteAccount(now: now + 901)
            fatalError("expired deletion bearer unexpectedly found a receipt")
        } catch let error as NativeServiceError {
            require(error.status == 401 && error.code == "APPLE_NATIVE_SESSION_REQUIRED", "expired deletion retry returned the wrong service error")
        }
        let pendingReauthentication = try reauthController.pendingAccountDeletion(now: now + 901)
        require(pendingReauthentication?.requiresReauthentication == true, "401 deletion retry did not persist reauthentication state")
        let preservedKey = pendingReauthentication?.idempotencyKey
        let refreshedIdentityToken = "new.header." + String(repeating: "p", count: 20)
        do {
            _ = try await reauthController.reauthorizePendingAccountDeletion(
                identityToken: refreshedIdentityToken,
                authorizationCode: "wrong-account-authorization-code",
                rawNonce: String(repeating: "n", count: 43),
                accountBinding: "different-apple-user",
                now: now + 902
            )
            fatalError("deletion retry accepted a different Apple identity")
        } catch {}
        _ = try await reauthController.reauthorizePendingAccountDeletion(
            identityToken: refreshedIdentityToken,
            authorizationCode: "deletion-reauth-authorization-code",
            rawNonce: String(repeating: "n", count: 43),
            accountBinding: accountBinding,
            now: now + 902
        )
        let reauthorizedAttempt = try reauthController.pendingAccountDeletion(now: now + 902)
        require(reauthorizedAttempt?.idempotencyKey == preservedKey, "reauthentication replaced the deletion key")
        _ = try await reauthController.deleteAccount(now: now + 903)
        let deletionRequests = reauthTransport.requests.filter { $0.0.url?.path == "/api/auth/apple/delete" }
        require(deletionRequests.count == 3, "expired retry made an unexpected number of deletion requests")
        require(deletionRequests.allSatisfy { $0.0.value(forHTTPHeaderField: "Idempotency-Key") == expectedKey }, "reauthenticated retry changed its deletion key")

        var strictBearer: String? = String(decoding: try JSONEncoder().encode(bearerSession), as: UTF8.self)
        var strictAttempts: [String: String] = [:]
        let strictVault = NativeAccountDeletionAttemptVault(
            read: { strictAttempts[$0] },
            write: { strictAttempts[$0] = $1 },
            delete: { strictAttempts.removeValue(forKey: $0) },
            random: { _ in deterministicBytes }
        )
        let unexpected = try json([
            "deleted": true,
            "idempotent": false,
            "providerCredentials": [
                "credentialsFound": 0,
                "credentialsRevoked": 0,
                "unreadableSessions": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": true,
            ],
            "originConnections": [
                "installationsFound": 0,
                "installationsRevoked": 0,
                "unreadableInstallations": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": false,
            ],
            "unexpected": true,
        ])
        let strictTransport = RecordingNativeTransport([
            .init(status: 200, data: unexpected, headers: ["Content-Type": "application/json"]),
        ])
        let strictController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: strictTransport),
            vault: NativeBearerVault(
                read: { strictBearer },
                write: { strictBearer = $0 },
                delete: { strictBearer = nil }
            ),
            deletionVault: strictVault
        )
        do {
            _ = try await strictController.deleteAccount(accountBinding: accountBinding, now: now)
            fatalError("account deletion accepted an unknown response field")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "strict deletion response returned the wrong error")
        }
        require(strictBearer != nil && strictVault.hasPending(accountBinding: accountBinding), "invalid deletion response scrubbed retry state")

        strictTransport.append(.init(status: 200, data: try json([
            "deleted": true,
            "idempotent": true,
            "providerCredentials": [
                "credentialsFound": 0,
                "credentialsRevoked": 0,
                "unreadableSessions": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": false,
            ],
            "originConnections": [
                "installationsFound": 0,
                "installationsRevoked": 0,
                "unreadableInstallations": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": false,
            ],
        ]), headers: ["Content-Type": "application/json"]))
        do {
            _ = try await strictController.deleteAccount(accountBinding: accountBinding, now: now + 1)
            fatalError("account deletion accepted an inconsistent manual-removal flag")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "inconsistent revocation summary returned the wrong error")
        }
        require(strictVault.hasPending(accountBinding: accountBinding), "inconsistent response discarded its retry transaction")

        strictTransport.append(.init(status: 200, data: try json([
            "deleted": true,
            "idempotent": true,
            "providerCredentials": [
                "credentialsFound": 0,
                "credentialsRevoked": 0,
                "unreadableSessions": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": true,
            ],
            "originConnections": [
                "installationsFound": 1,
                "installationsRevoked": 1,
                "unreadableInstallations": 0,
                "failedRevocations": 0,
                "manualRevocationRequired": true,
            ],
        ]), headers: ["Content-Type": "application/json"]))
        do {
            _ = try await strictController.deleteAccount(accountBinding: accountBinding, now: now + 2)
            fatalError("account deletion accepted an inconsistent Origin removal flag")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "inconsistent Origin summary returned the wrong error")
        }
        require(strictVault.hasPending(accountBinding: accountBinding), "inconsistent Origin response discarded its retry transaction")

        var persistenceBearer: String? = String(decoding: try JSONEncoder().encode(bearerSession), as: UTF8.self)
        let persistenceTransport = RecordingNativeTransport([])
        let persistenceController = NativeAppleAuthController(
            api: NativeAppleAuthAPI(endpoints: endpoints, transport: persistenceTransport),
            vault: NativeBearerVault(
                read: { persistenceBearer },
                write: { persistenceBearer = $0 },
                delete: { persistenceBearer = nil }
            ),
            deletionVault: NativeAccountDeletionAttemptVault(
                read: { _ in nil },
                write: { _, _ in throw SandboxError.blocked("KEYCHAIN_WRITE_FAILED") },
                delete: { _ in },
                random: { _ in deterministicBytes }
            )
        )
        do {
            _ = try await persistenceController.deleteAccount(accountBinding: "unwritable-attempt", now: now)
            fatalError("account deletion sent a request without durable retry state")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_WRITE_FAILED", "attempt persistence failure returned the wrong error")
        }
        require(persistenceTransport.requests.isEmpty, "account deletion fetched before its retry transaction was durable")
        require(persistenceBearer != nil, "attempt persistence failure scrubbed the bearer")
    }

    fileprivate static func transferFixtures(_ store: TransferMigrationStore) -> (
        mode: NativeAppleAccountModeVault,
        workspace: NativeLocalWorkspaceBindingVault,
        recovery: NativeRecoverySecretVault,
        block: NativeAppleTransferBlockVault,
        migration: NativeAppleTransferMigrationVault,
        coordinator: NativeAppleTransferMigrationCoordinator
    ) {
        let mode = NativeAppleAccountModeVault(
            read: { try store.checkedRead("mode", value: store.accountMode) },
            write: { value in
                if store.shouldFail("mode") { throw SandboxError.blocked("INJECTED_MODE_FAILURE") }
                store.accountMode = value
            },
            delete: { store.accountMode = nil }
        )
        let workspace = NativeLocalWorkspaceBindingVault(
            read: { try store.checkedRead("workspace", value: store.workspaceBinding) },
            write: { value in
                if store.shouldFail("workspace") { throw SandboxError.blocked("INJECTED_WORKSPACE_FAILURE") }
                store.workspaceBinding = value
            },
            delete: { store.workspaceBinding = nil }
        )
        let recovery = NativeRecoverySecretVault(
            read: { store.recovery[$0] },
            write: { store.recovery[$0] = $1 },
            delete: { store.recovery.removeValue(forKey: $0) },
            readRegistration: { store.recoveryRegistrations[$0] },
            writeRegistration: { key, value in
                if store.shouldFail("recovery") {
                    throw SandboxError.blocked("INJECTED_RECOVERY_FAILURE")
                }
                store.recoveryRegistrations[key] = value
            },
            deleteRegistration: { store.recoveryRegistrations.removeValue(forKey: $0) },
            listRegistrations: { store.recoveryRegistrations },
            accountBinding: { store.user }
        )
        let block = NativeAppleTransferBlockVault(
            read: { try store.checkedRead("block", value: store.transferBlock) },
            write: { store.transferBlock = $0 },
            delete: {
                if store.shouldFail("blockDelete") { throw SandboxError.blocked("INJECTED_BLOCK_FAILURE") }
                store.transferBlock = nil
            }
        )
        let migration = NativeAppleTransferMigrationVault(
            read: { try store.checkedRead("migration", value: store.migration) },
            write: {
                if store.shouldFail("migrationWrite") { throw SandboxError.blocked("INJECTED_MIGRATION_WRITE_FAILURE") }
                store.migration = $0
            },
            delete: {
                if store.shouldFail("migrationDelete") { throw SandboxError.blocked("INJECTED_MIGRATION_FAILURE") }
                store.migration = nil
            }
        )
        let coordinator = NativeAppleTransferMigrationCoordinator(
            accountModeVault: mode,
            workspaceBindingVault: workspace,
            recoveryVault: recovery,
            migrationVault: migration,
            transferBlockVault: block,
            readUser: { try store.checkedRead("user", value: store.user) },
            writeUser: { value in
                if store.alwaysFailUserWrite || store.shouldFail("user") {
                    throw SandboxError.blocked("INJECTED_USER_FAILURE")
                }
                store.user = value
            }
        )
        return (mode, workspace, recovery, block, migration, coordinator)
    }

    static func seedTransfer(
        fixtures: (
            mode: NativeAppleAccountModeVault,
            workspace: NativeLocalWorkspaceBindingVault,
            recovery: NativeRecoverySecretVault,
            block: NativeAppleTransferBlockVault,
            migration: NativeAppleTransferMigrationVault,
            coordinator: NativeAppleTransferMigrationCoordinator
        ),
        oldUser: String,
        workspaceId: String
    ) throws {
        try fixtures.mode.save(.linked, accountBinding: oldUser)
        _ = try fixtures.workspace.directoryName(accountBinding: oldUser)
        try fixtures.recovery.save(String(repeating: "A", count: 43), workspaceId: workspaceId)
        try fixtures.block.block(oldUser: oldUser)
    }

    static func transferMigrationContract() throws {
        let oldUser = "old-verified-apple-user"
        let newUser = "new-verified-apple-user"
        let workspaceId = String(repeating: "M", count: 32)

        let successStore = TransferMigrationStore(user: oldUser)
        let success = transferFixtures(successStore)
        try seedTransfer(fixtures: success, oldUser: oldUser, workspaceId: workspaceId)
        try success.coordinator.migrateVerifiedTransfer(
            from: oldUser,
            to: newUser,
            verifiedAccountMode: .linked
        )
        require(successStore.user == newUser, "verified transfer did not migrate appleUser")
        let successMode = try success.mode.load(accountBinding: newUser)
        let successWorkspaces = try success.recovery.registeredWorkspaceIds()
        require(successMode == .linked, "verified transfer lost account mode")
        require(successWorkspaces == [workspaceId], "verified transfer lost recovery scope")
        require(successStore.recovery[workspaceId] == String(repeating: "A", count: 43), "verified transfer changed the recovery secret")
        let successDirectory = try success.workspace.directoryName(accountBinding: newUser)
        require(successDirectory == NativeDigest.sha256(oldUser), "verified transfer changed the local workspace directory identity")
        do {
            _ = try success.workspace.directoryName(accountBinding: oldUser)
            fatalError("verified transfer left the local workspace binding on the old user")
        } catch {}
        require(successStore.transferBlock == nil && successStore.migration == nil, "verified transfer retained a completed block or journal")

        let deviceBStore = TransferMigrationStore(user: oldUser)
        let deviceB = transferFixtures(deviceBStore)
        try deviceB.mode.save(.linked, accountBinding: oldUser)
        _ = try deviceB.workspace.directoryName(accountBinding: oldUser)
        try deviceB.block.block(oldUser: oldUser)
        deviceBStore.user = newUser
        try deviceB.recovery.save(
            String(repeating: "B", count: 42) + "A",
            workspaceId: workspaceId
        )
        deviceBStore.user = oldUser
        try deviceB.coordinator.migrateVerifiedTransfer(
            from: oldUser,
            to: newUser,
            verifiedAccountMode: .linked
        )
        let deviceBWorkspaces = try deviceB.recovery.registeredWorkspaceIds()
        require(deviceBStore.user == newUser, "device-B transfer did not accept an already converged recovery registry")
        require(deviceBWorkspaces == [workspaceId], "device-B transfer lost the recovery registry migrated by device A")
        require(deviceBStore.transferBlock == nil && deviceBStore.migration == nil, "device-B convergence retained blocking state")

        let deviceBRollbackStore = TransferMigrationStore(user: oldUser)
        let deviceBRollback = transferFixtures(deviceBRollbackStore)
        try deviceBRollback.mode.save(.linked, accountBinding: oldUser)
        _ = try deviceBRollback.workspace.directoryName(accountBinding: oldUser)
        try deviceBRollback.block.block(oldUser: oldUser)
        deviceBRollbackStore.user = newUser
        try deviceBRollback.recovery.save(
            String(repeating: "C", count: 42) + "A",
            workspaceId: workspaceId
        )
        deviceBRollbackStore.user = oldUser
        deviceBRollbackStore.failOnce = "mode"
        do {
            try deviceBRollback.coordinator.migrateVerifiedTransfer(
                from: oldUser,
                to: newUser,
                verifiedAccountMode: .linked
            )
            fatalError("device-B transfer ignored an injected post-recovery failure")
        } catch {}
        let deviceBRollbackBlock = try deviceBRollback.block.load()
        require(deviceBRollbackStore.user == oldUser, "device-B rollback left a mixed Apple user")
        require(deviceBRollbackBlock == oldUser, "device-B rollback removed hosted blocking")
        require(deviceBRollbackStore.migration == nil, "device-B rollback retained a completed journal")
        deviceBRollbackStore.user = newUser
        let deviceBRollbackNewWorkspaces = try deviceBRollback.recovery.registeredWorkspaceIds()
        deviceBRollbackStore.user = oldUser
        let deviceBRollbackOldWorkspaces = try deviceBRollback.recovery.registeredWorkspaceIds()
        require(
            deviceBRollbackNewWorkspaces == [workspaceId] && deviceBRollbackOldWorkspaces.isEmpty,
            "device-B rollback reversed recovery metadata already converged through iCloud"
        )
        try deviceBRollback.coordinator.migrateVerifiedTransfer(
            from: oldUser,
            to: newUser,
            verifiedAccountMode: .linked
        )
        require(
            deviceBRollbackStore.user == newUser
                && deviceBRollbackStore.transferBlock == nil
                && deviceBRollbackStore.migration == nil,
            "device-B retry did not converge after preserving its recovery metadata"
        )

        for boundary in ["migrationWrite", "recovery", "workspace", "mode", "user", "blockDelete", "migrationDelete"] {
            let store = TransferMigrationStore(user: oldUser)
            let fixtures = transferFixtures(store)
            try seedTransfer(fixtures: fixtures, oldUser: oldUser, workspaceId: workspaceId)
            store.failOnce = boundary
            do {
                try fixtures.coordinator.migrateVerifiedTransfer(
                    from: oldUser,
                    to: newUser,
                    verifiedAccountMode: .linked
                )
                fatalError("verified transfer ignored injected \(boundary) failure")
            } catch {}
            let rolledBackMode = try fixtures.mode.load(accountBinding: oldUser)
            let rolledBackWorkspaces = try fixtures.recovery.registeredWorkspaceIds()
            let rolledBackBlock = try fixtures.block.load()
            let rolledBackDirectory = try fixtures.workspace.directoryName(accountBinding: oldUser)
            require(store.user == oldUser, "\(boundary) failure left a mixed Apple user")
            require(rolledBackMode == .linked, "\(boundary) failure lost old account mode")
            require(rolledBackWorkspaces == [workspaceId], "\(boundary) failure lost old recovery scope")
            require(rolledBackDirectory == NativeDigest.sha256(oldUser), "\(boundary) failure changed the local workspace directory identity")
            require(rolledBackBlock == oldUser, "\(boundary) failure removed the durable hosted-access block")
            require(store.migration == nil, "\(boundary) rollback retained its completed migration journal")
        }

        let staleStore = TransferMigrationStore(user: oldUser)
        let stale = transferFixtures(staleStore)
        try seedTransfer(fixtures: stale, oldUser: oldUser, workspaceId: workspaceId)
        staleStore.user = newUser
        try stale.recovery.save(String(repeating: "B", count: 42) + "A", workspaceId: String(repeating: "N", count: 32))
        staleStore.user = oldUser
        do {
            try stale.coordinator.migrateVerifiedTransfer(
                from: oldUser,
                to: newUser,
                verifiedAccountMode: .linked
            )
            fatalError("verified transfer inherited stale new-user recovery metadata")
        } catch {}
        let staleBlock = try stale.block.load()
        require(staleStore.user == oldUser, "stale metadata conflict changed the old Apple user")
        require(staleBlock == oldUser, "stale metadata conflict weakened transfer blocking")

        let staleWorkspaceStore = TransferMigrationStore(user: oldUser)
        let staleWorkspace = transferFixtures(staleWorkspaceStore)
        try staleWorkspace.mode.save(.linked, accountBinding: oldUser)
        try staleWorkspace.block.block(oldUser: oldUser)
        _ = try staleWorkspace.workspace.directoryName(accountBinding: newUser)
        do {
            try staleWorkspace.coordinator.migrateVerifiedTransfer(
                from: oldUser,
                to: newUser,
                verifiedAccountMode: .linked
            )
            fatalError("verified transfer inherited a stale destination local workspace binding")
        } catch {}
        let staleWorkspaceBlock = try staleWorkspace.block.load()
        require(staleWorkspaceStore.user == oldUser, "stale local workspace metadata changed the old Apple user")
        require(staleWorkspaceBlock == oldUser, "stale local workspace metadata weakened transfer blocking")

        let restartStore = TransferMigrationStore(user: oldUser)
        let restart = transferFixtures(restartStore)
        try seedTransfer(fixtures: restart, oldUser: oldUser, workspaceId: workspaceId)
        restartStore.alwaysFailUserWrite = true
        do {
            try restart.coordinator.migrateVerifiedTransfer(
                from: oldUser,
                to: newUser,
                verifiedAccountMode: .linked
            )
            fatalError("unrecoverable migration failure reported success")
        } catch let error as SandboxError {
            require(error.localizedDescription == "APPLE_TRANSFER_LOCAL_MIGRATION_RECOVERY_REQUIRED", "restart recovery failure was ambiguous")
        }
        let restartBlock = try restart.block.load()
        require(restartStore.migration != nil, "failed migration lost its restart journal")
        require(restartBlock == oldUser, "failed migration lost its durable block")
        restartStore.alwaysFailUserWrite = false
        let resumed = try restart.coordinator.resumePendingMigration()
        let restartMode = try restart.mode.load(accountBinding: newUser)
        let restartWorkspaces = try restart.recovery.registeredWorkspaceIds()
        let restartDirectory = try restart.workspace.directoryName(accountBinding: newUser)
        require(resumed, "restart did not resume verified transfer")
        require(restartStore.user == newUser, "restart recovery did not finish appleUser migration")
        require(restartMode == .linked, "restart recovery lost account mode")
        require(restartWorkspaces == [workspaceId], "restart recovery lost recovery scope")
        require(restartDirectory == NativeDigest.sha256(oldUser), "restart recovery changed the local workspace directory identity")
        require(restartStore.transferBlock == nil && restartStore.migration == nil, "restart recovery retained hosted blocking state")

        let deviceBRestartStore = TransferMigrationStore(user: oldUser)
        let deviceBRestart = transferFixtures(deviceBRestartStore)
        try deviceBRestart.mode.save(.linked, accountBinding: oldUser)
        _ = try deviceBRestart.workspace.directoryName(accountBinding: oldUser)
        try deviceBRestart.block.block(oldUser: oldUser)
        deviceBRestartStore.user = newUser
        try deviceBRestart.recovery.save(
            String(repeating: "D", count: 42) + "A",
            workspaceId: workspaceId
        )
        deviceBRestartStore.user = oldUser
        deviceBRestartStore.alwaysFailUserWrite = true
        do {
            try deviceBRestart.coordinator.migrateVerifiedTransfer(
                from: oldUser,
                to: newUser,
                verifiedAccountMode: .linked
            )
            fatalError("device-B restart fixture unexpectedly completed")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "APPLE_TRANSFER_LOCAL_MIGRATION_RECOVERY_REQUIRED",
                "device-B restart failure was ambiguous"
            )
        }
        let deviceBRestartBlock = try deviceBRestart.block.load()
        require(
            deviceBRestartStore.user == oldUser
                && deviceBRestartBlock == oldUser
                && deviceBRestartStore.migration != nil,
            "device-B restart failure lost its old-user block or recovery journal"
        )
        deviceBRestartStore.alwaysFailUserWrite = false
        let deviceBRestartResumed = try deviceBRestart.coordinator.resumePendingMigration()
        require(deviceBRestartResumed, "device-B restart did not resume")
        let deviceBRestartWorkspaces = try deviceBRestart.recovery.registeredWorkspaceIds()
        require(
            deviceBRestartStore.user == newUser
                && deviceBRestartWorkspaces == [workspaceId]
                && deviceBRestartStore.transferBlock == nil
                && deviceBRestartStore.migration == nil,
            "device-B restart recovery did not converge without stale old-principal metadata"
        )
    }

    static func syncTransportContract() async throws {
        let workspaceId = String(repeating: "W", count: 32)
        let epoch = String(repeating: "E", count: 24)
        let listBody = try json(["workspaces": [["workspaceId": workspaceId, "epoch": epoch, "updatedAt": "2026-09-10T00:00:00Z"]]])
        let transport = RecordingNativeTransport([.init(status: 200, data: listBody, headers: ["Cache-Control": "no-store"])])
        let endpoints = try NativeServiceEndpoints(origin: URL(string: "https://sandbox.example.test")!)
        let api = NativeWorkspaceSyncAPI(endpoints: endpoints, transport: transport)
        let workspaces = try await api.list(bearer: bearer)
        require(workspaces.map(\.workspaceId) == [workspaceId], "workspace list did not decode")
        require(transport.requests.count == 1, "one manual list action triggered more than one request")
        let request = transport.requests[0]
        require(request.0.httpMethod == "GET" && request.0.url?.path == "/api/sync", "workspace list used the wrong route")
        require(request.0.value(forHTTPHeaderField: "Authorization") == "Bearer \(bearer)", "sync did not use the native bearer")
        require(request.0.value(forHTTPHeaderField: "Cookie") == nil, "sync sent a browser cookie")
        require(request.1 == NativeServiceLimits.syncResponseBytes, "sync response was not explicitly bounded")

        let created = try WorkspaceCrypto.create(passphrase: "native sync request passphrase", createdAt: "2026-09-10T00:00:00Z")
        let envelope = try WorkspaceCrypto.seal(
            session: created.0,
            path: "workspace/new.txt",
            content: "new",
            baseRevision: nil,
            generation: 0,
            writerDevice: "device_0123456789abcdef",
            writtenAt: "2026-09-10T00:00:00Z"
        )
        let storedRecord = NativeStoredEncryptedRecord(revision: 0, envelope: envelope)
        require(envelope.version == 2, "native sync emitted a legacy encrypted workspace payload")
        let storedObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(storedRecord))
        transport.append(.init(status: 200, data: try json(["record": storedObject, "idempotent": false]), headers: ["Cache-Control": "no-store"]))
        _ = try await api.write(workspaceId: created.0.workspaceId, expectedRevision: nil, envelope: envelope, bearer: bearer)
        let writeBody = try JSONSerialization.jsonObject(with: transport.requests[1].0.httpBody!) as! [String: Any]
        require(writeBody.keys.contains("expectedRevision") && writeBody["expectedRevision"] is NSNull, "new sync write omitted the required null expected revision")
        let encodedEnvelope = writeBody["envelope"] as! [String: Any]
        require(encodedEnvelope.keys.contains("baseRevision") && encodedEnvelope["baseRevision"] is NSNull, "new encrypted record omitted the required null CAS base")

        var pageRecords: [NativeStoredEncryptedRecord] = []
        for index in 0..<5 {
            let item = try WorkspaceCrypto.seal(
                session: created.0,
                path: "workspace/page-\(index).txt",
                content: "page \(index)",
                baseRevision: 0,
                generation: index,
                writerDevice: "device_0123456789abcdef",
                writtenAt: "2026-09-10T00:00:00Z"
            )
            pageRecords.append(.init(revision: index + 1, envelope: item))
        }
        pageRecords.sort { $0.envelope.recordId < $1.envelope.recordId }
        let recoveryObject = try jsonObject(created.1)
        let firstPageObjects = try pageRecords.prefix(4).map(jsonObject)
        let lastPageObjects = try pageRecords.suffix(1).map(jsonObject)
        transport.append(.init(status: 200, data: try json([
            "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
            "snapshotRevision": 9, "records": firstPageObjects, "nextCursor": pageRecords[3].envelope.recordId,
        ]), headers: ["Cache-Control": "no-store"]))
        transport.append(.init(status: 200, data: try json([
            "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
            "snapshotRevision": 9, "records": lastPageObjects, "nextCursor": NSNull(),
        ]), headers: ["Cache-Control": "no-store"]))
        let snapshot = try await api.readWorkspace(workspaceId: created.0.workspaceId, bearer: bearer)
        require(snapshot.snapshotRevision == 9 && snapshot.records.count == 5, "paginated workspace did not aggregate one stable snapshot")
        require(transport.requests[2].1 == 512 * 1_024 && transport.requests[3].1 == 512 * 1_024, "workspace pages did not use the 512 KiB cap")
        let firstQuery = URLComponents(url: transport.requests[2].0.url!, resolvingAgainstBaseURL: false)!.queryItems!
        require(firstQuery.map(\.name) == ["workspaceId"], "initial page sent pagination state")
        let secondQuery = Dictionary(uniqueKeysWithValues: URLComponents(url: transport.requests[3].0.url!, resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value!) })
        require(secondQuery["cursor"] == pageRecords[3].envelope.recordId && secondQuery["snapshotRevision"] == "9", "follow-up page was not snapshot-bound")

        let restartTransport = RecordingNativeTransport([
            .init(status: 200, data: try json([
                "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
                "snapshotRevision": 9, "records": firstPageObjects, "nextCursor": pageRecords[3].envelope.recordId,
            ]), headers: [:]),
            .init(status: 409, data: try json(["code": "SYNC_SNAPSHOT_CHANGED", "error": "changed"]), headers: [:]),
            .init(status: 200, data: try json([
                "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
                "snapshotRevision": 10, "records": lastPageObjects, "nextCursor": NSNull(),
            ]), headers: [:]),
        ])
        let restartAPI = NativeWorkspaceSyncAPI(endpoints: endpoints, transport: restartTransport)
        let restarted = try await restartAPI.readWorkspace(workspaceId: created.0.workspaceId, bearer: bearer)
        require(restarted.snapshotRevision == 10 && restarted.records.count == 1, "snapshot change did not restart exactly from page one")
        let restartedQuery = URLComponents(url: restartTransport.requests[2].0.url!, resolvingAgainstBaseURL: false)!.queryItems!
        require(restartedQuery.map(\.name) == ["workspaceId"], "snapshot retry resumed from a stale cursor")

        let repeatedChange = RecordingNativeTransport([
            .init(status: 200, data: try json([
                "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
                "snapshotRevision": 9, "records": firstPageObjects, "nextCursor": pageRecords[3].envelope.recordId,
            ]), headers: [:]),
            .init(status: 409, data: try json(["code": "SYNC_SNAPSHOT_CHANGED", "error": "changed"]), headers: [:]),
            .init(status: 200, data: try json([
                "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
                "snapshotRevision": 10, "records": firstPageObjects, "nextCursor": pageRecords[3].envelope.recordId,
            ]), headers: [:]),
            .init(status: 409, data: try json(["code": "SYNC_SNAPSHOT_CHANGED", "error": "changed again"]), headers: [:]),
        ])
        do {
            _ = try await NativeWorkspaceSyncAPI(endpoints: endpoints, transport: repeatedChange).readWorkspace(workspaceId: created.0.workspaceId, bearer: bearer)
            fatalError("workspace snapshot restarted more than once")
        } catch let error as NativeServiceError {
            require(error.code == "SYNC_SNAPSHOT_CHANGED" && repeatedChange.requests.count == 4, "second snapshot mutation was not surfaced")
        }

        let missingCursorField = RecordingNativeTransport([
            .init(status: 200, data: try json([
                "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
                "snapshotRevision": 9, "records": [],
            ]), headers: [:]),
        ])
        do {
            _ = try await NativeWorkspaceSyncAPI(endpoints: endpoints, transport: missingCursorField).readWorkspace(workspaceId: created.0.workspaceId, bearer: bearer)
            fatalError("workspace page accepted an omitted nextCursor")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SERVICE_RESPONSE_INVALID", "missing nextCursor returned the wrong error")
        }

        let unsafeRevision = RecordingNativeTransport([
            .init(status: 200, data: try json([
                "workspaceId": created.0.workspaceId, "epoch": created.0.epoch, "recovery": recoveryObject,
                "snapshotRevision": 9_007_199_254_740_992, "records": [], "nextCursor": NSNull(),
            ]), headers: [:]),
        ])
        do {
            _ = try await NativeWorkspaceSyncAPI(endpoints: endpoints, transport: unsafeRevision).readWorkspace(workspaceId: created.0.workspaceId, bearer: bearer)
            fatalError("workspace page accepted a revision outside the JavaScript safe integer range")
        } catch let error as SandboxError {
            require(error.localizedDescription == "SYNC_WORKSPACE_PAGE_INVALID", "unsafe snapshot revision returned the wrong error")
        }

        for (version, maximum, marker) in [(1, WorkspaceCrypto.legacyMaximumCiphertextCharacters, "L"), (2, WorkspaceCrypto.maximumCiphertextCharacters, "V")] {
            let boundary = EncryptedWorkspaceRecord(
                format: WorkspaceCrypto.recordFormat,
                version: version,
                workspaceId: created.0.workspaceId,
                epoch: created.0.epoch,
                recordId: String(repeating: marker, count: 43),
                baseRevision: nil,
                mutationId: "boundary-mutation-\(marker)-0000",
                iv: String(repeating: "I", count: 16),
                data: String(repeating: marker, count: maximum)
            )
            let storedBoundary = NativeStoredEncryptedRecord(revision: 0, envelope: boundary)
            transport.append(.init(status: 200, data: try json(["record": try jsonObject(storedBoundary), "idempotent": false]), headers: [:]))
            _ = try await api.write(workspaceId: created.0.workspaceId, expectedRevision: nil, envelope: boundary, bearer: bearer)
            require((transport.requests.last?.0.httpBody?.count ?? NativeServiceLimits.syncRequestBytes + 1) <= NativeServiceLimits.syncRequestBytes, "maximum encrypted record exceeded the bounded sync request")
            let oversized = EncryptedWorkspaceRecord(format: boundary.format, version: version, workspaceId: boundary.workspaceId, epoch: boundary.epoch, recordId: boundary.recordId, baseRevision: nil, mutationId: boundary.mutationId, iv: boundary.iv, data: boundary.data + marker)
            do {
                _ = try await api.write(workspaceId: created.0.workspaceId, expectedRevision: nil, envelope: oversized, bearer: bearer)
                fatalError("native sync accepted oversized v\(version) ciphertext")
            } catch let error as SandboxError {
                require(error.localizedDescription == "SYNC_WRITE_METADATA_MISMATCH", "oversized v\(version) ciphertext returned the wrong error")
            }
        }

        let rotatedRecovery = try WorkspaceCrypto.rewrapRecovery(
            created.1,
            currentPassphrase: "native sync request passphrase",
            replacementPassphrase: "replacement native recovery phrase",
            createdAt: "2026-09-11T00:00:00Z"
        ).1
        transport.append(.init(status: 200, data: try json([
            "workspaceId": created.0.workspaceId,
            "epoch": created.0.epoch,
            "recovery": try jsonObject(rotatedRecovery),
            "snapshotRevision": 10,
            "idempotent": false,
        ]), headers: ["Cache-Control": "no-store"]))
        let rotatedRevision = try await api.replaceRecovery(
            workspaceId: created.0.workspaceId,
            expectedEpoch: created.0.epoch,
            expectedRevision: 9,
            recovery: rotatedRecovery,
            bearer: bearer
        )
        require(rotatedRevision == 10, "native recovery rotation did not validate the advanced snapshot revision")
        let rotationBody = try JSONSerialization.jsonObject(with: transport.requests.last!.0.httpBody!) as! [String: Any]
        require(rotationBody["kind"] as? String == "replaceRecovery" && rotationBody["expectedRevision"] as? Int == 9, "native recovery rotation omitted its CAS metadata")

        transport.append(.init(status: 200, data: try json([
            "workspaceId": created.0.workspaceId,
            "deleted": true,
            "idempotent": false,
        ]), headers: ["Cache-Control": "no-store"]))
        try await api.deleteWorkspace(
            workspaceId: created.0.workspaceId,
            expectedEpoch: created.0.epoch,
            expectedRevision: 10,
            bearer: bearer
        )
        let deletionBody = try JSONSerialization.jsonObject(with: transport.requests.last!.0.httpBody!) as! [String: Any]
        require(deletionBody["kind"] as? String == "deleteWorkspace" && deletionBody["expectedRevision"] as? Int == 10, "native workspace deletion omitted its CAS metadata")

        let tooLarge = Data(repeating: 0, count: NativeServiceLimits.syncRequestBytes + 1)
        do {
            _ = try NativeRequestFactory.sync(endpoints: endpoints, method: "POST", body: tooLarge, bearer: bearer)
            fatalError("oversized sync request was accepted")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SERVICE_REQUEST_TOO_LARGE", "oversized sync request returned the wrong error")
        }
        do {
            _ = try NativeRequestFactory.sync(endpoints: endpoints, method: "GET", body: Data(), bearer: bearer)
            fatalError("sync GET accepted a request body")
        } catch let error as SandboxError {
            require(error.localizedDescription == "NATIVE_SYNC_METHOD_INVALID", "invalid sync method/body returned the wrong error")
        }
    }

    static func recoveryContract() throws {
        let workspaceId = String(repeating: "R", count: 32)
        var synchronized: [String: String] = [:]
        var registrations: [String: String] = [:]
        let vault = NativeRecoverySecretVault(
            read: { synchronized[$0] },
            write: { synchronized[$0] = $1 },
            delete: { synchronized.removeValue(forKey: $0) },
            readRegistration: { registrations[$0] },
            writeRegistration: { registrations[$0] = $1 },
            deleteRegistration: { registrations.removeValue(forKey: $0) },
            listRegistrations: { registrations },
            accountBinding: { "native-recovery-test-user" }
        )
        let secret = try vault.newSecret { count in
            require(count == 32, "recovery secret did not request 256 bits")
            return Data(repeating: 7, count: count)
        }
        require(secret.count == 43, "recovery secret was not a 256-bit base64url value")
        do {
            _ = try vault.newSecret { _ in Data(repeating: 7, count: 33) }
            fatalError("recovery accepted the wrong random byte count")
        } catch let error as SandboxError {
            require(error.localizedDescription == "SECURE_RANDOM_LENGTH_INVALID", "recovery random length failure was ambiguous")
        }
        try vault.save(secret, workspaceId: workspaceId)
        let registeredWorkspaceIds = try vault.registeredWorkspaceIds()
        require(registeredWorkspaceIds == [workspaceId], "recovery registry did not expose the current account's enrolled workspace")
        let recovered = try vault.recoverySecret(workspaceId: workspaceId)
        require(recovered == secret, "synchronized recovery secret did not re-enroll a device")
        let replacement = try vault.newSecret { Data(repeating: 8, count: $0) }
        try vault.stageReplacement(replacement, workspaceId: workspaceId)
        let stagedCandidates = try vault.recoveryCandidates(workspaceId: workspaceId)
        require(stagedCandidates == [
            NativeRecoverySecretCandidate(secret: replacement, staged: true),
            NativeRecoverySecretCandidate(secret: secret, staged: false),
        ], "pending recovery rotation did not retain both crash-recovery candidates")
        try vault.commitStagedReplacement(workspaceId: workspaceId)
        let committedSecret = try vault.recoverySecret(workspaceId: workspaceId)
        let committedCandidates = try vault.recoveryCandidates(workspaceId: workspaceId)
        require(committedSecret == replacement, "committed recovery rotation did not replace the synchronized secret")
        require(committedCandidates == [NativeRecoverySecretCandidate(secret: replacement, staged: false)], "committed recovery rotation retained stale pending material")
        let abandoned = try vault.newSecret { Data(repeating: 9, count: $0) }
        try vault.stageReplacement(abandoned, workspaceId: workspaceId)
        try vault.discardStagedReplacement(workspaceId: workspaceId)
        let candidatesAfterDiscard = try vault.recoveryCandidates(workspaceId: workspaceId)
        require(candidatesAfterDiscard == [NativeRecoverySecretCandidate(secret: replacement, staged: false)], "discarded recovery rotation removed the committed secret")
        try vault.remove(workspaceId: workspaceId)
        let registeredWorkspaceIdsAfterRemoval = try vault.registeredWorkspaceIds()
        require(registeredWorkspaceIdsAfterRemoval.isEmpty, "recovery removal retained an obsolete registry entry")
        do {
            _ = try vault.recoverySecret(workspaceId: workspaceId)
            fatalError("missing recovery key silently regenerated")
        } catch let error as SandboxError {
            require(error.localizedDescription == "ICLOUD_RECOVERY_SECRET_UNAVAILABLE", "lost-key behavior was ambiguous")
        }
        let created = try WorkspaceCrypto.create(passphrase: secret, createdAt: "2026-09-10T00:00:00Z")
        let restored = try WorkspaceCrypto.restore(created.1, passphrase: secret)
        require(restored.workspaceId == created.0.workspaceId, "exported Apple recovery secret did not unlock the interoperable envelope")

        var recoveryWriteObserved = false
        var recoveryRegistrationItems: [String: String] = [:]
        let saveReadFailureVault = NativeRecoverySecretVault(
            read: { _ in throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            write: { _, _ in recoveryWriteObserved = true },
            delete: { _ in },
            readLegacyRegistry: { nil },
            readRegistration: { recoveryRegistrationItems[$0] },
            writeRegistration: { recoveryRegistrationItems[$0] = $1 },
            deleteRegistration: { recoveryRegistrationItems.removeValue(forKey: $0) },
            listRegistrations: { recoveryRegistrationItems },
            accountBinding: { "native-recovery-read-failure-user" }
        )
        do {
            try saveReadFailureVault.save(secret, workspaceId: workspaceId)
            fatalError("recovery persistence treated a verification read failure as success")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "recovery persistence verification returned the wrong read failure")
        }
        require(recoveryWriteObserved, "recovery read-failure fixture did not reach persistence verification")

        var removedKeys: [String] = []
        var registrationDeletionObserved = false
        let removalReadFailureVault = NativeRecoverySecretVault(
            read: { _ in throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            write: { _, _ in },
            delete: { removedKeys.append($0) },
            readLegacyRegistry: { nil },
            readRegistration: { _ in nil },
            writeRegistration: { _, _ in },
            deleteRegistration: { _ in registrationDeletionObserved = true },
            listRegistrations: { [:] },
            accountBinding: { "native-recovery-read-failure-user" }
        )
        do {
            try removalReadFailureVault.remove(workspaceId: workspaceId)
            fatalError("recovery deletion treated a verification read failure as confirmed absence")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "recovery deletion verification returned the wrong read failure")
        }
        require(
            removedKeys == [workspaceId, "pending.\(workspaceId)"],
            "recovery deletion verification did not follow both secret deletion attempts"
        )
        require(!registrationDeletionObserved, "recovery deletion removed its registration before secret absence was verified")
    }

    static func recoveryRegistryMigrationContract() throws {
        let accountBinding = "legacy-recovery-account"
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        let firstWorkspace = String(repeating: "L", count: 32)
        let secondWorkspace = String(repeating: "Q", count: 32)
        let legacyData = try json([
            "schemaVersion": 1,
            "entries": [
                ["workspaceId": firstWorkspace, "accountBindingHash": accountBindingHash],
                ["workspaceId": secondWorkspace, "accountBindingHash": accountBindingHash],
            ],
        ])
        var secretItems = ["registry": String(decoding: legacyData, as: UTF8.self)]
        var registrationItems: [String: String] = [:]
        var failingWorkspace: String? = secondWorkspace
        var failLegacyDelete = false
        let vault = NativeRecoverySecretVault(
            read: { secretItems[$0] },
            write: { secretItems[$0] = $1 },
            delete: { key in
                if key == "registry", failLegacyDelete {
                    failLegacyDelete = false
                    throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
                }
                secretItems.removeValue(forKey: key)
            },
            readRegistration: { registrationItems[$0] },
            writeRegistration: { workspaceId, value in
                if failingWorkspace == workspaceId {
                    failingWorkspace = nil
                    throw SandboxError.blocked("INJECTED_RECOVERY_REGISTRATION_WRITE_FAILURE")
                }
                registrationItems[workspaceId] = value
            },
            deleteRegistration: { registrationItems.removeValue(forKey: $0) },
            listRegistrations: { registrationItems },
            accountBinding: { accountBinding }
        )
        do {
            _ = try vault.registeredWorkspaceIds()
            fatalError("legacy recovery migration ignored a per-workspace persistence failure")
        } catch let error as SandboxError {
            require(
                error.localizedDescription == "INJECTED_RECOVERY_REGISTRATION_WRITE_FAILURE",
                "legacy recovery migration returned the wrong injected failure"
            )
        }
        require(secretItems["registry"] != nil, "partial legacy migration deleted its only complete source")
        require(
            registrationItems.keys.sorted() == [firstWorkspace],
            "partial legacy migration did not retain its independently converged item"
        )
        failLegacyDelete = true
        do {
            _ = try vault.registeredWorkspaceIds()
            fatalError("legacy recovery migration ignored a shared-registry deletion failure")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_DELETE_FAILED", "legacy registry deletion returned the wrong error")
        }
        require(secretItems["registry"] != nil, "failed legacy registry deletion was reported absent")
        require(
            registrationItems.keys.sorted() == [firstWorkspace, secondWorkspace],
            "legacy deletion failure discarded converged per-workspace items"
        )
        let migratedIds = try vault.registeredWorkspaceIds()
        require(migratedIds == [firstWorkspace, secondWorkspace], "legacy recovery migration retry lost a workspace")
        require(secretItems["registry"] == nil, "verified legacy recovery migration retained the shared registry blob")
        require(
            registrationItems.keys.sorted() == [firstWorkspace, secondWorkspace],
            "legacy recovery migration did not converge to one item per workspace"
        )

        var attemptedRegistrationWrite = false
        let unreadableLegacyVault = NativeRecoverySecretVault(
            read: { _ in nil },
            write: { _, _ in },
            delete: { _ in },
            readLegacyRegistry: { throw SandboxError.blocked("KEYCHAIN_READ_FAILED") },
            readRegistration: { _ in nil },
            writeRegistration: { _, _ in attemptedRegistrationWrite = true },
            deleteRegistration: { _ in },
            listRegistrations: { [:] },
            accountBinding: { accountBinding }
        )
        do {
            _ = try unreadableLegacyVault.registeredWorkspaceIds()
            fatalError("legacy migration treated a Keychain read failure as an empty registry")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_READ_FAILED", "legacy read failure was not propagated")
        }
        require(!attemptedRegistrationWrite, "legacy read failure wrote new registration state")

        let otherHash = try NativeAccountBinding.hash("different-recovery-account")
        let conflictingRegistration = String(decoding: try json([
            "workspaceId": firstWorkspace,
            "accountBindingHash": otherHash,
        ]), as: UTF8.self)
        var conflictingSecrets = ["registry": String(decoding: legacyData, as: UTF8.self)]
        var conflictingItems = [firstWorkspace: conflictingRegistration]
        let conflictingVault = NativeRecoverySecretVault(
            read: { conflictingSecrets[$0] },
            write: { conflictingSecrets[$0] = $1 },
            delete: { conflictingSecrets.removeValue(forKey: $0) },
            readRegistration: { conflictingItems[$0] },
            writeRegistration: { conflictingItems[$0] = $1 },
            deleteRegistration: { conflictingItems.removeValue(forKey: $0) },
            listRegistrations: { conflictingItems },
            accountBinding: { accountBinding }
        )
        do {
            _ = try conflictingVault.registeredWorkspaceIds()
            fatalError("legacy migration overwrote a conflicting per-workspace registration")
        } catch let error as SandboxError {
            require(error.localizedDescription == "ICLOUD_RECOVERY_SCOPE_CONFLICT", "legacy conflict returned the wrong error")
        }
        require(conflictingSecrets["registry"] != nil, "legacy conflict discarded the source registry")
        require(conflictingItems[firstWorkspace] == conflictingRegistration, "legacy conflict overwrote the converged item")

        var oversizedRegistry: [String: String] = [:]
        for index in 0...256 {
            let workspaceId = String(format: "%032d", index)
            oversizedRegistry[workspaceId] = String(decoding: try json([
                "workspaceId": workspaceId,
                "accountBindingHash": accountBindingHash,
            ]), as: UTF8.self)
        }
        let boundedVault = NativeRecoverySecretVault(
            read: { _ in nil },
            write: { _, _ in },
            delete: { _ in },
            readRegistration: { oversizedRegistry[$0] },
            writeRegistration: { oversizedRegistry[$0] = $1 },
            deleteRegistration: { oversizedRegistry.removeValue(forKey: $0) },
            listRegistrations: { oversizedRegistry },
            accountBinding: { accountBinding }
        )
        do {
            _ = try boundedVault.registeredWorkspaceIds()
            fatalError("recovery registry accepted more than its bounded item count")
        } catch let error as SandboxError {
            require(error.localizedDescription == "ICLOUD_RECOVERY_REGISTRY_FULL", "recovery registry bound returned the wrong error")
        }
    }

    static func concurrentRecoveryRegistrationContract() throws {
        let store = ConcurrentRecoveryRegistrationStore()
        let accountBinding = "concurrent-recovery-account"
        let firstVault = store.vault(accountBinding: accountBinding)
        let secondVault = store.vault(accountBinding: accountBinding)
        let firstWorkspace = String(repeating: "C", count: 32)
        let secondWorkspace = String(repeating: "D", count: 32)
        let firstSecret = String(repeating: "E", count: 42) + "A"
        let secondSecret = String(repeating: "F", count: 42) + "A"
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "LocalSandbox.concurrent-recovery-test", attributes: .concurrent)
        group.enter()
        queue.async {
            defer { group.leave() }
            do { try firstVault.save(firstSecret, workspaceId: firstWorkspace) }
            catch { store.record(error) }
        }
        group.enter()
        queue.async {
            defer { group.leave() }
            do { try secondVault.save(secondSecret, workspaceId: secondWorkspace) }
            catch { store.record(error) }
        }
        require(group.wait(timeout: .now() + 5) == .success, "concurrent recovery registration did not finish")
        require(store.recordedFailures().isEmpty, "concurrent recovery registration failed: \(store.recordedFailures())")
        let registeredWorkspaceIds = try firstVault.registeredWorkspaceIds()
        let recoveredFirstSecret = try firstVault.recoverySecret(workspaceId: firstWorkspace)
        let recoveredSecondSecret = try secondVault.recoverySecret(workspaceId: secondWorkspace)
        require(
            registeredWorkspaceIds == [firstWorkspace, secondWorkspace],
            "two-device recovery registration lost a concurrently enrolled workspace"
        )
        require(recoveredFirstSecret == firstSecret, "first concurrent recovery secret was lost")
        require(recoveredSecondSecret == secondSecret, "second concurrent recovery secret was lost")
    }
}
