import Foundation
import CryptoKit
import Security

enum NativeServiceLimits {
    static let maximumSafeInteger = 9_007_199_254_740_991
    static let exchangeRequestBytes = 20_000
    static let exchangeResponseBytes = 20_000
    static let accountDeletionResponseBytes = 8_192
    static let credentialReviewRequestBytes = 2_000
    static let credentialReviewResponseBytes = 2_000
    static let syncRequestBytes = 200_000
    static let syncResponseBytes = 512 * 1_024
    static let bearerLifetimeSeconds = 900
    static let authorizationCodeBytes = 8_000
    static let pendingRevocationRecords = 4
    static let pendingRevocationBytes = 4_096
    static let pendingActivationBytes = 4_096
    static let nativeGrantLifetimeSeconds = 30 * 24 * 60 * 60
    static let accountDeletionAttemptLifetimeSeconds = 30 * 24 * 60 * 60
    static let nativeResponseClockSkewSeconds = 30
}

struct NativeLifecycleGeneration {
    private(set) var value: UInt64 = 0

    func capture() -> UInt64 { value }
    func isCurrent(_ captured: UInt64) -> Bool { captured == value }
    mutating func invalidate() { value &+= 1 }
}

struct NativeBearerAuthorityWindow: Equatable, Sendable {
    let expiresAt: Date

    func remainingSeconds(at now: Date) -> TimeInterval? {
        let remaining = expiresAt.timeIntervalSince(now)
        guard remaining.isFinite, remaining > 0 else { return nil }
        return remaining
    }

    func isAvailable(at now: Date) -> Bool {
        remainingSeconds(at: now) != nil
    }
}

final class NativeAppleAuthPersistenceGate: @unchecked Sendable {
    private let lock = NSLock()
    private var newestGeneration: UInt64 = 0

    func register(_ generation: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        if generation > newestGeneration { newestGeneration = generation }
    }

    func requireCurrent(_ generation: UInt64) throws {
        lock.lock()
        defer { lock.unlock() }
        guard generation == newestGeneration else {
            throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
        }
    }

    func isCurrent(_ generation: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return generation == newestGeneration
    }

    func serialized<T>(_ operation: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try operation()
    }

    func savePendingIfCurrent(
        _ generation: UInt64,
        save: () throws -> NativePendingActivationRecord
    ) throws -> NativePendingActivationRecord? {
        lock.lock()
        defer { lock.unlock() }
        guard generation == newestGeneration else { return nil }
        return try save()
    }

    func persistIfCurrent(
        _ generation: UInt64,
        issued: NativeBearerSession,
        vault: NativeBearerVault,
        stagePrevious: (NativeBearerSession) throws -> Void,
        now: Int
    ) throws -> NativeAppleAuthPersistenceResult {
        lock.lock()
        defer { lock.unlock() }
        guard generation == newestGeneration else { return .superseded }
        let previous = try vault.loadChecked(now: now)
        if let previous,
           previous.token != issued.token,
           previous.mayHaveRevocableGrant(at: now) {
            try stagePrevious(previous)
        }
        try vault.save(issued, now: now)
        return .saved(previous: previous)
    }

    func persistRefreshIfCurrent(
        _ generation: UInt64,
        expectedToken: String,
        refreshed: NativeBearerSession,
        vault: NativeBearerVault,
        retirementContainsExactToken: () throws -> Bool,
        now: Int
    ) throws -> NativeAppleRefreshPersistenceResult {
        lock.lock()
        defer { lock.unlock() }
        let retained = try vault.loadChecked(now: now)
        let queuedForRetirement: Bool
        do {
            queuedForRetirement = try retirementContainsExactToken()
        } catch {
            if let retained, retained.token == expectedToken {
                if retained.expiresAt < refreshed.expiresAt {
                    try vault.save(refreshed, now: now)
                }
                return .retirementStateUnreadable(retainedCurrentToken: true)
            }
            return .retirementStateUnreadable(retainedCurrentToken: false)
        }
        guard generation == newestGeneration else {
            guard let retained, retained.token == expectedToken else {
                return .superseded(action: .retireDetached)
            }
            if queuedForRetirement {
                return .superseded(action: .extendRetirementDebt)
            }
            if retained.expiresAt < refreshed.expiresAt {
                try vault.save(refreshed, now: now)
            }
            return .superseded(action: .none)
        }
        guard let retained,
              retained.token == expectedToken,
              !queuedForRetirement else {
            return .superseded(action: queuedForRetirement ? .extendRetirementDebt:.retireDetached)
        }
        if retained.expiresAt >= refreshed.expiresAt {
            return .saved(retained)
        }
        try vault.save(refreshed, now: now)
        return .saved(refreshed)
    }

    func promoteIfCurrent(
        _ generation: UInt64,
        issued: NativeBearerSession,
        vault: NativeBearerVault,
        stagePrevious: (NativeBearerSession) throws -> Void,
        requirePendingActivation: () throws -> Void,
        clearPendingActivation: () throws -> Void,
        now: Int
    ) throws -> NativeAppleAuthPersistenceResult {
        lock.lock()
        defer { lock.unlock() }
        guard generation == newestGeneration else { return .superseded }
        try requirePendingActivation()
        let previous = try vault.loadChecked(now: now)
        if let previous,
           previous.token != issued.token,
           previous.mayHaveRevocableGrant(at: now) {
            try stagePrevious(previous)
        }
        if previous != issued {
            try vault.save(issued, now: now)
        }
        try clearPendingActivation()
        return .saved(previous: previous)
    }
}

enum NativeAppleAuthPersistenceResult: Sendable {
    case superseded
    case saved(previous: NativeBearerSession?)
}

enum NativeAppleRefreshPersistenceResult: Sendable {
    case saved(NativeBearerSession)
    case superseded(action: NativeAppleRefreshSupersededAction)
    case retirementStateUnreadable(retainedCurrentToken: Bool)
}

enum NativeAppleRefreshSupersededAction: Sendable {
    case none
    case extendRetirementDebt
    case retireDetached
}

enum NativeSecureRandom {
    static func bytes(count: Int) throws -> Data {
        guard count > 0, count <= 1_024 else { throw SandboxError.invalid("INVALID_RANDOM_LENGTH") }
        var value = Data(count: count)
        let status = value.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        guard status == errSecSuccess else { throw SandboxError.blocked("SECURE_RANDOM_UNAVAILABLE") }
        return value
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

enum NativeAppleNonce {
    static func make(using random: (Int) throws -> Data = NativeSecureRandom.bytes) throws -> String {
        let bytes = try random(32)
        guard bytes.count == 32 else { throw SandboxError.blocked("SECURE_RANDOM_LENGTH_INVALID") }
        return NativeSecureRandom.base64URL(bytes)
    }

    static func requestHash(_ rawNonce: String) throws -> String {
        guard rawNonce.range(of: "^[A-Za-z0-9_-]{32,128}$", options: .regularExpression) != nil else {
            throw SandboxError.invalid("APPLE_NATIVE_NONCE_INVALID")
        }
        return NativeSecureRandom.base64URL(Data(SHA256.hash(data: Data(rawNonce.utf8))))
    }
}

enum NativeAppleAuthorizationCode {
    static func strictUTF8(_ data: Data?) throws -> String {
        guard let data,
              (1...NativeServiceLimits.authorizationCodeBytes).contains(data.count),
              let value = String(data: data, encoding: .utf8),
              value.utf8.count == data.count else {
            throw SandboxError.invalid("APPLE_AUTHORIZATION_CODE_INVALID")
        }
        return try validated(value)
    }

    static func validated(_ value: String) throws -> String {
        guard (1...NativeServiceLimits.authorizationCodeBytes).contains(value.utf8.count) else {
            throw SandboxError.invalid("APPLE_AUTHORIZATION_CODE_INVALID")
        }
        return value
    }
}

enum NativeAccountDeletionKey {
    static func make(using random: (Int) throws -> Data = NativeSecureRandom.bytes) throws -> String {
        let bytes = try random(32)
        guard bytes.count == 32 else { throw SandboxError.blocked("SECURE_RANDOM_LENGTH_INVALID") }
        let value = "v1.\(NativeSecureRandom.base64URL(bytes))"
        guard valid(value) else { throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_KEY_INVALID") }
        return value
    }

    static func valid(_ value: String) -> Bool {
        guard value.range(of: "^v1\\.[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
            return false
        }
        let encoded = String(value.dropFirst(3))
        let base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + "="
        guard let bytes = Data(base64Encoded: base64), bytes.count == 32 else { return false }
        return NativeSecureRandom.base64URL(bytes) == encoded
    }
}

struct NativeServiceEndpoints: Equatable, Sendable {
    static let productionOrigin = URL(string: "https://local-sandbox.ctyy4wd4c2.chatgpt.site")!
    let origin: URL

    init(origin: URL = Self.productionOrigin) throws {
        guard origin.scheme == "https", origin.host != nil, origin.user == nil, origin.password == nil,
              origin.query == nil, origin.fragment == nil, origin.path.isEmpty || origin.path == "/" else {
            throw SandboxError.invalid("NATIVE_SERVICE_ORIGIN_INVALID")
        }
        self.origin = origin
    }

    func url(path: String, queryItems: [URLQueryItem] = []) throws -> URL {
        guard path.hasPrefix("/"), !path.contains("..") else { throw SandboxError.invalid("NATIVE_SERVICE_PATH_INVALID") }
        var components = URLComponents(url: origin, resolvingAgainstBaseURL: false)
        components?.path = path
        components?.queryItems = queryItems.isEmpty ? nil : queryItems
        guard let url = components?.url else { throw SandboxError.invalid("NATIVE_SERVICE_PATH_INVALID") }
        return url
    }
}

struct NativeHTTPResult: Sendable {
    let data: Data
    let response: HTTPURLResponse
}

protocol NativeHTTPPerforming: Sendable {
    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult
}

private final class NativeRedirectRefusalDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

final class NativeURLSessionTransport: NativeHTTPPerforming, Sendable {
    private let redirectDelegate: NativeRedirectRefusalDelegate
    private let session: URLSession

    init(protocolClasses: [AnyClass]? = nil) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpCookieStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 45
        if let protocolClasses { configuration.protocolClasses = protocolClasses }
        let redirectDelegate = NativeRedirectRefusalDelegate()
        self.redirectDelegate = redirectDelegate
        self.session = URLSession(configuration: configuration, delegate: redirectDelegate, delegateQueue: nil)
    }

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult {
        guard maximumResponseBytes > 0 else { throw SandboxError.invalid("INVALID_RESPONSE_BOUND") }
        let (bytes, rawResponse) = try await session.bytes(for: request)
        guard let response = rawResponse as? HTTPURLResponse else { throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_INVALID") }
        guard response.expectedContentLength < 0 || response.expectedContentLength <= Int64(maximumResponseBytes) else {
            throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_TOO_LARGE")
        }
        var data = Data()
        if response.expectedContentLength > 0 {
            data.reserveCapacity(min(Int(response.expectedContentLength), maximumResponseBytes))
        }
        for try await byte in bytes {
            guard data.count < maximumResponseBytes else { throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_TOO_LARGE") }
            data.append(byte)
        }
        return NativeHTTPResult(data: data, response: response)
    }
}

struct NativeServiceError: LocalizedError {
    let status: Int
    let code: String
    let message: String
    let conflictRecord: NativeStoredEncryptedRecord?

    var errorDescription: String? { "\(code): \(message)" }
}

private struct NativeErrorEnvelope: Decodable {
    let code: String?
    let error: String?
    let record: NativeStoredEncryptedRecord?
}

private enum NativeJSON {
    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()
    static let decoder = JSONDecoder()

    static func body<T: Encodable>(_ value: T, maximumBytes: Int) throws -> Data {
        let data = try encoder.encode(value)
        guard data.count <= maximumBytes else { throw SandboxError.invalid("NATIVE_SERVICE_REQUEST_TOO_LARGE") }
        return data
    }

    static func decode<T: Decodable>(_ type: T.Type, from result: NativeHTTPResult, maximumBytes: Int) throws -> T {
        guard result.data.count <= maximumBytes else { throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_TOO_LARGE") }
        guard (200...299).contains(result.response.statusCode) else {
            let decoded = try? decoder.decode(NativeErrorEnvelope.self, from: result.data)
            throw NativeServiceError(
                status: result.response.statusCode,
                code: decoded?.code ?? "HTTP_\(result.response.statusCode)",
                message: decoded?.error ?? "The Local Sandbox service rejected the request.",
                conflictRecord: decoded?.record
            )
        }
        do { return try decoder.decode(type, from: result.data) }
        catch { throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_INVALID") }
    }

    static func requireJSONSuccessContentType(_ result: NativeHTTPResult) throws {
        guard (200...299).contains(result.response.statusCode) else { return }
        let contentType = result.response.value(forHTTPHeaderField: "Content-Type")?
            .split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard contentType == "application/json" else {
            throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_INVALID")
        }
    }
}

enum NativeRequestFactory {
    static func exchange(
        endpoints: NativeServiceEndpoints,
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        transferRecoveryUser: String? = nil
    ) throws -> URLRequest {
        guard (20...16_000).contains(identityToken.utf8.count) else { throw SandboxError.invalid("APPLE_ID_TOKEN_INVALID") }
        let validatedCode = try NativeAppleAuthorizationCode.validated(authorizationCode)
        _ = try NativeAppleNonce.requestHash(rawNonce)
        if let transferRecoveryUser {
            guard (1...255).contains(transferRecoveryUser.utf8.count) else {
                throw SandboxError.invalid("APPLE_TRANSFER_RECOVERY_USER_INVALID")
            }
        }
        let body = try NativeJSON.body(
            NativeAppleExchangeRequest(
                identityToken: identityToken,
                authorizationCode: validatedCode,
                rawNonce: rawNonce,
                transferRecoveryUser: transferRecoveryUser
            ),
            maximumBytes: NativeServiceLimits.exchangeRequestBytes
        )
        return try request(url: endpoints.url(path: "/api/auth/apple/native/exchange"), method: "POST", body: body, bearer: nil)
    }

    static func refresh(endpoints: NativeServiceEndpoints, bearer: String) throws -> URLRequest {
        try request(url: endpoints.url(path: "/api/auth/apple/native/refresh"), method: "POST", body: nil, bearer: bearer)
    }

    static func activate(endpoints: NativeServiceEndpoints, bearer: String) throws -> URLRequest {
        try request(url: endpoints.url(path: "/api/auth/apple/native/activate"), method: "POST", body: nil, bearer: bearer)
    }

    static func revoke(endpoints: NativeServiceEndpoints, bearer: String) throws -> URLRequest {
        try request(url: endpoints.url(path: "/api/auth/apple/native/revoke"), method: "POST", body: nil, bearer: bearer)
    }

    static func deleteAccount(
        endpoints: NativeServiceEndpoints,
        bearer: String,
        idempotencyKey: String
    ) throws -> URLRequest {
        guard NativeAccountDeletionKey.valid(idempotencyKey) else {
            throw SandboxError.invalid("APPLE_ACCOUNT_DELETION_KEY_INVALID")
        }
        var deletion = try request(
            url: endpoints.url(path: "/api/auth/apple/delete"),
            method: "POST",
            body: nil,
            bearer: bearer
        )
        deletion.setValue(idempotencyKey, forHTTPHeaderField: "Idempotency-Key")
        return deletion
    }

    static func possibleCredentialReview(
        endpoints: NativeServiceEndpoints,
        bearer: String
    ) throws -> URLRequest {
        try request(
            url: endpoints.url(path: "/api/auth/apple/possible-credential"),
            method: "GET",
            body: nil,
            bearer: bearer
        )
    }

    static func acknowledgePossibleCredentialReview(
        endpoints: NativeServiceEndpoints,
        bearer: String,
        acknowledgementID: NativeAppleCredentialReviewAcknowledgementID
    ) throws -> URLRequest {
        let body = try NativeJSON.body(
            NativeAppleCredentialReviewAcknowledgementRequest(
                acknowledgementId: acknowledgementID.rawValue
            ),
            maximumBytes: NativeServiceLimits.credentialReviewRequestBytes
        )
        return try request(
            url: endpoints.url(path: "/api/auth/apple/possible-credential"),
            method: "POST",
            body: body,
            bearer: bearer
        )
    }

    static func sync(
        endpoints: NativeServiceEndpoints,
        method: String,
        queryItems: [URLQueryItem] = [],
        body: Data? = nil,
        bearer: String
    ) throws -> URLRequest {
        guard (method == "GET" && body == nil) || (method == "POST" && body != nil) else {
            throw SandboxError.invalid("NATIVE_SYNC_METHOD_INVALID")
        }
        guard body.map({ $0.count <= NativeServiceLimits.syncRequestBytes }) ?? true else {
            throw SandboxError.invalid("NATIVE_SERVICE_REQUEST_TOO_LARGE")
        }
        return try request(url: endpoints.url(path: "/api/sync", queryItems: queryItems), method: method, body: body, bearer: bearer)
    }

    private static func request(url: URL, method: String, body: Data?, bearer: String?) throws -> URLRequest {
        guard url.scheme == "https", url.user == nil, url.password == nil else {
            throw SandboxError.invalid("NATIVE_SERVICE_URL_INVALID")
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 30)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let bearer {
            guard NativeBearerSession.validToken(bearer) else { throw SandboxError.blocked("APPLE_NATIVE_SESSION_INVALID") }
            request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        }
        request.setValue(nil, forHTTPHeaderField: "Cookie")
        return request
    }
}

private struct NativeAppleExchangeRequest: Encodable {
    let identityToken: String
    let authorizationCode: String
    let rawNonce: String
    let transferRecoveryUser: String?
}

private struct NativeAppleCredentialReviewAcknowledgementRequest: Encodable {
    let acknowledgementId: String
}

enum NativeAppleAccountMode: String, Codable, Equatable, Sendable {
    case standalone, linked
}

struct NativeApplePendingSessionResponse: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let activationState: String
    let tokenType: String
    let token: String
    let expiresAt: Int
    let accountMode: NativeAppleAccountMode

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, activationState, tokenType, token, expiresAt, accountMode
    }

    init(
        schemaVersion: Int,
        activationState: String,
        tokenType: String,
        token: String,
        expiresAt: Int,
        accountMode: NativeAppleAccountMode
    ) {
        self.schemaVersion = schemaVersion
        self.activationState = activationState
        self.tokenType = tokenType
        self.token = token
        self.expiresAt = expiresAt
        self.accountMode = accountMode
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        activationState = try container.decode(String.self, forKey: .activationState)
        tokenType = try container.decode(String.self, forKey: .tokenType)
        token = try container.decode(String.self, forKey: .token)
        expiresAt = try container.decode(Int.self, forKey: .expiresAt)
        accountMode = try container.decode(NativeAppleAccountMode.self, forKey: .accountMode)
    }

    func structurallyValidated() throws -> Self {
        guard schemaVersion == 2,
              activationState == "pending",
              tokenType == "Bearer",
              NativeBearerSession.validToken(token),
              (1...NativeServiceLimits.maximumSafeInteger).contains(expiresAt) else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_INVALID")
        }
        return self
    }

    func validated(now: Int) throws -> Self {
        let pending = try structurallyValidated()
        guard expiresAt > now,
              expiresAt <= now + NativeServiceLimits.bearerLifetimeSeconds
                + NativeServiceLimits.nativeResponseClockSkewSeconds else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_INVALID")
        }
        return pending
    }

    func retirementSession() throws -> NativeBearerSession {
        _ = try structurallyValidated()
        return NativeBearerSession(
            schemaVersion: 1,
            tokenType: tokenType,
            token: token,
            expiresAt: expiresAt,
            accountMode: accountMode
        )
    }
}

struct NativeAppleActiveSessionResponse: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let activationState: String
    let tokenType: String
    let token: String
    let expiresAt: Int
    let accountMode: NativeAppleAccountMode

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, activationState, tokenType, token, expiresAt, accountMode
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        activationState = try container.decode(String.self, forKey: .activationState)
        tokenType = try container.decode(String.self, forKey: .tokenType)
        token = try container.decode(String.self, forKey: .token)
        expiresAt = try container.decode(Int.self, forKey: .expiresAt)
        accountMode = try container.decode(NativeAppleAccountMode.self, forKey: .accountMode)
    }

    func retirementBearer() throws -> NativeBearerSession {
        guard schemaVersion == 2, activationState == "active" else {
            throw SandboxError.blocked("APPLE_NATIVE_ACTIVE_SESSION_INVALID")
        }
        guard tokenType == "Bearer",
              NativeBearerSession.validToken(token),
              (1...NativeServiceLimits.maximumSafeInteger).contains(expiresAt) else {
            throw SandboxError.blocked("APPLE_NATIVE_ACTIVE_SESSION_INVALID")
        }
        return NativeBearerSession(
            schemaVersion: 1,
            tokenType: tokenType,
            token: token,
            expiresAt: expiresAt,
            accountMode: accountMode
        )
    }

    func localBearer(now: Int) throws -> NativeBearerSession {
        try retirementBearer().validated(now: now)
    }

    func localBearer(matching pending: NativeApplePendingSessionResponse, now: Int) throws -> NativeBearerSession {
        let active = try localBearer(now: now)
        let expected = try pending.structurallyValidated()
        guard active.token == expected.token,
              active.expiresAt == expected.expiresAt,
              active.accountMode == expected.accountMode else {
            throw SandboxError.blocked("APPLE_NATIVE_ACTIVATION_RESPONSE_MISMATCH")
        }
        return active
    }
}

struct NativeBearerSession: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let tokenType: String
    let token: String
    let expiresAt: Int
    let accountMode: NativeAppleAccountMode

    static func validToken(_ value: String) -> Bool {
        value.range(of: "^v1\\.[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
    }

    func validated(
        now: Int,
        maximumLifetime: Int = NativeServiceLimits.bearerLifetimeSeconds
            + NativeServiceLimits.nativeResponseClockSkewSeconds
    ) throws -> Self {
        guard schemaVersion == 1, tokenType == "Bearer", Self.validToken(token),
              expiresAt > now, expiresAt <= now + maximumLifetime else {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_INVALID")
        }
        return self
    }

    func mayHaveRevocableGrant(at now: Int) -> Bool {
        _ = now
        return Self.validToken(token) && expiresAt > 0
    }
}

struct NativeAppleSessionResponseRejected: LocalizedError, Sendable {
    let session: NativeBearerSession
    let receivedAt: Int
    let code: String
    let observedResponseToken: String?

    init(
        session: NativeBearerSession,
        receivedAt: Int,
        code: String,
        observedResponseToken: String? = nil
    ) {
        self.session = session
        self.receivedAt = receivedAt
        self.code = code
        self.observedResponseToken = observedResponseToken
    }

    var errorDescription: String? { code }
}

private enum NativeAppleExchangeRecoveryEnvelope {
    static func token(from data: Data) -> String? {
        guard data.count <= NativeServiceLimits.exchangeResponseBytes,
              let object = try? JSONSerialization.jsonObject(with: data),
              let payload = object as? [String: Any],
              let token = payload["token"] as? String,
              NativeBearerSession.validToken(token) else {
            return nil
        }
        return token
    }
}

struct NativeReceived<Value: Sendable>: Sendable {
    let value: Value
    let receivedAt: Int
}

struct NativeAppleCredentialReviewAcknowledgementID: Equatable, Sendable {
    let rawValue: String

    init(_ rawValue: String) throws {
        guard rawValue.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
            throw SandboxError.invalid("APPLE_AUTH_CREDENTIAL_REVIEW_ID_INVALID")
        }
        self.rawValue = rawValue
    }
}

struct NativeAppleCredentialReviewReceipt: Equatable, Sendable {
    let acknowledgementID: NativeAppleCredentialReviewAcknowledgementID
    let markedAt: Int
}

enum NativeAppleCredentialReview: Equatable, Sendable, Decodable {
    case clear
    case required(NativeAppleCredentialReviewReceipt)

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case manualReviewRequired, acknowledgementId, markedAt
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let manualReviewRequired = try container.decode(Bool.self, forKey: .manualReviewRequired)
        if manualReviewRequired {
            let acknowledgementID = try NativeAppleCredentialReviewAcknowledgementID(
                container.decode(String.self, forKey: .acknowledgementId)
            )
            let markedAt = try container.decode(Int.self, forKey: .markedAt)
            guard (0...NativeServiceLimits.maximumSafeInteger).contains(markedAt) else {
                throw DecodingError.dataCorrupted(.init(
                    codingPath: decoder.codingPath,
                    debugDescription: "The Apple credential review timestamp is invalid."
                ))
            }
            self = .required(.init(acknowledgementID: acknowledgementID, markedAt: markedAt))
            return
        }
        guard try container.decodeNil(forKey: .acknowledgementId),
              try container.decodeNil(forKey: .markedAt) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "A clear Apple credential review cannot contain a receipt."
            ))
        }
        self = .clear
    }
}

private final class NativeHostedAccessAdmissionState: @unchecked Sendable {
    let lock = NSLock()
    var blocked = true
}

enum NativeHostedAccessAdmission {
    private static let state = NativeHostedAccessAdmissionState()

    static func block() {
        state.lock.lock()
        state.blocked = true
        state.lock.unlock()
    }

    static func allowAfterCredentialVerification() {
        state.lock.lock()
        state.blocked = false
        state.lock.unlock()
    }

    static func isBlocked() -> Bool {
        state.lock.lock()
        defer { state.lock.unlock() }
        return state.blocked
    }
}

private struct NativeAppleTransferBlockRecord: Codable, Equatable {
    let schemaVersion: Int
    let oldUser: String
    let oldUserHash: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, oldUser, oldUserHash
    }

    init(oldUser: String) throws {
        schemaVersion = 1
        self.oldUser = oldUser
        oldUserHash = try NativeAccountBinding.hash(oldUser)
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        oldUser = try container.decode(String.self, forKey: .oldUser)
        oldUserHash = try container.decode(String.self, forKey: .oldUserHash)
    }

    func validated() throws -> Self {
        guard schemaVersion == 1,
              (1...1_000).contains(oldUser.utf8.count),
              oldUserHash == (try NativeAccountBinding.hash(oldUser)) else {
            throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_INVALID")
        }
        return self
    }
}

struct NativeAppleTransferBlockVault: @unchecked Sendable {
    private static let storageKey = "appleNativeTransferBlock.v1"
    let read: () throws -> String?
    let write: (String) throws -> Void
    let delete: () throws -> Void

    static let live = NativeAppleTransferBlockVault(
        read: { try Keychain.getChecked(storageKey) },
        write: { try Keychain.set($0, for: storageKey) },
        delete: { try Keychain.deleteChecked(storageKey) }
    )

    func load() throws -> String? {
        guard let encoded = try read() else { return nil }
        guard encoded.utf8.count <= 2_500,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_INVALID")
        }
        do {
            return try NativeJSON.decoder.decode(NativeAppleTransferBlockRecord.self, from: data)
                .validated().oldUser
        } catch {
            throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_INVALID")
        }
    }

    func block(oldUser: String) throws {
        if let existing = try load() {
            guard existing == oldUser else {
                throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_CONFLICT")
            }
            return
        }
        let encoded = String(
            decoding: try NativeJSON.encoder.encode(NativeAppleTransferBlockRecord(oldUser: oldUser)),
            as: UTF8.self
        )
        try write(encoded)
        guard try load() == oldUser else {
            throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_PERSISTENCE_FAILED")
        }
    }

    func clearChecked(oldUser: String) throws {
        guard let existing = try load() else { return }
        guard existing == oldUser else {
            throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_CONFLICT")
        }
        try delete()
        guard try read() == nil else {
            throw SandboxError.blocked("APPLE_TRANSFER_BLOCK_PERSISTENCE_FAILED")
        }
    }
}

enum NativeAppleActivationPurpose: String, Codable, Equatable, Hashable, Sendable {
    case ordinary
    case transferRecovery
    case deletionReauthorization
}

struct NativeAppleActivationContext: Equatable, Hashable, Sendable {
    let targetAccountBindingHash: String
    let purpose: NativeAppleActivationPurpose
    let transferRecoveryAccountBindingHash: String?

    init(
        targetAccountBinding: String,
        purpose: NativeAppleActivationPurpose,
        transferRecoveryUser: String?
    ) throws {
        targetAccountBindingHash = try NativeAccountBinding.hash(targetAccountBinding)
        self.purpose = purpose
        transferRecoveryAccountBindingHash = try transferRecoveryUser.map(NativeAccountBinding.hash)
        try validatePurpose()
    }

    fileprivate init(
        targetAccountBindingHash: String,
        purpose: NativeAppleActivationPurpose,
        transferRecoveryAccountBindingHash: String?
    ) throws {
        self.targetAccountBindingHash = targetAccountBindingHash
        self.purpose = purpose
        self.transferRecoveryAccountBindingHash = transferRecoveryAccountBindingHash
        try validatePurpose()
    }

    private func validatePurpose() throws {
        let validHash: (String) -> Bool = {
            $0.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
        }
        guard validHash(targetAccountBindingHash),
              transferRecoveryAccountBindingHash.map(validHash) ?? true else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_INVALID")
        }
        switch purpose {
        case .ordinary:
            guard transferRecoveryAccountBindingHash == nil else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_INVALID")
            }
        case .transferRecovery:
            guard transferRecoveryAccountBindingHash != nil else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_INVALID")
            }
        case .deletionReauthorization:
            break
        }
    }
}

struct NativePendingActivationRecord: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let targetAccountBindingHash: String
    let purpose: NativeAppleActivationPurpose
    let transferRecoveryAccountBindingHash: String?
    let pendingSession: NativeApplePendingSessionResponse

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, targetAccountBindingHash, purpose
        case transferRecoveryAccountBindingHash, pendingSession
    }

    init(context: NativeAppleActivationContext, pendingSession: NativeApplePendingSessionResponse) {
        schemaVersion = 1
        targetAccountBindingHash = context.targetAccountBindingHash
        purpose = context.purpose
        transferRecoveryAccountBindingHash = context.transferRecoveryAccountBindingHash
        self.pendingSession = pendingSession
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        targetAccountBindingHash = try container.decode(String.self, forKey: .targetAccountBindingHash)
        purpose = try container.decode(NativeAppleActivationPurpose.self, forKey: .purpose)
        transferRecoveryAccountBindingHash = try container.decodeIfPresent(
            String.self,
            forKey: .transferRecoveryAccountBindingHash
        )
        pendingSession = try container.decode(NativeApplePendingSessionResponse.self, forKey: .pendingSession)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(targetAccountBindingHash, forKey: .targetAccountBindingHash)
        try container.encode(purpose, forKey: .purpose)
        if let transferRecoveryAccountBindingHash {
            try container.encode(
                transferRecoveryAccountBindingHash,
                forKey: .transferRecoveryAccountBindingHash
            )
        } else {
            try container.encodeNil(forKey: .transferRecoveryAccountBindingHash)
        }
        try container.encode(pendingSession, forKey: .pendingSession)
    }

    func validated() throws -> Self {
        guard schemaVersion == 1 else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_INVALID")
        }
        _ = try context()
        _ = try pendingSession.structurallyValidated()
        return self
    }

    func context() throws -> NativeAppleActivationContext {
        try NativeAppleActivationContext(
            targetAccountBindingHash: targetAccountBindingHash,
            purpose: purpose,
            transferRecoveryAccountBindingHash: transferRecoveryAccountBindingHash
        )
    }
}

final class NativePendingActivationVault: @unchecked Sendable {
    private final class Memory: @unchecked Sendable { var value: String? }
    private static let storageKey = "appleNativePendingActivation.v1"
    private let lock = NSLock()
    private let read: () throws -> String?
    private let write: (String) throws -> Void
    private let delete: () throws -> Void

    static let live = NativePendingActivationVault(
        read: { try Keychain.getChecked(storageKey) },
        write: { try Keychain.set($0, for: storageKey) },
        delete: { try Keychain.deleteChecked(storageKey) }
    )

    init(
        read: @escaping () throws -> String?,
        write: @escaping (String) throws -> Void,
        delete: @escaping () throws -> Void
    ) {
        self.read = read
        self.write = write
        self.delete = delete
    }

    static func transient() -> NativePendingActivationVault {
        let memory = Memory()
        return NativePendingActivationVault(
            read: { memory.value },
            write: { memory.value = $0 },
            delete: { memory.value = nil }
        )
    }

    func load() throws -> NativePendingActivationRecord? {
        lock.lock()
        defer { lock.unlock() }
        return try loadLocked()
    }

    @discardableResult
    func save(
        _ pending: NativeApplePendingSessionResponse,
        context: NativeAppleActivationContext,
        now: Int
    ) throws -> NativePendingActivationRecord {
        lock.lock()
        defer { lock.unlock() }
        let candidate = try NativePendingActivationRecord(
            context: context,
            pendingSession: pending.validated(now: now)
        ).validated()
        if let existing = try loadLocked() {
            guard existing == candidate else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
            }
            return existing
        }
        let encoded = String(decoding: try NativeJSON.encoder.encode(candidate), as: UTF8.self)
        guard encoded.utf8.count <= NativeServiceLimits.pendingActivationBytes else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_INVALID")
        }
        try write(encoded)
        guard try read() == encoded,
              try loadLocked() == candidate else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_PERSISTENCE_FAILED")
        }
        return candidate
    }

    func clearMatching(_ expected: NativePendingActivationRecord) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let stored = try loadLocked() else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
        }
        guard stored == expected else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
        }
        try clearLocked()
    }

    func requireMatching(_ expected: NativePendingActivationRecord) throws {
        lock.lock()
        defer { lock.unlock() }
        guard try loadLocked() == expected else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
        }
    }

    func clearMatchingToken(_ token: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let stored = try loadLocked() else { return }
        guard stored.pendingSession.token == token else { return }
        try clearLocked()
    }

    func clearChecked() throws {
        lock.lock()
        defer { lock.unlock() }
        try clearLocked()
    }

    func blocksAdmission() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        do { return try read() != nil }
        catch { return true }
    }

    private func loadLocked() throws -> NativePendingActivationRecord? {
        guard let encoded = try read() else { return nil }
        guard encoded.utf8.count <= NativeServiceLimits.pendingActivationBytes,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_INVALID")
        }
        do {
            return try NativeJSON.decoder.decode(
                NativePendingActivationRecord.self,
                from: data
            ).validated()
        } catch {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_INVALID")
        }
    }

    private func clearLocked() throws {
        try delete()
        guard try read() == nil else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_PERSISTENCE_FAILED")
        }
    }
}

private final class NativeBearerVaultStorage: @unchecked Sendable {
    let lock = NSLock()
    let read: () -> String?
    let readChecked: () throws -> String?
    let write: (String) throws -> Void
    let delete: () throws -> Void
    let admissionBlocked: () -> Bool
    let retirementBlocked: (String, Int) -> Bool

    init(
        read: @escaping () -> String?,
        readChecked: @escaping () throws -> String?,
        write: @escaping (String) throws -> Void,
        delete: @escaping () throws -> Void,
        admissionBlocked: @escaping () -> Bool,
        retirementBlocked: @escaping (String, Int) -> Bool
    ) {
        self.read = read
        self.readChecked = readChecked
        self.write = write
        self.delete = delete
        self.admissionBlocked = admissionBlocked
        self.retirementBlocked = retirementBlocked
    }
}

struct NativeBearerVault: @unchecked Sendable {
    private let storage: NativeBearerVaultStorage

    init(
        read: @escaping () -> String?,
        readChecked: (() throws -> String?)? = nil,
        write: @escaping (String) throws -> Void,
        delete: @escaping () throws -> Void,
        admissionBlocked: @escaping () -> Bool = { false },
        retirementBlocked: @escaping (String, Int) -> Bool = { _, _ in false }
    ) {
        self.storage = NativeBearerVaultStorage(
            read: read,
            readChecked: readChecked ?? { read() },
            write: write,
            delete: delete,
            admissionBlocked: admissionBlocked,
            retirementBlocked: retirementBlocked
        )
    }

    static let live = NativeBearerVault(
        read: { Keychain.get("appleNativeBearer.v1") },
        readChecked: { try Keychain.getChecked("appleNativeBearer.v1") },
        write: { try Keychain.set($0, for: "appleNativeBearer.v1") },
        delete: { try Keychain.deleteChecked("appleNativeBearer.v1") },
        admissionBlocked: {
            if NativeHostedAccessAdmission.isBlocked() { return true }
            if NativePendingActivationVault.live.blocksAdmission() { return true }
            do { return try Keychain.getChecked("appleNativeTransferBlock.v1") != nil }
            catch { return true }
        },
        retirementBlocked: { bearerToken, now in
            NativePendingRevocationVault.live.blocksAdmission(
                bearerToken: bearerToken,
                now: now
            )
        }
    )

    func load(now: Int = Int(Date().timeIntervalSince1970)) -> NativeBearerSession? {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return loadLocked(now: now)
    }

    func loadChecked(now: Int = Int(Date().timeIntervalSince1970)) throws -> NativeBearerSession? {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        guard let encoded = try storage.readChecked() else { return nil }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8),
              let session = try? NativeJSON.decoder.decode(NativeBearerSession.self, from: data),
              session.schemaVersion == 1,
              session.tokenType == "Bearer",
              NativeBearerSession.validToken(session.token),
              session.expiresAt > 0 else {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_INVALID")
        }
        if session.expiresAt > now, (try? session.validated(now: now)) == nil {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_INVALID")
        }
        // An expired bearer can still identify an Apple grant within the longer follow-up window.
        // Preserve it as the prior session so a successful replacement retires that grant.
        return session
    }

    func save(_ session: NativeBearerSession, now: Int = Int(Date().timeIntervalSince1970)) throws {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        let encoded = String(decoding: try NativeJSON.encoder.encode(try session.validated(now: now)), as: UTF8.self)
        try storage.write(encoded)
        guard try storage.readChecked() == encoded else {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_PERSISTENCE_FAILED")
        }
    }

    func loadForRetirement() throws -> NativeBearerSession? {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        guard let encoded = try storage.readChecked() else { return nil }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8),
              let session = try? NativeJSON.decoder.decode(NativeBearerSession.self, from: data),
              session.schemaVersion == 1,
              session.tokenType == "Bearer",
              NativeBearerSession.validToken(session.token),
              session.expiresAt > 0 else {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_INVALID")
        }
        return session
    }

    func clearChecked() throws {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        try clearCheckedLocked()
    }

    func clearIfMatchingChecked(token: String) throws {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        guard let encoded = try storage.readChecked() else { return }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8),
              let stored = try? NativeJSON.decoder.decode(NativeBearerSession.self, from: data),
              NativeBearerSession.validToken(stored.token) else {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_INVALID")
        }
        guard stored.token == token else { return }
        try clearCheckedLocked()
    }

    private func loadLocked(now: Int) -> NativeBearerSession? {
        guard !storage.admissionBlocked() else { return nil }
        guard let encoded = storage.read() else { return nil }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8),
              let session = try? NativeJSON.decoder.decode(NativeBearerSession.self, from: data),
              session.schemaVersion == 1,
              session.tokenType == "Bearer",
              NativeBearerSession.validToken(session.token),
              session.expiresAt > 0 else { return nil }
        guard let admitted = try? session.validated(now: now),
              !storage.retirementBlocked(admitted.token, now) else { return nil }
        return admitted
    }

    private func clearCheckedLocked() throws {
        try storage.delete()
        guard try storage.readChecked() == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
    }
}

struct NativePendingRevocation: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let bearerToken: String
    let queuedAt: Int
    let expiresAt: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, bearerToken, queuedAt, expiresAt
    }

    init(session: NativeBearerSession, now: Int) throws {
        let grantTail = NativeServiceLimits.nativeGrantLifetimeSeconds
            - NativeServiceLimits.bearerLifetimeSeconds
        guard NativeBearerSession.validToken(session.token),
              session.expiresAt > 0,
              session.expiresAt <= NativeServiceLimits.maximumSafeInteger,
              now > 0,
              now <= Int.max - NativeServiceLimits.nativeGrantLifetimeSeconds
                - NativeServiceLimits.nativeResponseClockSkewSeconds else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        bearerToken = session.token
        queuedAt = now
        if session.expiresAt <= now + NativeServiceLimits.bearerLifetimeSeconds
            + NativeServiceLimits.nativeResponseClockSkewSeconds,
           session.expiresAt <= Int.max - grantTail,
           session.expiresAt + grantTail > now {
            schemaVersion = 2
            expiresAt = session.expiresAt + grantTail
        } else {
            schemaVersion = 4
            expiresAt = now + NativeServiceLimits.nativeGrantLifetimeSeconds
                + NativeServiceLimits.nativeResponseClockSkewSeconds
        }
    }

    init(legacyDeletionAttempt attempt: NativeAccountDeletionAttempt, now: Int) throws {
        let legacy = try attempt.structurallyValidated()
        guard legacy.schemaVersion == 2,
              now >= legacy.createdAt,
              legacy.expiresAt <= Int.max - NativeServiceLimits.nativeGrantLifetimeSeconds
                - NativeServiceLimits.nativeResponseClockSkewSeconds else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        schemaVersion = 3
        bearerToken = legacy.bearerToken
        queuedAt = legacy.createdAt
        expiresAt = legacy.expiresAt + NativeServiceLimits.nativeGrantLifetimeSeconds
            + NativeServiceLimits.nativeResponseClockSkewSeconds
    }

    init(rejectedSession session: NativeBearerSession, receivedAt: Int) throws {
        guard NativeBearerSession.validToken(session.token),
              session.expiresAt > 0,
              session.expiresAt <= NativeServiceLimits.maximumSafeInteger,
              receivedAt > 0,
              receivedAt <= Int.max - NativeServiceLimits.nativeGrantLifetimeSeconds
                - NativeServiceLimits.nativeResponseClockSkewSeconds else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        schemaVersion = 4
        bearerToken = session.token
        queuedAt = receivedAt
        expiresAt = receivedAt + NativeServiceLimits.nativeGrantLifetimeSeconds
            + NativeServiceLimits.nativeResponseClockSkewSeconds
    }

    private init(
        schemaVersion: Int,
        bearerToken: String,
        queuedAt: Int,
        expiresAt: Int
    ) {
        self.schemaVersion = schemaVersion
        self.bearerToken = bearerToken
        self.queuedAt = queuedAt
        self.expiresAt = expiresAt
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        bearerToken = try container.decode(String.self, forKey: .bearerToken)
        queuedAt = try container.decode(Int.self, forKey: .queuedAt)
        expiresAt = try container.decode(Int.self, forKey: .expiresAt)
    }

    func validated(now _: Int) throws -> Self {
        let maximumLifetime: Int
        switch schemaVersion {
        case 1: maximumLifetime = NativeServiceLimits.bearerLifetimeSeconds
        case 2:
            maximumLifetime = NativeServiceLimits.nativeGrantLifetimeSeconds
                + NativeServiceLimits.nativeResponseClockSkewSeconds
        case 3:
            maximumLifetime = NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
                + NativeServiceLimits.nativeGrantLifetimeSeconds
                + NativeServiceLimits.nativeResponseClockSkewSeconds
        case 4:
            maximumLifetime = NativeServiceLimits.nativeGrantLifetimeSeconds
                + NativeServiceLimits.nativeResponseClockSkewSeconds
        default: throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        guard [1, 2, 3, 4].contains(schemaVersion),
              NativeBearerSession.validToken(bearerToken),
              queuedAt > 0,
              queuedAt <= Int.max - maximumLifetime,
              expiresAt > queuedAt,
              expiresAt <= queuedAt + maximumLifetime else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        return self
    }

    func upgradedForGrantRevocation(now: Int) throws -> Self {
        let validated = try validated(now: now)
        guard validated.schemaVersion == 1 else { return validated }
        let grantTail = NativeServiceLimits.nativeGrantLifetimeSeconds
            - NativeServiceLimits.bearerLifetimeSeconds
        guard validated.expiresAt <= Int.max - grantTail else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        return try NativePendingRevocation(
            schemaVersion: 2,
            bearerToken: validated.bearerToken,
            queuedAt: validated.queuedAt,
            expiresAt: validated.expiresAt + grantTail
        ).validated(now: now)
    }
}

private struct NativePendingRevocationQueue: Codable {
    let schemaVersion: Int
    let entries: [NativePendingRevocation]

    private enum CodingKeys: String, CodingKey, CaseIterable { case schemaVersion, entries }

    init(entries: [NativePendingRevocation]) {
        schemaVersion = 1
        self.entries = entries
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        entries = try container.decode([NativePendingRevocation].self, forKey: .entries)
    }

    func validated(now: Int) throws -> [NativePendingRevocation] {
        guard schemaVersion == 1, (1...NativeServiceLimits.pendingRevocationRecords).contains(entries.count) else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        let valid = try entries.map { try $0.upgradedForGrantRevocation(now: now) }
        guard Set(valid.map(\.bearerToken)).count == valid.count else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        return valid
    }
}

struct NativePendingRevocationStatus: Equatable, Sendable {
    let count: Int
    let expiresAt: Int
}

struct NativeRevocationDeferredError: LocalizedError, Equatable, Sendable {
    let expiresAt: Int
    var errorDescription: String? { "APPLE_NATIVE_REVOCATION_DEFERRED" }
}

final class NativePendingRevocationVault: @unchecked Sendable {
    private final class Memory: @unchecked Sendable { var value: String? }
    private static let storageKey = "appleNativeRevocationFollowUp.v1"
    private let lock = NSLock()
    private let read: () throws -> String?
    private let write: (String) throws -> Void
    private let delete: () throws -> Void

    static let live = NativePendingRevocationVault(
        read: { try Keychain.getChecked(storageKey) },
        write: { try Keychain.set($0, for: storageKey) },
        delete: { try Keychain.deleteChecked(storageKey) }
    )

    static func transient() -> NativePendingRevocationVault {
        let memory = Memory()
        return NativePendingRevocationVault(
            read: { memory.value },
            write: { memory.value = $0 },
            delete: { memory.value = nil }
        )
    }

    init(
        read: @escaping () throws -> String?,
        write: @escaping (String) throws -> Void,
        delete: @escaping () throws -> Void
    ) {
        self.read = read
        self.write = write
        self.delete = delete
    }

    func stage(_ session: NativeBearerSession, now: Int) throws {
        _ = try stage([session], now: now)
    }

    func stageRejectedSession(_ session: NativeBearerSession, receivedAt: Int) throws {
        let candidate = try NativePendingRevocation(
            rejectedSession: session,
            receivedAt: receivedAt
        )
        lock.lock()
        defer { lock.unlock() }
        var entries = try loadLocked(now: receivedAt)
        if let index = entries.firstIndex(where: { $0.bearerToken == candidate.bearerToken }) {
            guard candidate.expiresAt > entries[index].expiresAt else { return }
            entries[index] = candidate
        } else {
            guard entries.count < NativeServiceLimits.pendingRevocationRecords else {
                throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL")
            }
            entries.append(candidate)
            entries.sort { $0.bearerToken < $1.bearerToken }
        }
        try persistLocked(entries)
    }

    @discardableResult
    func stage(
        _ sessions: [NativeBearerSession],
        legacyDeletionAttempt: NativeAccountDeletionAttempt? = nil,
        now: Int
    ) throws -> Set<String> {
        var pendingByToken = try sessions.reduce(into: [String: NativePendingRevocation]()) {
            records, session in
            let pending = try NativePendingRevocation(session: session, now: now)
            if let existing = records[pending.bearerToken] {
                if pending.expiresAt > existing.expiresAt {
                    records[pending.bearerToken] = pending
                }
            } else {
                records[pending.bearerToken] = pending
            }
        }
        if let legacyDeletionAttempt {
            let pending = try NativePendingRevocation(
                legacyDeletionAttempt: legacyDeletionAttempt,
                now: now
            )
            if let existing = pendingByToken[pending.bearerToken] {
                if pending.expiresAt > existing.expiresAt {
                    pendingByToken[pending.bearerToken] = pending
                }
            } else {
                pendingByToken[pending.bearerToken] = pending
            }
        }
        lock.lock()
        defer { lock.unlock() }
        var entries = try loadLocked(now: now)
        let existingTokens = Set(entries.map(\.bearerToken))
        let additions = pendingByToken.values.filter { !existingTokens.contains($0.bearerToken) }
        guard entries.count + additions.count <= NativeServiceLimits.pendingRevocationRecords else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL")
        }
        var changed = !additions.isEmpty
        entries.append(contentsOf: additions.sorted { $0.bearerToken < $1.bearerToken })
        for (token, candidate) in pendingByToken where existingTokens.contains(token) {
            guard let index = entries.firstIndex(where: { $0.bearerToken == token }) else { continue }
            if candidate.expiresAt > entries[index].expiresAt {
                entries[index] = candidate
                changed = true
            }
        }
        if changed {
            try persistLocked(entries)
        }
        return Set(pendingByToken.keys)
    }

    func snapshot(now: Int) throws -> [NativePendingRevocation] {
        lock.lock()
        defer { lock.unlock() }
        return try loadLocked(now: now)
    }

    func status(now: Int = Int(Date().timeIntervalSince1970)) throws -> NativePendingRevocationStatus? {
        let entries = try snapshot(now: now)
        guard let expiresAt = entries.map(\.expiresAt).max() else { return nil }
        return NativePendingRevocationStatus(count: entries.count, expiresAt: expiresAt)
    }

    func remove(bearerToken: String, now: Int) throws {
        lock.lock()
        defer { lock.unlock() }
        let entries = try loadLocked(now: now)
        let retained = entries.filter { $0.bearerToken != bearerToken }
        guard retained.count != entries.count else { return }
        try persistLocked(retained)
    }

    func clearChecked() throws {
        lock.lock()
        defer { lock.unlock() }
        try clearLocked()
    }

    func blocksAdmission(bearerToken: String, now: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        do {
            guard let encoded = try read() else { return false }
            guard encoded.utf8.count <= NativeServiceLimits.pendingRevocationBytes,
                  let data = encoded.data(using: .utf8),
                  let queue = try? NativeJSON.decoder.decode(NativePendingRevocationQueue.self, from: data),
                  let entries = try? queue.validated(now: now) else { return true }
            return entries.contains {
                $0.bearerToken == bearerToken
            }
        } catch { return true }
    }

    func containsChecked(bearerToken: String, now: Int) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return try loadLocked(now: now).contains {
            $0.bearerToken == bearerToken
        }
    }

    func requireAdditionalCapacity(
        for sessions: [NativeBearerSession] = [],
        reservingUnknownRecords: Int = 1,
        now: Int
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        let entries = try loadLocked(now: now)
        guard (0...NativeServiceLimits.pendingRevocationRecords).contains(reservingUnknownRecords) else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        let existingTokens = Set(entries.map(\.bearerToken))
        let additionalTokens = Set(sessions.compactMap { session in
            session.mayHaveRevocableGrant(at: now) && !existingTokens.contains(session.token)
                ? session.token
                : nil
        })
        guard entries.count + additionalTokens.count + reservingUnknownRecords
                <= NativeServiceLimits.pendingRevocationRecords else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_FULL")
        }
    }

    private func loadLocked(now: Int) throws -> [NativePendingRevocation] {
        guard let encoded = try read() else { return [] }
        guard encoded.utf8.count <= NativeServiceLimits.pendingRevocationBytes,
              let data = encoded.data(using: .utf8),
              let queue = try? NativeJSON.decoder.decode(NativePendingRevocationQueue.self, from: data),
              let entries = try? queue.validated(now: now) else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        if entries != queue.entries { try persistLocked(entries) }
        return entries
    }

    private func persistLocked(_ entries: [NativePendingRevocation]) throws {
        guard !entries.isEmpty else { try clearLocked(); return }
        let encoded = String(decoding: try NativeJSON.encoder.encode(NativePendingRevocationQueue(entries: entries)), as: UTF8.self)
        guard encoded.utf8.count <= NativeServiceLimits.pendingRevocationBytes else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID")
        }
        try write(encoded)
        guard try read() == encoded else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_PERSISTENCE_FAILED")
        }
    }

    private func clearLocked() throws {
        try delete()
        guard try read() == nil else {
            throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_PERSISTENCE_FAILED")
        }
    }
}

enum NativeAccountBinding {
    static func hash(_ accountBinding: String) throws -> String {
        guard (1...1_000).contains(accountBinding.utf8.count) else {
            throw SandboxError.invalid("APPLE_ACCOUNT_BINDING_INVALID")
        }
        return NativeSecureRandom.base64URL(Data(SHA256.hash(data: Data(accountBinding.utf8))))
    }
}

private struct NativeLocalWorkspaceBindingRecord: Codable, Equatable {
    let schemaVersion: Int
    let accountBindingHash: String
    let directoryName: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, accountBindingHash, directoryName
    }

    init(accountBindingHash: String, directoryName: String) {
        schemaVersion = 1
        self.accountBindingHash = accountBindingHash
        self.directoryName = directoryName
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        accountBindingHash = try container.decode(String.self, forKey: .accountBindingHash)
        directoryName = try container.decode(String.self, forKey: .directoryName)
    }

    func validated() throws -> Self {
        guard schemaVersion == 1,
              accountBindingHash.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              directoryName.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else {
            throw SandboxError.blocked("LOCAL_WORKSPACE_BINDING_INVALID")
        }
        return self
    }

    func validated(accountBinding: String) throws -> Self {
        let record = try validated()
        guard record.accountBindingHash == (try NativeAccountBinding.hash(accountBinding)) else {
            throw SandboxError.blocked("LOCAL_WORKSPACE_BINDING_CONFLICT")
        }
        return record
    }
}

struct NativeLocalWorkspaceBindingVault: @unchecked Sendable {
    private static let storageKey = "appleLocalWorkspaceBinding.v1"
    let read: () throws -> String?
    let write: (String) throws -> Void
    let delete: () throws -> Void

    static let live = NativeLocalWorkspaceBindingVault(
        read: { try Keychain.getChecked(storageKey) },
        write: { try Keychain.set($0, for: storageKey) },
        delete: { try Keychain.deleteChecked(storageKey) }
    )

    func directoryName(accountBinding: String) throws -> String {
        if let record = try loadRecord() {
            return try record.validated(accountBinding: accountBinding).directoryName
        }
        let record = try NativeLocalWorkspaceBindingRecord(
            accountBindingHash: NativeAccountBinding.hash(accountBinding),
            directoryName: NativeDigest.sha256(accountBinding)
        ).validated()
        try save(record)
        return record.directoryName
    }

    func validateAccountBindingMigration(from oldUser: String, to newUser: String) throws -> String {
        guard try NativeAccountBinding.hash(oldUser) != NativeAccountBinding.hash(newUser) else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_INVALID")
        }
        return try directoryName(accountBinding: oldUser)
    }

    func migrateAccountBinding(
        from oldUser: String,
        to newUser: String,
        expectedDirectoryName: String,
        allowAlreadyMigrated: Bool
    ) throws {
        let oldHash = try NativeAccountBinding.hash(oldUser)
        let newHash = try NativeAccountBinding.hash(newUser)
        guard oldHash != newHash,
              expectedDirectoryName.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              let current = try loadRecord(),
              current.directoryName == expectedDirectoryName else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
        }
        if current.accountBindingHash == newHash {
            guard allowAlreadyMigrated else {
                throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
            }
            return
        }
        guard current.accountBindingHash == oldHash else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
        }
        try save(NativeLocalWorkspaceBindingRecord(
            accountBindingHash: newHash,
            directoryName: expectedDirectoryName
        ))
    }

    func clearChecked() throws {
        try delete()
        guard try read() == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
    }

    private func loadRecord() throws -> NativeLocalWorkspaceBindingRecord? {
        guard let encoded = try read() else { return nil }
        guard encoded.utf8.count <= 512,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("LOCAL_WORKSPACE_BINDING_INVALID")
        }
        do {
            return try NativeJSON.decoder.decode(NativeLocalWorkspaceBindingRecord.self, from: data)
                .validated()
        } catch {
            throw SandboxError.blocked("LOCAL_WORKSPACE_BINDING_INVALID")
        }
    }

    private func save(_ record: NativeLocalWorkspaceBindingRecord) throws {
        let validated = try record.validated()
        let encoded = String(decoding: try NativeJSON.encoder.encode(validated), as: UTF8.self)
        try write(encoded)
        guard try loadRecord() == validated else {
            throw SandboxError.blocked("LOCAL_WORKSPACE_BINDING_PERSISTENCE_FAILED")
        }
    }
}

private struct NativeAppleAccountModeRecord: Codable, Equatable {
    let schemaVersion: Int
    let accountBindingHash: String
    let accountMode: NativeAppleAccountMode

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, accountBindingHash, accountMode
    }

    init(accountBindingHash: String, accountMode: NativeAppleAccountMode) {
        schemaVersion = 1
        self.accountBindingHash = accountBindingHash
        self.accountMode = accountMode
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        accountBindingHash = try container.decode(String.self, forKey: .accountBindingHash)
        accountMode = try container.decode(NativeAppleAccountMode.self, forKey: .accountMode)
    }

    func validated(accountBinding: String) throws -> Self {
        guard schemaVersion == 1,
              accountBindingHash.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              accountBindingHash == (try NativeAccountBinding.hash(accountBinding)) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_MODE_INVALID")
        }
        return self
    }
}

struct NativeAppleAccountModeVault: @unchecked Sendable {
    let read: () throws -> String?
    let write: (String) throws -> Void
    let delete: () throws -> Void

    static let live = NativeAppleAccountModeVault(
        read: { try Keychain.getChecked("appleAccountMode.v1") },
        write: { try Keychain.set($0, for: "appleAccountMode.v1") },
        delete: { try Keychain.deleteChecked("appleAccountMode.v1") }
    )

    func load(accountBinding: String) throws -> NativeAppleAccountMode? {
        guard let encoded = try read() else { return nil }
        guard encoded.utf8.count <= 512, let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_MODE_INVALID")
        }
        do {
            let record = try NativeJSON.decoder.decode(NativeAppleAccountModeRecord.self, from: data)
            return try record.validated(accountBinding: accountBinding).accountMode
        } catch {
            throw SandboxError.blocked("APPLE_ACCOUNT_MODE_INVALID")
        }
    }

    func save(_ accountMode: NativeAppleAccountMode, accountBinding: String) throws {
        let record = NativeAppleAccountModeRecord(
            accountBindingHash: try NativeAccountBinding.hash(accountBinding),
            accountMode: accountMode
        )
        try write(String(decoding: NativeJSON.encoder.encode(record), as: UTF8.self))
        guard try load(accountBinding: accountBinding) == accountMode else {
            throw SandboxError.blocked("APPLE_ACCOUNT_MODE_PERSISTENCE_FAILED")
        }
    }

    func clear() { try? delete() }

    func clearChecked() throws {
        try delete()
        guard try read() == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
    }
}

struct NativeAccountDeletionAttempt: Codable, Equatable {
    let schemaVersion: Int
    let accountBindingHash: String
    let idempotencyKey: String
    let bearerToken: String
    let bearerExpiresAt: Int
    let accountMode: NativeAppleAccountMode
    let requiresReauthentication: Bool
    let createdAt: Int
    let expiresAt: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, accountBindingHash, idempotencyKey, bearerToken, bearerExpiresAt, accountMode
        case requiresReauthentication, createdAt, expiresAt
    }

    init(
        schemaVersion: Int = 3,
        accountBindingHash: String,
        idempotencyKey: String,
        bearerToken: String,
        bearerExpiresAt: Int? = nil,
        accountMode: NativeAppleAccountMode,
        requiresReauthentication: Bool = false,
        createdAt: Int,
        expiresAt: Int
    ) {
        self.schemaVersion = schemaVersion
        self.accountBindingHash = accountBindingHash
        self.idempotencyKey = idempotencyKey
        self.bearerToken = bearerToken
        self.bearerExpiresAt = bearerExpiresAt ?? (
            createdAt <= Int.max - NativeServiceLimits.bearerLifetimeSeconds
                ? createdAt + NativeServiceLimits.bearerLifetimeSeconds
                : Int.max
        )
        self.accountMode = accountMode
        self.requiresReauthentication = requiresReauthentication
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedSchemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        schemaVersion = decodedSchemaVersion
        let expectedKeys = Set(CodingKeys.allCases
            .filter { decodedSchemaVersion != 2 || $0 != .bearerExpiresAt }
            .map(\.rawValue))
        try requireExactKeys(decoder, expected: expectedKeys)
        accountBindingHash = try container.decode(String.self, forKey: .accountBindingHash)
        idempotencyKey = try container.decode(String.self, forKey: .idempotencyKey)
        bearerToken = try container.decode(String.self, forKey: .bearerToken)
        accountMode = try container.decode(NativeAppleAccountMode.self, forKey: .accountMode)
        requiresReauthentication = try container.decode(Bool.self, forKey: .requiresReauthentication)
        createdAt = try container.decode(Int.self, forKey: .createdAt)
        expiresAt = try container.decode(Int.self, forKey: .expiresAt)
        if schemaVersion == 2 {
            guard createdAt <= Int.max - NativeServiceLimits.bearerLifetimeSeconds else {
                throw DecodingError.dataCorruptedError(
                    forKey: .createdAt,
                    in: container,
                    debugDescription: "Legacy deletion attempt time is out of range."
                )
            }
            bearerExpiresAt = createdAt + NativeServiceLimits.bearerLifetimeSeconds
        } else {
            bearerExpiresAt = try container.decode(Int.self, forKey: .bearerExpiresAt)
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(accountBindingHash, forKey: .accountBindingHash)
        try container.encode(idempotencyKey, forKey: .idempotencyKey)
        try container.encode(bearerToken, forKey: .bearerToken)
        if schemaVersion != 2 {
            try container.encode(bearerExpiresAt, forKey: .bearerExpiresAt)
        }
        try container.encode(accountMode, forKey: .accountMode)
        try container.encode(requiresReauthentication, forKey: .requiresReauthentication)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(expiresAt, forKey: .expiresAt)
    }

    func structurallyValidated() throws -> Self {
        guard [2, 3].contains(schemaVersion),
              accountBindingHash.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
              NativeAccountDeletionKey.valid(idempotencyKey),
              NativeBearerSession.validToken(bearerToken),
              createdAt > 0,
              createdAt <= Int.max - NativeServiceLimits.accountDeletionAttemptLifetimeSeconds,
              expiresAt == createdAt + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds,
              expiresAt <= Int.max - NativeServiceLimits.bearerLifetimeSeconds
                - NativeServiceLimits.nativeResponseClockSkewSeconds,
              bearerExpiresAt > createdAt,
              bearerExpiresAt <= expiresAt + NativeServiceLimits.bearerLifetimeSeconds
                + NativeServiceLimits.nativeResponseClockSkewSeconds,
              (schemaVersion != 2
                || bearerExpiresAt == createdAt + NativeServiceLimits.bearerLifetimeSeconds) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        return self
    }

    func validated(now: Int) throws -> Self {
        let attempt = try structurallyValidated()
        guard attempt.expiresAt > now else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        return attempt
    }

    func retirementSession(now: Int) throws -> NativeBearerSession {
        let attempt = try structurallyValidated()
        guard now > 0,
              now <= Int.max - NativeServiceLimits.bearerLifetimeSeconds else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        // Legacy v2 did not retain the replacement bearer expiry. Treat that timing as
        // ambiguous and conservatively reserve the full grant window from this discard.
        let retirementBearerExpiry = attempt.schemaVersion == 2
            ? now + NativeServiceLimits.bearerLifetimeSeconds
            : attempt.bearerExpiresAt
        return NativeBearerSession(
            schemaVersion: 1,
            tokenType: "Bearer",
            token: attempt.bearerToken,
            expiresAt: retirementBearerExpiry,
            accountMode: attempt.accountMode
        )
    }

    func belongs(to accountBinding: String) throws -> Bool {
        accountBindingHash == (try NativeAccountBinding.hash(accountBinding))
    }
}

struct NativeAccountDeletionAttemptVault: @unchecked Sendable {
    let read: (String) throws -> String?
    let write: (String, String) throws -> Void
    let delete: (String) throws -> Void
    let random: (Int) throws -> Data

    static let live = NativeAccountDeletionAttemptVault(
        read: { try Keychain.getChecked($0) },
        write: { key, value in try Keychain.set(value, for: key) },
        delete: { try Keychain.deleteChecked($0) },
        random: NativeSecureRandom.bytes
    )

    init(
        read: @escaping (String) throws -> String?,
        write: @escaping (String, String) throws -> Void,
        delete: @escaping (String) throws -> Void,
        random: @escaping (Int) throws -> Data = NativeSecureRandom.bytes
    ) {
        self.read = read
        self.write = write
        self.delete = delete
        self.random = random
    }

    private static let storageKey = "appleAccountDeletionAttempt.v2"

    func hasPending() -> Bool {
        do { return try read(Self.storageKey) != nil }
        catch { return true }
    }

    func hasPending(accountBinding: String, now: Int = Int(Date().timeIntervalSince1970)) -> Bool {
        do {
            guard let attempt = try load(now: now) else { return false }
            return try attempt.belongs(to: accountBinding)
        } catch {
            return true
        }
    }

    func load(now: Int = Int(Date().timeIntervalSince1970)) throws -> NativeAccountDeletionAttempt? {
        try load(storageKey: Self.storageKey, now: now)
    }

    func loadForRetirement() throws -> NativeAccountDeletionAttempt? {
        guard let encoded = try read(Self.storageKey) else { return nil }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8),
              let attempt = try? NativeJSON.decoder.decode(
                NativeAccountDeletionAttempt.self,
                from: data
              ).structurallyValidated() else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        return attempt
    }

    func load(
        accountBinding: String,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeAccountDeletionAttempt? {
        guard let attempt = try load(now: now) else { return nil }
        guard try attempt.belongs(to: accountBinding) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_ACCOUNT_MISMATCH")
        }
        return attempt
    }

    func attempt(
        accountBinding: String,
        bearer: NativeBearerSession,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeAccountDeletionAttempt {
        if let existing = try load(accountBinding: accountBinding, now: now) { return existing }
        guard now > 0,
              now <= Int.max - NativeServiceLimits.accountDeletionAttemptLifetimeSeconds else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        let created = try NativeAccountDeletionAttempt(
            accountBindingHash: NativeAccountBinding.hash(accountBinding),
            idempotencyKey: NativeAccountDeletionKey.make(using: random),
            bearerToken: bearer.token,
            bearerExpiresAt: bearer.expiresAt,
            accountMode: bearer.accountMode,
            createdAt: now,
            expiresAt: now + NativeServiceLimits.accountDeletionAttemptLifetimeSeconds
        ).validated(now: now)
        try write(Self.storageKey, String(decoding: NativeJSON.encoder.encode(created), as: UTF8.self))
        guard try load(storageKey: Self.storageKey, now: now) == created else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_PERSISTENCE_FAILED")
        }
        return created
    }

    func requireReauthentication(now: Int = Int(Date().timeIntervalSince1970)) throws {
        guard let current = try load(now: now) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        let updated = NativeAccountDeletionAttempt(
            schemaVersion: current.schemaVersion,
            accountBindingHash: current.accountBindingHash,
            idempotencyKey: current.idempotencyKey,
            bearerToken: current.bearerToken,
            bearerExpiresAt: current.bearerExpiresAt,
            accountMode: current.accountMode,
            requiresReauthentication: true,
            createdAt: current.createdAt,
            expiresAt: current.expiresAt
        )
        try write(Self.storageKey, String(decoding: NativeJSON.encoder.encode(updated), as: UTF8.self))
        guard try load(now: now) == updated else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_PERSISTENCE_FAILED")
        }
    }

    func replaceBearer(
        accountBinding: String,
        bearer: NativeBearerSession,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws {
        guard let current = try load(accountBinding: accountBinding, now: now),
              current.requiresReauthentication,
              bearer.accountMode == current.accountMode else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_REAUTHENTICATION_INVALID")
        }
        _ = try bearer.validated(now: now)
        let updated = NativeAccountDeletionAttempt(
            accountBindingHash: current.accountBindingHash,
            idempotencyKey: current.idempotencyKey,
            bearerToken: bearer.token,
            bearerExpiresAt: bearer.expiresAt,
            accountMode: current.accountMode,
            requiresReauthentication: false,
            createdAt: current.createdAt,
            expiresAt: current.expiresAt
        )
        try write(Self.storageKey, String(decoding: NativeJSON.encoder.encode(updated), as: UTF8.self))
        guard try load(accountBinding: accountBinding, now: now) == updated else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_PERSISTENCE_FAILED")
        }
    }

    func clear() { try? delete(Self.storageKey) }

    func clearChecked() throws {
        try delete(Self.storageKey)
        guard try read(Self.storageKey) == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
    }

    private func load(storageKey: String, now: Int) throws -> NativeAccountDeletionAttempt? {
        guard let encoded = try read(storageKey) else { return nil }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
        do {
            return try NativeJSON.decoder.decode(NativeAccountDeletionAttempt.self, from: data)
                .validated(now: now)
        } catch {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_INVALID")
        }
    }
}

enum NativeAccountDeletionRecoveryState: Equatable {
    case none
    case recoverable(NativeAccountDeletionAttempt)
    case requiresExplicitDiscard
}

struct NativeAccountDeletionOutcome: Codable, Equatable {
    let schemaVersion: Int
    let accountBindingHash: String
    let accountMode: NativeAppleAccountMode
    let manualRevocationRequired: Bool
    let manualOriginRevocationRequired: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, accountBindingHash, accountMode, manualRevocationRequired
        case manualOriginRevocationRequired
    }

    init(
        schemaVersion: Int = 2,
        accountBindingHash: String,
        accountMode: NativeAppleAccountMode,
        manualRevocationRequired: Bool,
        manualOriginRevocationRequired: Bool
    ) {
        self.schemaVersion = schemaVersion
        self.accountBindingHash = accountBindingHash
        self.accountMode = accountMode
        self.manualRevocationRequired = manualRevocationRequired
        self.manualOriginRevocationRequired = manualOriginRevocationRequired
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        accountBindingHash = try container.decode(String.self, forKey: .accountBindingHash)
        accountMode = try container.decode(NativeAppleAccountMode.self, forKey: .accountMode)
        manualRevocationRequired = try container.decode(Bool.self, forKey: .manualRevocationRequired)
        manualOriginRevocationRequired = try container.decode(
            Bool.self,
            forKey: .manualOriginRevocationRequired
        )
    }

    func validated() throws -> Self {
        guard schemaVersion == 2,
              NativeAccountDeletionKey.valid("v1.\(accountBindingHash)") else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_OUTCOME_INVALID")
        }
        return self
    }
}

struct NativeAccountDeletionOutcomeVault: @unchecked Sendable {
    let read: () throws -> String?
    let write: (String) throws -> Void
    let delete: () throws -> Void

    static let live = NativeAccountDeletionOutcomeVault(
        read: { try Keychain.getChecked("appleAccountDeletionOutcome.v1") },
        write: { try Keychain.set($0, for: "appleAccountDeletionOutcome.v1") },
        delete: { try Keychain.deleteChecked("appleAccountDeletionOutcome.v1") }
    )

    func load() throws -> NativeAccountDeletionOutcome? {
        guard let encoded = try read() else { return nil }
        guard encoded.utf8.count <= 512, let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_OUTCOME_INVALID")
        }
        do {
            return try NativeJSON.decoder.decode(NativeAccountDeletionOutcome.self, from: data)
                .validated()
        } catch {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_OUTCOME_INVALID")
        }
    }

    func save(_ outcome: NativeAccountDeletionOutcome) throws {
        let validated = try outcome.validated()
        try write(String(decoding: NativeJSON.encoder.encode(validated), as: UTF8.self))
        guard try load() == validated else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_OUTCOME_PERSISTENCE_FAILED")
        }
    }

    func clearChecked() throws {
        try delete()
        guard try read() == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
    }
}

struct NativeAccountDeletionCompletionRecovery: @unchecked Sendable {
    let outcomeVault: NativeAccountDeletionOutcomeVault

    func record(_ outcome: NativeAccountDeletionOutcome) throws {
        try outcomeVault.save(outcome)
    }

    func resume(
        scrub: (NativeAccountDeletionOutcome) throws -> Void,
        finalizeTransaction: () throws -> Void
    ) throws -> NativeAccountDeletionOutcome? {
        guard let outcome = try outcomeVault.load() else { return nil }
        try scrub(outcome)
        try finalizeTransaction()
        return outcome
    }
}

struct NativeLocalProfileCredentialScrubber: @unchecked Sendable {
    let bearerVault: NativeBearerVault
    let accountModeVault: NativeAppleAccountModeVault
    let workspaceBindingVault: NativeLocalWorkspaceBindingVault
    let recoveryVault: NativeRecoverySecretVault
    let read: (String) throws -> String?
    let write: (String, String) throws -> Void
    let delete: (String) throws -> Void

    static let live = NativeLocalProfileCredentialScrubber(
        bearerVault: .live,
        accountModeVault: .live,
        workspaceBindingVault: .live,
        recoveryVault: .live,
        read: { try Keychain.getChecked($0) },
        write: { key, value in try Keychain.set(value, for: key) },
        delete: { try Keychain.deleteChecked($0) }
    )

    init(
        bearerVault: NativeBearerVault,
        accountModeVault: NativeAppleAccountModeVault,
        workspaceBindingVault: NativeLocalWorkspaceBindingVault = .live,
        recoveryVault: NativeRecoverySecretVault = .live,
        read: @escaping (String) throws -> String?,
        write: @escaping (String, String) throws -> Void,
        delete: @escaping (String) throws -> Void
    ) {
        self.bearerVault = bearerVault
        self.accountModeVault = accountModeVault
        self.workspaceBindingVault = workspaceBindingVault
        self.recoveryVault = recoveryVault
        self.read = read
        self.write = write
        self.delete = delete
    }

    func scrubNonIdentity(
        accountBindingHash: String? = nil,
        includeRecoverySecrets: Bool = false,
        preserveBearer: Bool = false
    ) throws {
        if includeRecoverySecrets {
            guard let accountBindingHash else {
                throw SandboxError.blocked("WORKSPACE_RECOVERY_SCOPE_REQUIRED")
            }
            try recoveryVault.scrub(accountBindingHash: accountBindingHash)
        }
        try workspaceBindingVault.clearChecked()
        for key in ["openaiKey", "openaiModel", "githubToken"] {
            try delete(key)
            guard try read(key) == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
        }
        try accountModeVault.clearChecked()
        if !preserveBearer { try bearerVault.clearChecked() }
    }

    func clearIdentity() throws {
        guard let retainedIdentity = try read("appleUser") else { return }
        do {
            try delete("appleUser")
            guard try read("appleUser") == nil else {
                throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
            }
        } catch {
            let deletionError = error
            do {
                try write("appleUser", retainedIdentity)
                guard try read("appleUser") == retainedIdentity else {
                    throw SandboxError.blocked("APPLE_USER_IDENTITY_RECOVERY_REQUIRED")
                }
            } catch {
                throw SandboxError.blocked("APPLE_USER_IDENTITY_RECOVERY_REQUIRED")
            }
            throw deletionError
        }
    }

    func scrub(
        accountBindingHash: String? = nil,
        includeRecoverySecrets: Bool = false,
        preserveBearer: Bool = false
    ) throws {
        try scrubNonIdentity(
            accountBindingHash: accountBindingHash,
            includeRecoverySecrets: includeRecoverySecrets,
            preserveBearer: preserveBearer
        )
        try clearIdentity()
    }
}

struct NativeAppleAuthAPI: Sendable {
    let endpoints: NativeServiceEndpoints
    let transport: NativeHTTPPerforming
    private let clock: @Sendable () -> Int

    init(
        endpoints: NativeServiceEndpoints = try! NativeServiceEndpoints(),
        transport: NativeHTTPPerforming = NativeURLSessionTransport(),
        clock: @escaping @Sendable () -> Int = {
            Int(Date().timeIntervalSince1970)
        }
    ) {
        self.endpoints = endpoints
        self.transport = transport
        self.clock = clock
    }

    private func responseTime() -> Int { clock() }

    func exchange(
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        transferRecoveryUser: String? = nil,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeReceived<NativeApplePendingSessionResponse> {
        let request = try NativeRequestFactory.exchange(
            endpoints: endpoints,
            identityToken: identityToken,
            authorizationCode: authorizationCode,
            rawNonce: rawNonce,
            transferRecoveryUser: transferRecoveryUser
        )
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes)
        let receivedAt = responseTime()
        guard (200...299).contains(result.response.statusCode) else {
            try NativeJSON.requireJSONSuccessContentType(result)
            return NativeReceived(
                value: try NativeJSON.decode(
                    NativeApplePendingSessionResponse.self,
                    from: result,
                    maximumBytes: NativeServiceLimits.exchangeResponseBytes
                ).validated(now: receivedAt),
                receivedAt: receivedAt
            )
        }
        let recoveryToken = NativeAppleExchangeRecoveryEnvelope.token(from: result.data)
        do {
            try NativeJSON.requireJSONSuccessContentType(result)
            let decoded = try NativeJSON.decode(
                NativeApplePendingSessionResponse.self,
                from: result,
                maximumBytes: NativeServiceLimits.exchangeResponseBytes
            )
            let structural = try decoded.structurallyValidated()
            return NativeReceived(
                value: try structural.validated(now: receivedAt),
                receivedAt: receivedAt
            )
        } catch {
            guard let recoveryToken,
                  receivedAt <= NativeServiceLimits.maximumSafeInteger
                    - NativeServiceLimits.bearerLifetimeSeconds
                    - NativeServiceLimits.nativeResponseClockSkewSeconds else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
            }
            let recoverySession = NativeBearerSession(
                schemaVersion: 1,
                tokenType: "Bearer",
                token: recoveryToken,
                expiresAt: receivedAt + NativeServiceLimits.bearerLifetimeSeconds
                    + NativeServiceLimits.nativeResponseClockSkewSeconds,
                accountMode: .standalone
            )
            throw NativeAppleSessionResponseRejected(
                session: recoverySession,
                receivedAt: receivedAt,
                code: error.localizedDescription,
                observedResponseToken: recoverySession.token
            )
        }
    }

    func activate(
        pending: NativeApplePendingSessionResponse,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeReceived<NativeBearerSession> {
        let expected = try pending.structurallyValidated()
        let request = try NativeRequestFactory.activate(endpoints: endpoints, bearer: expected.token)
        let result = try await transport.perform(
            request,
            maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes
        )
        let receivedAt = responseTime()
        try NativeJSON.requireJSONSuccessContentType(result)
        let decoded = try NativeJSON.decode(
            NativeAppleActiveSessionResponse.self,
            from: result,
            maximumBytes: NativeServiceLimits.exchangeResponseBytes
        )
        let structural = try decoded.retirementBearer()
        do {
            return NativeReceived(
                value: try decoded.localBearer(matching: expected, now: receivedAt),
                receivedAt: receivedAt
            )
        } catch {
            throw NativeAppleSessionResponseRejected(
                session: structural,
                receivedAt: receivedAt,
                code: error.localizedDescription
            )
        }
    }

    func refresh(
        bearer: String,
        accountMode: NativeAppleAccountMode,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeReceived<NativeBearerSession> {
        let request = try NativeRequestFactory.refresh(endpoints: endpoints, bearer: bearer)
        var sampledAt: Int?
        do {
            let result = try await transport.perform(
                request,
                maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes
            )
            let receivedAt = responseTime()
            sampledAt = receivedAt
            try NativeJSON.requireJSONSuccessContentType(result)
            let decoded = try NativeJSON.decode(
                NativeAppleActiveSessionResponse.self,
                from: result,
                maximumBytes: NativeServiceLimits.exchangeResponseBytes
            )
            let structural = try decoded.retirementBearer()
            do {
                let refreshed = try structural.validated(now: receivedAt)
                guard refreshed.token == bearer,
                      refreshed.accountMode == accountMode else {
                    throw SandboxError.blocked("APPLE_NATIVE_REFRESH_TOKEN_CHANGED")
                }
                return NativeReceived(value: refreshed, receivedAt: receivedAt)
            } catch {
                throw NativeAppleSessionResponseRejected(
                    session: NativeBearerSession(
                        schemaVersion: 1,
                        tokenType: "Bearer",
                        token: bearer,
                        expiresAt: max(
                            structural.expiresAt,
                            receivedAt + NativeServiceLimits.bearerLifetimeSeconds
                                + NativeServiceLimits.nativeResponseClockSkewSeconds
                        ),
                        accountMode: accountMode
                    ),
                    receivedAt: receivedAt,
                    code: error.localizedDescription,
                    observedResponseToken: structural.token
                )
            }
        } catch let rejected as NativeAppleSessionResponseRejected {
            throw rejected
        } catch {
            let receivedAt = sampledAt ?? responseTime()
            guard receivedAt > 0,
                  receivedAt <= NativeServiceLimits.maximumSafeInteger
                    - NativeServiceLimits.bearerLifetimeSeconds
                    - NativeServiceLimits.nativeResponseClockSkewSeconds else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
            }
            throw NativeAppleSessionResponseRejected(
                session: NativeBearerSession(
                    schemaVersion: 1,
                    tokenType: "Bearer",
                    token: bearer,
                    expiresAt: receivedAt + NativeServiceLimits.bearerLifetimeSeconds
                        + NativeServiceLimits.nativeResponseClockSkewSeconds,
                    accountMode: accountMode
                ),
                receivedAt: receivedAt,
                code: error.localizedDescription
            )
        }
    }

    func revoke(bearer: String) async throws {
        let request = try NativeRequestFactory.revoke(endpoints: endpoints, bearer: bearer)
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.exchangeResponseBytes)
        let response = try NativeJSON.decode(NativeRevokeResponse.self, from: result, maximumBytes: NativeServiceLimits.exchangeResponseBytes)
        guard response.revoked else { throw SandboxError.blocked("APPLE_NATIVE_REVOKE_FAILED") }
    }

    func possibleCredentialReview(bearer: String) async throws -> NativeAppleCredentialReview {
        let request = try NativeRequestFactory.possibleCredentialReview(
            endpoints: endpoints,
            bearer: bearer
        )
        let result = try await transport.perform(
            request,
            maximumResponseBytes: NativeServiceLimits.credentialReviewResponseBytes
        )
        try NativeJSON.requireJSONSuccessContentType(result)
        return try NativeJSON.decode(
            NativeAppleCredentialReview.self,
            from: result,
            maximumBytes: NativeServiceLimits.credentialReviewResponseBytes
        )
    }

    func acknowledgePossibleCredentialReview(
        bearer: String,
        acknowledgementID: NativeAppleCredentialReviewAcknowledgementID
    ) async throws {
        let request = try NativeRequestFactory.acknowledgePossibleCredentialReview(
            endpoints: endpoints,
            bearer: bearer,
            acknowledgementID: acknowledgementID
        )
        let result = try await transport.perform(
            request,
            maximumResponseBytes: NativeServiceLimits.credentialReviewResponseBytes
        )
        try NativeJSON.requireJSONSuccessContentType(result)
        _ = try NativeJSON.decode(
            NativeAppleCredentialReviewAcknowledgement.self,
            from: result,
            maximumBytes: NativeServiceLimits.credentialReviewResponseBytes
        )
    }

    func deleteAccount(bearer: String, idempotencyKey: String) async throws -> NativeAccountDeletionResponse {
        let request = try NativeRequestFactory.deleteAccount(
            endpoints: endpoints,
            bearer: bearer,
            idempotencyKey: idempotencyKey
        )
        let result = try await transport.perform(
            request,
            maximumResponseBytes: NativeServiceLimits.accountDeletionResponseBytes
        )
        let contentType = result.response.value(forHTTPHeaderField: "Content-Type")?
            .split(separator: ";", maxSplits: 1).first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard contentType == "application/json" else {
            throw SandboxError.blocked("NATIVE_SERVICE_RESPONSE_INVALID")
        }
        return try NativeJSON.decode(
            NativeAccountDeletionResponse.self,
            from: result,
            maximumBytes: NativeServiceLimits.accountDeletionResponseBytes
        )
    }
}

private struct NativeRevokeResponse: Decodable { let revoked: Bool }

private struct NativeAnyCodingKey: CodingKey, Hashable {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) { self.stringValue = stringValue;intValue = nil }
    init?(intValue: Int) { self.stringValue = String(intValue);self.intValue = intValue }
}

private func requireExactKeys(_ decoder: Decoder, expected: Set<String>) throws {
    let container = try decoder.container(keyedBy: NativeAnyCodingKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else {
        throw DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "The response contains missing or unknown fields."
        ))
    }
}

private struct NativeAppleCredentialReviewAcknowledgement: Decodable {
    let acknowledged: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case acknowledged
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        acknowledged = try container.decode(Bool.self, forKey: .acknowledged)
        guard acknowledged else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "The server did not confirm Apple credential review."
            ))
        }
    }
}

struct NativeAccountDeletionProviderCredentials: Decodable, Equatable {
    let credentialsFound: Int
    let credentialsRevoked: Int
    let unreadableSessions: Int
    let failedRevocations: Int
    let manualRevocationRequired: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case credentialsFound, credentialsRevoked, unreadableSessions
        case failedRevocations, manualRevocationRequired
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        credentialsFound = try container.decode(Int.self, forKey: .credentialsFound)
        credentialsRevoked = try container.decode(Int.self, forKey: .credentialsRevoked)
        unreadableSessions = try container.decode(Int.self, forKey: .unreadableSessions)
        failedRevocations = try container.decode(Int.self, forKey: .failedRevocations)
        manualRevocationRequired = try container.decode(Bool.self, forKey: .manualRevocationRequired)
        guard credentialsFound >= 0, credentialsRevoked >= 0, unreadableSessions >= 0,
              failedRevocations >= 0, credentialsRevoked <= credentialsFound,
              failedRevocations == credentialsFound - credentialsRevoked,
              manualRevocationRequired == (
                credentialsFound == 0 || unreadableSessions > 0 || failedRevocations > 0
              ) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "The provider revocation summary is inconsistent."
            ))
        }
    }
}

struct NativeAccountDeletionOriginConnections: Decodable, Equatable {
    let installationsFound: Int
    let installationsRevoked: Int
    let unreadableInstallations: Int
    let failedRevocations: Int
    let manualRevocationRequired: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case installationsFound, installationsRevoked, unreadableInstallations
        case failedRevocations, manualRevocationRequired
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        installationsFound = try container.decode(Int.self, forKey: .installationsFound)
        installationsRevoked = try container.decode(Int.self, forKey: .installationsRevoked)
        unreadableInstallations = try container.decode(Int.self, forKey: .unreadableInstallations)
        failedRevocations = try container.decode(Int.self, forKey: .failedRevocations)
        manualRevocationRequired = try container.decode(Bool.self, forKey: .manualRevocationRequired)
        guard installationsFound >= 0, installationsRevoked >= 0,
              unreadableInstallations >= 0, failedRevocations >= 0,
              installationsFound == installationsRevoked
                + unreadableInstallations + failedRevocations,
              manualRevocationRequired == (
                unreadableInstallations > 0 || failedRevocations > 0
              ) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "The Origin revocation summary is inconsistent."
            ))
        }
    }
}

struct NativeAccountDeletionResponse: Decodable, Equatable {
    let deleted: Bool
    let idempotent: Bool
    let providerCredentials: NativeAccountDeletionProviderCredentials
    let originConnections: NativeAccountDeletionOriginConnections

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case deleted, idempotent, providerCredentials, originConnections
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        deleted = try container.decode(Bool.self, forKey: .deleted)
        idempotent = try container.decode(Bool.self, forKey: .idempotent)
        providerCredentials = try container.decode(
            NativeAccountDeletionProviderCredentials.self,
            forKey: .providerCredentials
        )
        originConnections = try container.decode(
            NativeAccountDeletionOriginConnections.self,
            forKey: .originConnections
        )
        guard deleted else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "The server did not confirm account deletion."
            ))
        }
    }
}

private final class NativeAppleActivationGenerationLease: @unchecked Sendable {
    private let lock = NSLock()
    private var generation: UInt64

    init(_ generation: UInt64) { self.generation = generation }

    func adopt(_ generation: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        if generation > self.generation { self.generation = generation }
    }

    func current() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return generation
    }
}

private actor NativeAppleActivationSingleFlight {
    private struct Flight {
        let id: UUID
        let context: NativeAppleActivationContext
        let generationLease: NativeAppleActivationGenerationLease
        let task: Task<NativeReceived<NativeBearerSession>, Error>
    }

    private var flight: Flight?

    func run(
        context: NativeAppleActivationContext,
        persistenceGeneration: UInt64,
        operation: @escaping @Sendable (NativeAppleActivationGenerationLease) async throws -> NativeReceived<NativeBearerSession>
    ) async throws -> NativeReceived<NativeBearerSession> {
        if let flight {
            guard flight.context == context else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_MISMATCH")
            }
            flight.generationLease.adopt(persistenceGeneration)
            do {
                let result = try await flight.task.value
                if self.flight?.id == flight.id { self.flight = nil }
                return result
            } catch {
                if self.flight?.id == flight.id { self.flight = nil }
                throw error
            }
        }
        let id = UUID()
        let generationLease = NativeAppleActivationGenerationLease(persistenceGeneration)
        let task = Task { try await operation(generationLease) }
        flight = Flight(
            id: id,
            context: context,
            generationLease: generationLease,
            task: task
        )
        do {
            let result = try await task.value
            if flight?.id == id { flight = nil }
            return result
        } catch {
            if flight?.id == id { flight = nil }
            throw error
        }
    }
}

struct NativeCapturedAppleSessions: Equatable, Sendable {
    let sessions: [NativeBearerSession]
}

struct NativePreparedAppleSessionRetirement: Equatable, Sendable {
    let sessions: [NativeBearerSession]
    let durablyStagedBearerTokens: Set<String>
}

struct NativeAppleAuthController: @unchecked Sendable {
    let api: NativeAppleAuthAPI
    let vault: NativeBearerVault
    let deletionVault: NativeAccountDeletionAttemptVault
    let pendingRevocationVault: NativePendingRevocationVault
    let pendingActivationVault: NativePendingActivationVault
    private let persistenceGate: NativeAppleAuthPersistenceGate
    private let activationSingleFlight: NativeAppleActivationSingleFlight

    static let live = NativeAppleAuthController(
        api: NativeAppleAuthAPI(),
        vault: .live,
        deletionVault: .live,
        pendingRevocationVault: .live,
        pendingActivationVault: .live
    )

    init(
        api: NativeAppleAuthAPI,
        vault: NativeBearerVault,
        deletionVault: NativeAccountDeletionAttemptVault = .live,
        pendingRevocationVault: NativePendingRevocationVault = .transient(),
        pendingActivationVault: NativePendingActivationVault = .transient()
    ) {
        self.api = api
        self.vault = vault
        self.deletionVault = deletionVault
        self.pendingRevocationVault = pendingRevocationVault
        self.pendingActivationVault = pendingActivationVault
        self.persistenceGate = NativeAppleAuthPersistenceGate()
        self.activationSingleFlight = NativeAppleActivationSingleFlight()
    }

    func connect(
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        targetAccountBinding: String,
        transferRecoveryUser: String? = nil,
        activationPurpose: NativeAppleActivationPurpose? = nil,
        persistenceGeneration: UInt64 = 0,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeBearerSession {
        try await connectReceived(
            identityToken: identityToken,
            authorizationCode: authorizationCode,
            rawNonce: rawNonce,
            targetAccountBinding: targetAccountBinding,
            transferRecoveryUser: transferRecoveryUser,
            activationPurpose: activationPurpose,
            persistenceGeneration: persistenceGeneration,
            now: now
        ).value
    }

    private func connectReceived(
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        targetAccountBinding: String,
        transferRecoveryUser: String? = nil,
        activationPurpose: NativeAppleActivationPurpose? = nil,
        persistenceGeneration: UInt64 = 0,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeReceived<NativeBearerSession> {
        let context = try NativeAppleActivationContext(
            targetAccountBinding: targetAccountBinding,
            purpose: activationPurpose ?? (
                transferRecoveryUser == nil ? .ordinary : .transferRecovery
            ),
            transferRecoveryUser: transferRecoveryUser
        )
        persistenceGate.register(persistenceGeneration)
        do {
            let issued = try await activationSingleFlight.run(
                context: context,
                persistenceGeneration: persistenceGeneration
            ) { generationLease in
                try await connectSingleFlight(
                    identityToken: identityToken,
                    authorizationCode: authorizationCode,
                    rawNonce: rawNonce,
                    context: context,
                    transferRecoveryUser: transferRecoveryUser,
                    generationLease: generationLease,
                    now: now
                )
            }
            try persistenceGate.requireCurrent(persistenceGeneration)
            return issued
        } catch {
            guard error.localizedDescription == "APPLE_NATIVE_AUTH_SUPERSEDED",
                  persistenceGate.isCurrent(persistenceGeneration) else {
                throw error
            }
            let issued = try await activationSingleFlight.run(
                context: context,
                persistenceGeneration: persistenceGeneration
            ) { generationLease in
                try await connectSingleFlight(
                    identityToken: identityToken,
                    authorizationCode: authorizationCode,
                    rawNonce: rawNonce,
                    context: context,
                    transferRecoveryUser: transferRecoveryUser,
                    generationLease: generationLease,
                    now: now
                )
            }
            try persistenceGate.requireCurrent(persistenceGeneration)
            return issued
        }
    }

    func resumeOrdinaryPendingActivation(
        accountBinding: String,
        persistenceGeneration: UInt64 = 0,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeBearerSession? {
        let context = try NativeAppleActivationContext(
            targetAccountBinding: accountBinding,
            purpose: .ordinary,
            transferRecoveryUser: nil
        )
        guard let initial = try pendingActivationVault.load() else { return nil }
        guard try initial.context() == context else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_EXPLICIT_FLOW_REQUIRED")
        }
        persistenceGate.register(persistenceGeneration)
        let received = try await activationSingleFlight.run(
            context: context,
            persistenceGeneration: persistenceGeneration
        ) { generationLease in
            guard let saved = try pendingActivationVault.load(),
                  try saved.context() == context else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
            }
            guard (try? saved.pendingSession.validated(now: now)) != nil,
                  !pendingRevocationVault.blocksAdmission(
                    bearerToken: saved.pendingSession.token,
                    now: now
                  ) else {
                try await retireRejectedPendingActivation(saved, now: now)
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_REAUTHENTICATION_REQUIRED")
            }
            return try await activateSavedPendingSession(
                saved,
                generationLease: generationLease,
                now: now
            )
        }
        try persistenceGate.requireCurrent(persistenceGeneration)
        return received.value
    }

    private func connectSingleFlight(
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        context: NativeAppleActivationContext,
        transferRecoveryUser: String?,
        generationLease: NativeAppleActivationGenerationLease,
        now: Int
    ) async throws -> NativeReceived<NativeBearerSession> {
        let record: NativePendingActivationRecord
        var activationStart = now
        if let saved = try pendingActivationVault.load() {
            guard try saved.context() == context else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_MISMATCH")
            }
            if (try? saved.pendingSession.validated(now: now)) == nil
                || pendingRevocationVault.blocksAdmission(
                    bearerToken: saved.pendingSession.token,
                    now: now
                ) {
                try await retireRejectedPendingActivation(saved, now: now)
                return try await connectSingleFlight(
                    identityToken: identityToken,
                    authorizationCode: authorizationCode,
                    rawNonce: rawNonce,
                    context: context,
                    transferRecoveryUser: transferRecoveryUser,
                    generationLease: generationLease,
                    now: now
                )
            }
            record = saved
        } else {
            try persistenceGate.requireCurrent(generationLease.current())
            let existingActive = try vault.loadChecked(now: now)
            _ = try await retryPendingRevocations(
                excludingBearer: existingActive?.token,
                now: now
            )
            try persistenceGate.requireCurrent(generationLease.current())
            try pendingRevocationVault.requireAdditionalCapacity(
                for: existingActive.map { [$0] } ?? [],
                reservingUnknownRecords: 1,
                now: now
            )
            let receivedPending: NativeReceived<NativeApplePendingSessionResponse>
            do {
                receivedPending = try await api.exchange(
                    identityToken: identityToken,
                    authorizationCode: authorizationCode,
                    rawNonce: rawNonce,
                    transferRecoveryUser: transferRecoveryUser,
                    now: now
                )
            } catch let rejected as NativeAppleSessionResponseRejected {
                try await preserveRejectedExactSession(
                    rejected.session,
                    receivedAt: rejected.receivedAt
                )
                throw rejected
            }
            let pending = receivedPending.value
            let pendingReceivedAt = receivedPending.receivedAt
            activationStart = pendingReceivedAt
            let saved: NativePendingActivationRecord?
            do {
                let saveGeneration = generationLease.current()
                saved = try persistenceGate.savePendingIfCurrent(
                    saveGeneration,
                    save: {
                        try pendingActivationVault.save(
                            pending,
                            context: context,
                            now: pendingReceivedAt
                        )
                    }
                )
            } catch {
                let persistenceError = error
                try await safeguardUnjournaledPendingSession(pending, now: pendingReceivedAt)
                throw persistenceError
            }
            guard let saved else {
                try await safeguardUnjournaledPendingSession(pending, now: pendingReceivedAt)
                throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
            }
            record = saved
        }

        return try await activateSavedPendingSession(
            record,
            generationLease: generationLease,
            now: activationStart
        )
    }

    private func activateSavedPendingSession(
        _ record: NativePendingActivationRecord,
        generationLease: NativeAppleActivationGenerationLease,
        now: Int
    ) async throws -> NativeReceived<NativeBearerSession> {
        try persistenceGate.requireCurrent(generationLease.current())
        let pending = record.pendingSession
        if pendingRevocationVault.blocksAdmission(bearerToken: pending.token, now: now) {
            try await retireRejectedPendingActivation(record, now: now)
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_REAUTHENTICATION_REQUIRED")
        }
        if let existing = try vault.loadChecked(now: now), existing.token == pending.token {
            guard existing.expiresAt == pending.expiresAt,
                  existing.accountMode == pending.accountMode else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
            }
        }

        let receivedIssued: NativeReceived<NativeBearerSession>
        do {
            receivedIssued = try await api.activate(pending: pending, now: now)
        } catch let activationError as NativeServiceError where activationError.status == 401 {
            try await retireRejectedPendingActivation(record, now: now)
            throw activationError
        } catch let rejected as NativeAppleSessionResponseRejected {
            let activatedAuthority = try pending.retirementSession()
            try await preserveRejectedExactSession(
                NativeBearerSession(
                    schemaVersion: activatedAuthority.schemaVersion,
                    tokenType: activatedAuthority.tokenType,
                    token: activatedAuthority.token,
                    expiresAt: max(
                        activatedAuthority.expiresAt,
                        rejected.receivedAt + NativeServiceLimits.bearerLifetimeSeconds
                            + NativeServiceLimits.nativeResponseClockSkewSeconds
                    ),
                    accountMode: activatedAuthority.accountMode
                ),
                receivedAt: rejected.receivedAt
            )
            throw rejected
        }
        let issued = receivedIssued.value
        let promotionNow = receivedIssued.receivedAt
        let persistence = try persistenceGate.promoteIfCurrent(
            generationLease.current(),
            issued: issued,
            vault: vault,
            stagePrevious: { try pendingRevocationVault.stage($0, now: promotionNow) },
            requirePendingActivation: { try pendingActivationVault.requireMatching(record) },
            clearPendingActivation: { try pendingActivationVault.clearMatching(record) },
            now: promotionNow
        )
        guard case .saved(let previous) = persistence else {
            throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
        }
        if previous?.token != issued.token {
            do { _ = try await retryPendingRevocations(excludingBearer: issued.token, now: promotionNow) }
            catch { }
        }
        return receivedIssued
    }

    private func safeguardUnjournaledPendingSession(
        _ pending: NativeApplePendingSessionResponse,
        now: Int
    ) async throws {
        try await safeguardExactSession(try pending.retirementSession(), now: now)
    }

    private func safeguardExactSession(
        _ session: NativeBearerSession,
        now: Int
    ) async throws {
        guard session.mayHaveRevocableGrant(at: now) else { return }
        var staged = false
        var stageError: Error?
        do {
            try pendingRevocationVault.stage(session, now: now)
            staged = true
        } catch {
            stageError = error
        }
        var revokeConfirmed = false
        do {
            try await api.revoke(bearer: session.token)
            revokeConfirmed = true
        } catch let error as NativeServiceError where error.status == 401 {
            revokeConfirmed = true
        } catch {
            guard staged else {
                _ = stageError
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
            }
        }
        if revokeConfirmed, staged {
            try pendingRevocationVault.remove(bearerToken: session.token, now: now)
        }
    }

    private func retireRejectedPendingActivation(
        _ record: NativePendingActivationRecord,
        now: Int
    ) async throws {
        try pendingActivationVault.requireMatching(record)
        let session = try record.pendingSession.retirementSession()
        guard session.mayHaveRevocableGrant(at: now) else {
            try vault.clearIfMatchingChecked(token: session.token)
            try pendingActivationVault.clearMatching(record)
            return
        }
        var staged = false
        var stageError: Error?
        do {
            try pendingRevocationVault.stage(session, now: now)
            staged = true
        } catch {
            stageError = error
        }
        var revokeConfirmed = false
        do {
            try await api.revoke(bearer: session.token)
            revokeConfirmed = true
        } catch let error as NativeServiceError where error.status == 401 {
            revokeConfirmed = true
        } catch {
            guard staged else {
                if let stageError { throw stageError }
                throw SandboxError.blocked("APPLE_NATIVE_ACTIVATION_RETIREMENT_UNAVAILABLE")
            }
        }
        try vault.clearIfMatchingChecked(token: session.token)
        try pendingActivationVault.clearMatching(record)
        if revokeConfirmed, staged {
            try pendingRevocationVault.remove(bearerToken: session.token, now: now)
        }
    }

    func refreshIfNeeded(
        minimumRemainingSeconds: Int = 5 * 60,
        persistenceGeneration: UInt64 = 0,
        allowWhileHostedAdmissionBlocked: Bool = false,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeBearerSession? {
        persistenceGate.register(persistenceGeneration)
        try persistenceGate.requireCurrent(persistenceGeneration)
        let current: NativeBearerSession?
        if allowWhileHostedAdmissionBlocked {
            guard try pendingActivationVault.load() == nil else {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
            }
            current = try vault.loadChecked(now: now)
            if let current,
               try pendingRevocationVault.containsChecked(
                bearerToken: current.token,
                now: now
               ) {
                throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_PENDING")
            }
        } else {
            current = vault.load(now: now)
        }
        guard let current else { return nil }
        // A foreground credential recheck must prove current server authority before
        // reopening hosted admission. In that mode, never trust a previously saved
        // expiry to skip the network boundary: an earlier uncertain refresh may have
        // left the exact bearer retained (but deliberately non-admitted) without a
        // writable revocation slot.
        if !allowWhileHostedAdmissionBlocked,
           current.expiresAt - now > minimumRemainingSeconds {
            return current
        }
        // A refresh can extend the server grant before its response is accepted.
        // Reserve capacity for the exact requested bearer before crossing that
        // boundary; otherwise a failed response could leave a full queue with no
        // durable way to mark this bearer non-admitted for later retirement.
        try pendingRevocationVault.requireAdditionalCapacity(
            for: [current],
            reservingUnknownRecords: 0,
            now: now
        )
        let receivedRefresh: NativeReceived<NativeBearerSession>
        do {
            receivedRefresh = try await api.refresh(
                bearer: current.token,
                accountMode: current.accountMode,
                now: now
            )
        }
        catch let rejected as NativeAppleSessionResponseRejected {
            try await preserveRejectedExactSession(
                NativeBearerSession(
                    schemaVersion: current.schemaVersion,
                    tokenType: current.tokenType,
                    token: current.token,
                    expiresAt: max(
                        current.expiresAt,
                        rejected.receivedAt + NativeServiceLimits.bearerLifetimeSeconds
                            + NativeServiceLimits.nativeResponseClockSkewSeconds
                    ),
                    accountMode: current.accountMode
                ),
                receivedAt: rejected.receivedAt
            )
            throw rejected
        }
        let refreshed = receivedRefresh.value
        let receivedAt = receivedRefresh.receivedAt
        let persistence: NativeAppleRefreshPersistenceResult
        do {
            persistence = try persistenceGate.persistRefreshIfCurrent(
                persistenceGeneration,
                expectedToken: current.token,
                refreshed: refreshed,
                vault: vault,
                retirementContainsExactToken: {
                    try pendingRevocationVault.containsChecked(
                        bearerToken: current.token,
                        now: receivedAt
                    )
                },
                now: receivedAt
            )
        }
        catch {
            let persistenceError = error
            do { try pendingRevocationVault.stage(refreshed, now: receivedAt) }
            catch {
                throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
            }
            throw persistenceError
        }
        switch persistence {
        case .saved(let effective):
            return effective
        case .retirementStateUnreadable(let retainedCurrentToken):
            if !retainedCurrentToken {
                do { try await api.revoke(bearer: refreshed.token) }
                catch let error as NativeServiceError where error.status == 401 { }
                catch { }
            }
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
        case .superseded(let action):
            switch action {
            case .none:
                break
            case .extendRetirementDebt:
                try pendingRevocationVault.stage(refreshed, now: receivedAt)
            case .retireDetached:
                try await safeguardExactSession(refreshed, now: receivedAt)
            }
            throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
        }
    }

    private func preserveRejectedExactSession(
        _ session: NativeBearerSession,
        receivedAt: Int
    ) async throws {
        do {
            try pendingRevocationVault.stageRejectedSession(session, receivedAt: receivedAt)
            return
        } catch { }
        let retainedCurrentToken: Bool
        do {
            retainedCurrentToken = try persistenceGate.serialized {
                let retained = try vault.loadChecked(now: receivedAt)
                guard let retained, retained.token == session.token else { return false }
                return true
            }
        } catch {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
        }
        guard !retainedCurrentToken else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
        }
        do {
            try await api.revoke(bearer: session.token)
        } catch let error as NativeServiceError where error.status == 401 {
        } catch {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_SESSION_RECOVERY_LIMITED")
        }
        try persistenceGate.serialized {
            try vault.clearIfMatchingChecked(token: session.token)
        }
    }

    func possibleCredentialReview(
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeAppleCredentialReview? {
        guard let session = vault.load(now: now) else { return nil }
        let review = try await api.possibleCredentialReview(bearer: session.token)
        guard vault.load(now: now)?.token == session.token else {
            throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
        }
        return review
    }

    func acknowledgePossibleCredentialReview(
        _ acknowledgementID: NativeAppleCredentialReviewAcknowledgementID,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeAppleCredentialReview {
        guard let session = vault.load(now: now) else {
            throw SandboxError.blocked("APPLE_NATIVE_SESSION_REQUIRED")
        }
        try await api.acknowledgePossibleCredentialReview(
            bearer: session.token,
            acknowledgementID: acknowledgementID
        )
        guard vault.load(now: now)?.token == session.token else {
            throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
        }
        let current = try await api.possibleCredentialReview(bearer: session.token)
        guard vault.load(now: now)?.token == session.token else {
            throw SandboxError.blocked("APPLE_NATIVE_AUTH_SUPERSEDED")
        }
        return current
    }

    func invalidatePersistence(generation: UInt64) {
        persistenceGate.register(generation)
    }

    func validatePendingActivationContextIfPresent(
        targetAccountBinding: String,
        purpose: NativeAppleActivationPurpose,
        transferRecoveryUser: String?
    ) throws -> Bool {
        guard let pending = try pendingActivationVault.load() else { return false }
        let expected = try NativeAppleActivationContext(
            targetAccountBinding: targetAccountBinding,
            purpose: purpose,
            transferRecoveryUser: transferRecoveryUser
        )
        guard try pending.context() == expected else {
            throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONTEXT_MISMATCH")
        }
        return true
    }

    func retireIssuedSession(
        _ issued: NativeBearerSession,
        pendingDeletion: Bool,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws {
        do { _ = try await retireActiveSession(issued, now: now) }
        catch {
            if pendingDeletion { try deletionVault.requireReauthentication(now: now) }
            throw error
        }
        if pendingDeletion { try deletionVault.requireReauthentication(now: now) }
    }

    func retireClearedSession(
        _ session: NativeBearerSession,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws {
        let serverConfirmed = try await retireServerSession(session, now: now)
        if serverConfirmed {
            try pendingRevocationVault.remove(bearerToken: session.token, now: now)
            return
        }
        throw NativeRevocationDeferredError(
            expiresAt: try pendingRevocationVault.status(now: now)?.expiresAt ?? session.expiresAt
        )
    }

    func captureSessionsForRetirement() throws -> NativeCapturedAppleSessions {
        let pending = try pendingActivationVault.load()
        let active = try vault.loadForRetirement()
        var sessions: [NativeBearerSession] = []
        if let pending {
            sessions.append(try pending.pendingSession.retirementSession())
        }
        if let active {
            if let retained = sessions.first(where: { $0.token == active.token }) {
                guard retained == active else {
                    throw SandboxError.blocked("APPLE_NATIVE_PENDING_ACTIVATION_CONFLICT")
                }
            } else {
                sessions.append(active)
            }
        }
        return NativeCapturedAppleSessions(sessions: sessions)
    }

    func stageSessionsForRetirement(
        _ captured: NativeCapturedAppleSessions,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativePreparedAppleSessionRetirement {
        let revocable = captured.sessions.filter { $0.mayHaveRevocableGrant(at: now) }
        let staged = try pendingRevocationVault.stage(revocable, now: now)
        return NativePreparedAppleSessionRetirement(
            sessions: captured.sessions,
            durablyStagedBearerTokens: staged
        )
    }

    func handoffPreparedSessionsForRetirement(
        _ prepared: NativePreparedAppleSessionRetirement,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws {
        for session in prepared.sessions {
            guard !session.mayHaveRevocableGrant(at: now)
                    || prepared.durablyStagedBearerTokens.contains(session.token) else {
                throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_NOT_SAVED")
            }
            try vault.clearIfMatchingChecked(token: session.token)
            try pendingActivationVault.clearMatchingToken(session.token)
        }
    }

    func prepareSessionsForRetirement(
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativePreparedAppleSessionRetirement {
        try persistenceGate.serialized {
            let captured = try captureSessionsForRetirement()
            let prepared = try stageSessionsForRetirement(captured, now: now)
            try handoffPreparedSessionsForRetirement(prepared, now: now)
            return prepared
        }
    }

    func retirePreparedSessions(
        _ prepared: NativePreparedAppleSessionRetirement,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws {
        var firstFailure: Error?
        var deferred = false
        for session in prepared.sessions {
            let mayHaveGrant = session.mayHaveRevocableGrant(at: now)
            guard !mayHaveGrant || prepared.durablyStagedBearerTokens.contains(session.token) else {
                throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_NOT_SAVED")
            }

            var serverConfirmed = !mayHaveGrant
            if mayHaveGrant {
                do {
                    try await api.revoke(bearer: session.token)
                    serverConfirmed = true
                } catch let error as NativeServiceError where error.status == 401 {
                    serverConfirmed = true
                } catch {
                    deferred = true
                }
            }

            var localClearFailed = false
            do { try vault.clearIfMatchingChecked(token: session.token) }
            catch {
                localClearFailed = true
                if firstFailure == nil { firstFailure = error }
            }
            do { try pendingActivationVault.clearMatchingToken(session.token) }
            catch {
                localClearFailed = true
                if firstFailure == nil { firstFailure = error }
            }
            if serverConfirmed,
               mayHaveGrant,
               !localClearFailed {
                do { try pendingRevocationVault.remove(bearerToken: session.token, now: now) }
                catch { if firstFailure == nil { firstFailure = error } }
            }
        }
        if let firstFailure { throw firstFailure }
        if deferred {
            throw NativeRevocationDeferredError(
                expiresAt: try pendingRevocationVault.status(now: now)?.expiresAt ?? now
            )
        }
    }

    @discardableResult
    func stagePendingRevocationIfNeeded(
        _ session: NativeBearerSession,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> Bool {
        guard session.mayHaveRevocableGrant(at: now) else { return false }
        try pendingRevocationVault.stage(session, now: now)
        return true
    }

    func disconnect(now: Int = Int(Date().timeIntervalSince1970)) async throws {
        let prepared: NativePreparedAppleSessionRetirement
        do {
            prepared = try prepareSessionsForRetirement(now: now)
        } catch {
            let captured = try captureSessionsForRetirement()
            var remoteFailure = false
            for session in captured.sessions where session.mayHaveRevocableGrant(at: now) {
                do { try await api.revoke(bearer: session.token) }
                catch let error as NativeServiceError where error.status == 401 { }
                catch { remoteFailure = true }
            }
            guard !remoteFailure else {
                throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_NOT_SAVED")
            }
            for session in captured.sessions {
                try vault.clearIfMatchingChecked(token: session.token)
                try pendingActivationVault.clearMatchingToken(session.token)
            }
            return
        }
        try await retirePreparedSessions(prepared, now: now)
    }

    func pendingRevocationStatus(
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativePendingRevocationStatus? {
        try pendingRevocationVault.status(now: now)
    }

    @discardableResult
    func retryPendingRevocations(
        excludingBearer: String? = nil,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativePendingRevocationStatus? {
        let pending = try pendingRevocationVault.snapshot(now: now)
        for entry in pending {
            if entry.bearerToken == excludingBearer {
                continue
            }
            var serverConfirmed = false
            do {
                try await api.revoke(bearer: entry.bearerToken)
                serverConfirmed = true
            } catch let error as NativeServiceError where error.status == 401 {
                serverConfirmed = true
            } catch {
                continue
            }
            guard serverConfirmed else { continue }
            do {
                try vault.clearIfMatchingChecked(token: entry.bearerToken)
                try pendingActivationVault.clearMatchingToken(entry.bearerToken)
                try pendingRevocationVault.remove(bearerToken: entry.bearerToken, now: now)
            } catch {
                continue
            }
        }
        return try pendingRevocationVault.status(now: now)
    }

    private func retireServerSession(_ session: NativeBearerSession, now: Int) async throws -> Bool {
        var persistenceError: Error?
        do { try pendingRevocationVault.stage(session, now: now) }
        catch { persistenceError = error }
        do {
            try await api.revoke(bearer: session.token)
        } catch let error as NativeServiceError where error.status == 401 {
            return true
        } catch {
            guard persistenceError == nil else {
                throw SandboxError.blocked("APPLE_NATIVE_REVOCATION_FOLLOW_UP_NOT_SAVED")
            }
            return false
        }
        return true
    }

    private func retireActiveSession(_ session: NativeBearerSession, now: Int) async throws -> Bool {
        let serverConfirmed: Bool
        do { serverConfirmed = try await retireServerSession(session, now: now) }
        catch { throw error }
        try vault.clearIfMatchingChecked(token: session.token)
        if serverConfirmed {
            try pendingRevocationVault.remove(bearerToken: session.token, now: now)
        }
        return serverConfirmed
    }

    func hasPendingAccountDeletion() -> Bool {
        deletionVault.hasPending()
    }

    func hasPendingAccountDeletion(accountBinding: String) -> Bool {
        deletionVault.hasPending(accountBinding: accountBinding)
    }

    func accountDeletionRecoveryState(
        now: Int = Int(Date().timeIntervalSince1970)
    ) -> NativeAccountDeletionRecoveryState {
        guard deletionVault.hasPending() else { return .none }
        do {
            guard let pending = try deletionVault.load(now: now) else { return .none }
            return .recoverable(pending)
        } catch {
            return .requiresExplicitDiscard
        }
    }

    func pendingAccountDeletion(
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeAccountDeletionAttempt? {
        try deletionVault.load(now: now)
    }

    func pendingAccountDeletion(
        accountBinding: String,
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativeAccountDeletionAttempt? {
        try deletionVault.load(accountBinding: accountBinding, now: now)
    }

    func discardPendingAccountDeletion() throws {
        try deletionVault.clearChecked()
    }

    func preparePendingAccountDeletionDiscard(
        now: Int = Int(Date().timeIntervalSince1970)
    ) throws -> NativePreparedAppleSessionRetirement {
        try persistenceGate.serialized {
            let deletionAttempt = try deletionVault.loadForRetirement()
            let captured = try captureSessionsForRetirement()
            var sessions = captured.sessions
            if let attemptSession = try deletionAttempt?.retirementSession(now: now),
               !sessions.contains(where: { $0.token == attemptSession.token }) {
                sessions.append(attemptSession)
            }
            let revocable = sessions.filter { $0.mayHaveRevocableGrant(at: now) }
            let staged = try pendingRevocationVault.stage(
                revocable,
                legacyDeletionAttempt: deletionAttempt?.schemaVersion == 2 ? deletionAttempt : nil,
                now: now
            )
            let prepared = NativePreparedAppleSessionRetirement(
                sessions: sessions,
                durablyStagedBearerTokens: staged
            )
            try handoffPreparedSessionsForRetirement(prepared, now: now)
            return prepared
        }
    }

    func finalizeConfirmedAccountDeletion(accountBindingHash: String) throws {
        guard NativeAccountDeletionKey.valid("v1.\(accountBindingHash)") else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_OUTCOME_INVALID")
        }
        if let pending = try pendingActivationVault.load(),
           pending.targetAccountBindingHash == accountBindingHash {
            try pendingActivationVault.clearMatching(pending)
        }
        try deletionVault.clearChecked()
    }

    func reauthorizePendingAccountDeletion(
        identityToken: String,
        authorizationCode: String,
        rawNonce: String,
        accountBinding: String,
        transferRecoveryUser: String? = nil,
        persistenceGeneration: UInt64 = 0,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeBearerSession {
        guard let pending = try deletionVault.load(accountBinding: accountBinding, now: now),
              pending.requiresReauthentication else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_REAUTHENTICATION_INVALID")
        }
        let receivedIssued = try await connectReceived(
            identityToken: identityToken,
            authorizationCode: authorizationCode,
            rawNonce: rawNonce,
            targetAccountBinding: accountBinding,
            transferRecoveryUser: transferRecoveryUser,
            activationPurpose: .deletionReauthorization,
            persistenceGeneration:persistenceGeneration,
            now: now
        )
        let issued = receivedIssued.value
        do {
            try deletionVault.replaceBearer(
                accountBinding: accountBinding,
                bearer: issued,
                now: receivedIssued.receivedAt
            )
        } catch {
            try? await disconnect(now: receivedIssued.receivedAt)
            throw error
        }
        return issued
    }

    func deleteAccount(
        accountBinding: String? = nil,
        now: Int = Int(Date().timeIntervalSince1970)
    ) async throws -> NativeAccountDeletionResponse {
        let attempt: NativeAccountDeletionAttempt
        if let pending = try deletionVault.load(now: now) {
            if let accountBinding,try !pending.belongs(to: accountBinding) {
                throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_ATTEMPT_ACCOUNT_MISMATCH")
            }
            attempt = pending
        } else {
            guard let accountBinding else {
                throw SandboxError.blocked("APPLE_NATIVE_SESSION_REQUIRED")
            }
            guard let bearer = vault.load(now: now) else {
                throw SandboxError.blocked("APPLE_NATIVE_SESSION_REQUIRED")
            }
            attempt = try deletionVault.attempt(
                accountBinding: accountBinding,
                bearer: bearer,
                now: now
            )
        }
        guard !attempt.requiresReauthentication else {
            throw SandboxError.blocked("APPLE_ACCOUNT_DELETION_REAUTHENTICATION_REQUIRED")
        }
        do {
            return try await api.deleteAccount(
                bearer: attempt.bearerToken,
                idempotencyKey: attempt.idempotencyKey
            )
        } catch let error as NativeServiceError
            where error.status == 401 && error.code == "APPLE_NATIVE_SESSION_REQUIRED" {
            try deletionVault.requireReauthentication(now: now)
            throw error
        }
    }
}

private struct NativeRecoverySecretRegistration: Codable, Equatable {
    let workspaceId: String
    let accountBindingHash: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case workspaceId, accountBindingHash
    }

    init(workspaceId: String, accountBindingHash: String) {
        self.workspaceId = workspaceId
        self.accountBindingHash = accountBindingHash
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        workspaceId = try container.decode(String.self, forKey: .workspaceId)
        accountBindingHash = try container.decode(String.self, forKey: .accountBindingHash)
    }
}

private struct NativeRecoverySecretRegistry: Codable, Equatable {
    let schemaVersion: Int
    let entries: [NativeRecoverySecretRegistration]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, entries
    }

    init(entries: [NativeRecoverySecretRegistration]) {
        schemaVersion = 1
        self.entries = entries
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        entries = try container.decode([NativeRecoverySecretRegistration].self, forKey: .entries)
    }
}

struct NativeRecoverySecretCandidate: Equatable {
    let secret: String
    let staged: Bool
}

struct NativeRecoverySecretVault: @unchecked Sendable {
    let read: (String) throws -> String?
    let write: (String, String) throws -> Void
    let delete: (String) throws -> Void
    let readLegacyRegistry: () throws -> String?
    let readRegistration: (String) throws -> String?
    let writeRegistration: (String, String) throws -> Void
    let deleteRegistration: (String) throws -> Void
    let listRegistrations: () throws -> [String: String]
    let accountBinding: () throws -> String?

    private static let registryKey = "registry"
    private static let pendingPrefix = "pending."
    private static let maximumRegistrations = 256
    private static let maximumRegistryBytes = 32_768
    private static let maximumRegistrationBytes = 512

    static let live = NativeRecoverySecretVault(
        read: { try Keychain.getSynchronizableChecked("workspaceRecovery.v1.\($0)") },
        write: { workspaceId, secret in try Keychain.setSynchronizable(secret, for: "workspaceRecovery.v1.\(workspaceId)") },
        delete: { try Keychain.deleteSynchronizableChecked("workspaceRecovery.v1.\($0)") },
        readLegacyRegistry: { try Keychain.getSynchronizableChecked("workspaceRecovery.v1.\(registryKey)") },
        readRegistration: { try Keychain.getSynchronizableRecoveryRegistrationChecked($0) },
        writeRegistration: { workspaceId, registration in try Keychain.setSynchronizableRecoveryRegistration(registration, workspaceId: workspaceId) },
        deleteRegistration: { try Keychain.deleteSynchronizableRecoveryRegistrationChecked($0) },
        listRegistrations: {
            try Keychain.synchronizableRecoveryRegistrations(
                maximumItems: maximumRegistrations + 1,
                maximumValueBytes: maximumRegistrationBytes
            )
        },
        accountBinding: { try Keychain.getChecked("appleUser") }
    )

    init(
        read: @escaping (String) throws -> String?,
        write: @escaping (String, String) throws -> Void,
        delete: @escaping (String) throws -> Void,
        readLegacyRegistry: (() throws -> String?)? = nil,
        readRegistration: @escaping (String) throws -> String?,
        writeRegistration: @escaping (String, String) throws -> Void,
        deleteRegistration: @escaping (String) throws -> Void,
        listRegistrations: @escaping () throws -> [String: String],
        accountBinding: @escaping () throws -> String? = { try Keychain.getChecked("appleUser") }
    ) {
        self.read = read
        self.write = write
        self.delete = delete
        self.readLegacyRegistry = readLegacyRegistry ?? { try read(Self.registryKey) }
        self.readRegistration = readRegistration
        self.writeRegistration = writeRegistration
        self.deleteRegistration = deleteRegistration
        self.listRegistrations = listRegistrations
        self.accountBinding = accountBinding
    }

    func newSecret(using random: (Int) throws -> Data = NativeSecureRandom.bytes) throws -> String {
        let bytes = try random(32)
        guard bytes.count == 32 else { throw SandboxError.blocked("SECURE_RANDOM_LENGTH_INVALID") }
        return NativeSecureRandom.base64URL(bytes)
    }

    func save(_ secret: String, workspaceId: String) throws {
        guard validWorkspaceId(workspaceId), NativeAccountDeletionKey.valid("v1.\(secret)"),
              let accountBinding = try accountBinding() else {
            throw SandboxError.invalid("ICLOUD_RECOVERY_SECRET_INVALID")
        }
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        let registration = NativeRecoverySecretRegistration(
            workspaceId: workspaceId,
            accountBindingHash: accountBindingHash
        )
        try ensureRegistration(registration)
        try write(workspaceId, secret)
        guard try read(workspaceId) == secret else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_PERSISTENCE_FAILED")
        }
        try delete(Self.pendingKey(workspaceId))
        guard try read(Self.pendingKey(workspaceId)) == nil else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
    }

    func recoverySecret(workspaceId: String) throws -> String {
        guard validWorkspaceId(workspaceId), let accountBinding = try accountBinding() else {
            throw SandboxError.invalid("INVALID_WORKSPACE_ID")
        }
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        guard try registration(workspaceId: workspaceId)?.accountBindingHash == accountBindingHash,
              let secret = try read(workspaceId), NativeAccountDeletionKey.valid("v1.\(secret)") else {
            // Never invent a replacement secret for an existing envelope. A replacement cannot decrypt it.
            // On another device, wait for iCloud Keychain, use the original local passphrase if that
            // workspace was created in local-only mode, or create a new Apple-recovered workspace.
            throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_UNAVAILABLE")
        }
        return secret
    }

    func registeredWorkspaceIds() throws -> [String] {
        guard let accountBinding = try accountBinding() else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_UNAVAILABLE")
        }
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        return try loadRegistrations()
            .filter { $0.accountBindingHash == accountBindingHash }
            .map(\.workspaceId)
            .sorted()
    }

    func recoveryCandidates(workspaceId: String) throws -> [NativeRecoverySecretCandidate] {
        guard validWorkspaceId(workspaceId), let accountBinding = try accountBinding() else {
            throw SandboxError.invalid("INVALID_WORKSPACE_ID")
        }
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        guard try registration(workspaceId: workspaceId)?.accountBindingHash == accountBindingHash else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_UNAVAILABLE")
        }
        var candidates: [NativeRecoverySecretCandidate] = []
        if let pending = try read(Self.pendingKey(workspaceId)), NativeAccountDeletionKey.valid("v1.\(pending)") {
            candidates.append(NativeRecoverySecretCandidate(secret: pending, staged: true))
        }
        if let current = try read(workspaceId), NativeAccountDeletionKey.valid("v1.\(current)"),
           !candidates.contains(where: { $0.secret == current }) {
            candidates.append(NativeRecoverySecretCandidate(secret: current, staged: false))
        }
        guard !candidates.isEmpty else { throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_UNAVAILABLE") }
        return candidates
    }

    func stageReplacement(_ secret: String, workspaceId: String) throws {
        guard validWorkspaceId(workspaceId), NativeAccountDeletionKey.valid("v1.\(secret)"),
              let accountBinding = try accountBinding() else {
            throw SandboxError.invalid("ICLOUD_RECOVERY_SECRET_INVALID")
        }
        let accountBindingHash = try NativeAccountBinding.hash(accountBinding)
        let registration = NativeRecoverySecretRegistration(workspaceId: workspaceId, accountBindingHash: accountBindingHash)
        try ensureRegistration(registration)
        try write(Self.pendingKey(workspaceId), secret)
        guard try read(Self.pendingKey(workspaceId)) == secret else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_PERSISTENCE_FAILED")
        }
    }

    func commitStagedReplacement(workspaceId: String) throws {
        guard validWorkspaceId(workspaceId), let pending = try read(Self.pendingKey(workspaceId)),
              NativeAccountDeletionKey.valid("v1.\(pending)") else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_ROTATION_NOT_STAGED")
        }
        try write(workspaceId, pending)
        guard try read(workspaceId) == pending else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_SECRET_PERSISTENCE_FAILED")
        }
        try delete(Self.pendingKey(workspaceId))
        guard try read(Self.pendingKey(workspaceId)) == nil else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
    }

    func discardStagedReplacement(workspaceId: String) throws {
        guard validWorkspaceId(workspaceId) else { return }
        try delete(Self.pendingKey(workspaceId))
        guard try read(Self.pendingKey(workspaceId)) == nil else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
    }

    func remove(workspaceId: String) throws {
        guard validWorkspaceId(workspaceId) else { return }
        try delete(workspaceId)
        try delete(Self.pendingKey(workspaceId))
        guard try read(workspaceId) == nil, try read(Self.pendingKey(workspaceId)) == nil else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
        try removeRegistration(workspaceId: workspaceId)
    }

    func scrub(accountBindingHash: String) throws {
        guard NativeAccountDeletionKey.valid("v1.\(accountBindingHash)") else {
            throw SandboxError.blocked("WORKSPACE_RECOVERY_SCOPE_INVALID")
        }
        let registrations = try loadRegistrations()
        let scoped = registrations.filter { $0.accountBindingHash == accountBindingHash }
        for registration in scoped {
            try delete(registration.workspaceId)
            try delete(Self.pendingKey(registration.workspaceId))
            guard try read(registration.workspaceId) == nil,
                  try read(Self.pendingKey(registration.workspaceId)) == nil else {
                throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
            }
            try removeRegistration(workspaceId: registration.workspaceId)
        }
        guard try loadRegistrations().allSatisfy({ $0.accountBindingHash != accountBindingHash }) else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_PERSISTENCE_FAILED")
        }
    }

    func validateAccountBindingMigration(
        from oldUser: String,
        to newUser: String
    ) throws -> NativeRecoveryBindingMigrationState {
        let oldHash = try NativeAccountBinding.hash(oldUser)
        let newHash = try NativeAccountBinding.hash(newUser)
        guard oldHash != newHash else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_INVALID")
        }
        let entries = try loadRegistrations()
        let hasOld = entries.contains { $0.accountBindingHash == oldHash }
        let hasNew = entries.contains { $0.accountBindingHash == newHash }
        if hasOld && hasNew {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
        }
        if hasOld { return .requiresMigration }
        if hasNew { return .alreadyMigrated }
        return .absent
    }

    func migrateAccountBinding(
        from oldUser: String,
        to newUser: String,
        allowAlreadyMigrated: Bool
    ) throws {
        let oldHash = try NativeAccountBinding.hash(oldUser)
        let newHash = try NativeAccountBinding.hash(newUser)
        guard oldHash != newHash else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_INVALID")
        }
        let original = try loadRegistrations()
        let oldEntries = original.filter { $0.accountBindingHash == oldHash }
        let newEntries = original.filter { $0.accountBindingHash == newHash }
        if !allowAlreadyMigrated && !newEntries.isEmpty {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
        }
        guard !oldEntries.isEmpty else {
            if allowAlreadyMigrated || newEntries.isEmpty { return }
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
        }
        for entry in oldEntries {
            try saveRegistration(NativeRecoverySecretRegistration(
                workspaceId: entry.workspaceId,
                accountBindingHash: newHash
            ))
        }
        let verified = try loadRegistrations()
        guard !verified.contains(where: { $0.accountBindingHash == oldHash }),
              verified.filter({ $0.accountBindingHash == newHash }).count == oldEntries.count + newEntries.count else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_PERSISTENCE_FAILED")
        }
    }

    private func loadLegacyRegistry() throws -> NativeRecoverySecretRegistry {
        guard let encoded = try readLegacyRegistry() else {
            return NativeRecoverySecretRegistry(entries: [])
        }
        guard encoded.utf8.count <= Self.maximumRegistryBytes,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
        }
        do {
            let registry = try NativeJSON.decoder.decode(NativeRecoverySecretRegistry.self, from: data)
            guard registry.schemaVersion == 1,
                  registry.entries.count <= Self.maximumRegistrations,
                  Set(registry.entries.map(\.workspaceId)).count == registry.entries.count,
                  registry.entries.allSatisfy({
                      validWorkspaceId($0.workspaceId)
                          && NativeAccountDeletionKey.valid("v1.\($0.accountBindingHash)")
                  }) else {
                throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
            }
            return registry
        } catch {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
        }
    }

    private func migrateLegacyRegistryIfNeeded() throws {
        let legacy = try loadLegacyRegistry()
        guard !legacy.entries.isEmpty else {
            if try readLegacyRegistry() != nil {
                try delete(Self.registryKey)
                guard try readLegacyRegistry() == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
            }
            return
        }
        var existing = try decodedRegistrationItems()
        let mergedWorkspaceIds = Set(existing.map(\.workspaceId)).union(legacy.entries.map(\.workspaceId))
        guard mergedWorkspaceIds.count <= Self.maximumRegistrations else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_FULL")
        }
        for registration in legacy.entries {
            if let current = existing.first(where: { $0.workspaceId == registration.workspaceId }) {
                guard current == registration else { throw SandboxError.blocked("ICLOUD_RECOVERY_SCOPE_CONFLICT") }
            } else {
                try saveRegistration(registration)
                existing.append(registration)
            }
        }
        let verified = try decodedRegistrationItems()
        guard legacy.entries.allSatisfy({ verified.contains($0) }) else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_PERSISTENCE_FAILED")
        }
        try delete(Self.registryKey)
        guard try readLegacyRegistry() == nil else { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") }
    }

    private func loadRegistrations() throws -> [NativeRecoverySecretRegistration] {
        try migrateLegacyRegistryIfNeeded()
        return try decodedRegistrationItems()
    }

    private func registration(workspaceId: String) throws -> NativeRecoverySecretRegistration? {
        try migrateLegacyRegistryIfNeeded()
        guard let encoded = try readRegistration(workspaceId) else { return nil }
        return try decodeRegistration(encoded, expectedWorkspaceId: workspaceId)
    }

    private func ensureRegistration(_ registration: NativeRecoverySecretRegistration) throws {
        try migrateLegacyRegistryIfNeeded()
        if let current = try self.registration(workspaceId: registration.workspaceId) {
            guard current == registration else { throw SandboxError.blocked("ICLOUD_RECOVERY_SCOPE_CONFLICT") }
            return
        }
        guard try decodedRegistrationItems().count < Self.maximumRegistrations else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_FULL")
        }
        try saveRegistration(registration)
        let converged = try decodedRegistrationItems(maximumAllowed: Self.maximumRegistrations + 1)
        guard converged.count <= Self.maximumRegistrations else {
            try removeRegistration(workspaceId: registration.workspaceId)
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_FULL")
        }
        guard converged.contains(registration) else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_PERSISTENCE_FAILED")
        }
    }

    private func saveRegistration(_ registration: NativeRecoverySecretRegistration) throws {
        let encoded = String(decoding: try NativeJSON.encoder.encode(registration), as: UTF8.self)
        guard encoded.utf8.count <= Self.maximumRegistrationBytes else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
        }
        try writeRegistration(registration.workspaceId, encoded)
        guard let readback = try readRegistration(registration.workspaceId),
              try decodeRegistration(readback, expectedWorkspaceId: registration.workspaceId) == registration else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_PERSISTENCE_FAILED")
        }
    }

    private func removeRegistration(workspaceId: String) throws {
        try deleteRegistration(workspaceId)
        guard try readRegistration(workspaceId) == nil else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
    }

    private func decodedRegistrationItems(
        maximumAllowed: Int = Self.maximumRegistrations
    ) throws -> [NativeRecoverySecretRegistration] {
        let items = try listRegistrations()
        guard items.count <= maximumAllowed else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_FULL")
        }
        return try items.map { workspaceId, encoded in
            try decodeRegistration(encoded, expectedWorkspaceId: workspaceId)
        }.sorted { $0.workspaceId < $1.workspaceId }
    }

    private func decodeRegistration(
        _ encoded: String,
        expectedWorkspaceId: String
    ) throws -> NativeRecoverySecretRegistration {
        guard validWorkspaceId(expectedWorkspaceId),
              encoded.utf8.count <= Self.maximumRegistrationBytes,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
        }
        do {
            let registration = try NativeJSON.decoder.decode(NativeRecoverySecretRegistration.self, from: data)
            guard registration.workspaceId == expectedWorkspaceId,
                  NativeAccountDeletionKey.valid("v1.\(registration.accountBindingHash)") else {
                throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
            }
            return registration
        } catch {
            throw SandboxError.blocked("ICLOUD_RECOVERY_REGISTRY_INVALID")
        }
    }

    private func validWorkspaceId(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9_-]{32}$", options: .regularExpression) != nil
    }

    private static func pendingKey(_ workspaceId: String) -> String {
        "\(pendingPrefix)\(workspaceId)"
    }
}

enum NativeRecoveryBindingMigrationState: String, Codable, Equatable {
    case absent
    case requiresMigration
    case alreadyMigrated
}

private struct NativeAppleTransferMigrationRecord: Codable, Equatable {
    let schemaVersion: Int
    let oldUser: String
    let newUser: String
    let workspaceDirectoryName: String
    let recoveryBindingState: NativeRecoveryBindingMigrationState
    let previousAccountMode: NativeAppleAccountMode?
    let verifiedAccountMode: NativeAppleAccountMode

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, oldUser, newUser, workspaceDirectoryName
        case recoveryBindingState, previousAccountMode, verifiedAccountMode
    }

    init(
        oldUser: String,
        newUser: String,
        workspaceDirectoryName: String,
        recoveryBindingState: NativeRecoveryBindingMigrationState,
        previousAccountMode: NativeAppleAccountMode?,
        verifiedAccountMode: NativeAppleAccountMode
    ) {
        schemaVersion = 2
        self.oldUser = oldUser
        self.newUser = newUser
        self.workspaceDirectoryName = workspaceDirectoryName
        self.recoveryBindingState = recoveryBindingState
        self.previousAccountMode = previousAccountMode
        self.verifiedAccountMode = verifiedAccountMode
    }

    init(from decoder: Decoder) throws {
        try requireExactKeys(decoder, expected: Set(CodingKeys.allCases.map(\.rawValue)))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        oldUser = try container.decode(String.self, forKey: .oldUser)
        newUser = try container.decode(String.self, forKey: .newUser)
        workspaceDirectoryName = try container.decode(String.self, forKey: .workspaceDirectoryName)
        recoveryBindingState = try container.decode(
            NativeRecoveryBindingMigrationState.self,
            forKey: .recoveryBindingState
        )
        previousAccountMode = try container.decodeIfPresent(
            NativeAppleAccountMode.self,
            forKey: .previousAccountMode
        )
        verifiedAccountMode = try container.decode(
            NativeAppleAccountMode.self,
            forKey: .verifiedAccountMode
        )
    }

    func validated() throws -> Self {
        guard schemaVersion == 2,
              oldUser != newUser,
              (1...1_000).contains(oldUser.utf8.count),
              (1...1_000).contains(newUser.utf8.count),
              try NativeAccountBinding.hash(oldUser) != NativeAccountBinding.hash(newUser),
              workspaceDirectoryName.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              previousAccountMode == nil || previousAccountMode == verifiedAccountMode else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_INVALID")
        }
        return self
    }
}

struct NativeAppleTransferMigrationVault: @unchecked Sendable {
    private static let storageKey = "appleTransferMigration.v1"
    let read: () throws -> String?
    let write: (String) throws -> Void
    let delete: () throws -> Void

    static let live = NativeAppleTransferMigrationVault(
        read: { try Keychain.getChecked(storageKey) },
        write: { try Keychain.set($0, for: storageKey) },
        delete: { try Keychain.deleteChecked(storageKey) }
    )

    fileprivate func load() throws -> NativeAppleTransferMigrationRecord? {
        guard let encoded = try read() else { return nil }
        guard encoded.utf8.count <= 4_096,
              let data = encoded.data(using: .utf8) else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_INVALID")
        }
        do {
            return try NativeJSON.decoder.decode(NativeAppleTransferMigrationRecord.self, from: data)
                .validated()
        } catch {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_INVALID")
        }
    }

    fileprivate func save(_ record: NativeAppleTransferMigrationRecord) throws {
        let validated = try record.validated()
        let encoded = String(decoding: try NativeJSON.encoder.encode(validated), as: UTF8.self)
        try write(encoded)
        guard try load() == validated else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_PERSISTENCE_FAILED")
        }
    }

    fileprivate func clearChecked() throws {
        try delete()
        guard try read() == nil else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_PERSISTENCE_FAILED")
        }
    }
}

struct NativeAppleTransferMigrationCoordinator: @unchecked Sendable {
    let accountModeVault: NativeAppleAccountModeVault
    let workspaceBindingVault: NativeLocalWorkspaceBindingVault
    let recoveryVault: NativeRecoverySecretVault
    let migrationVault: NativeAppleTransferMigrationVault
    let transferBlockVault: NativeAppleTransferBlockVault
    let readUser: () throws -> String?
    let writeUser: (String) throws -> Void

    static let live = NativeAppleTransferMigrationCoordinator(
        accountModeVault: .live,
        workspaceBindingVault: .live,
        recoveryVault: .live,
        migrationVault: .live,
        transferBlockVault: .live,
        readUser: { try Keychain.getChecked("appleUser") },
        writeUser: { try Keychain.set($0, for: "appleUser") }
    )

    func migrateVerifiedTransfer(
        from oldUser: String,
        to newUser: String,
        verifiedAccountMode: NativeAppleAccountMode
    ) throws {
        guard try migrationVault.load() == nil,
              try readUser() == oldUser,
              try transferBlockVault.load() == oldUser else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_CONFLICT")
        }
        let previousAccountMode = try accountModeVault.load(accountBinding: oldUser)
        guard previousAccountMode == nil || previousAccountMode == verifiedAccountMode else {
            throw SandboxError.blocked("APPLE_TRANSFER_ACCOUNT_MODE_CHANGED")
        }
        let recoveryBindingState = try recoveryVault.validateAccountBindingMigration(
            from: oldUser,
            to: newUser
        )
        let workspaceDirectoryName = try workspaceBindingVault.validateAccountBindingMigration(
            from: oldUser,
            to: newUser
        )
        let record = try NativeAppleTransferMigrationRecord(
            oldUser: oldUser,
            newUser: newUser,
            workspaceDirectoryName: workspaceDirectoryName,
            recoveryBindingState: recoveryBindingState,
            previousAccountMode: previousAccountMode,
            verifiedAccountMode: verifiedAccountMode
        ).validated()
        try migrationVault.save(record)
        do {
            try complete(record)
        } catch {
            let originalError = error
            do {
                try rollback(record)
                try migrationVault.clearChecked()
            } catch {
                throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_RECOVERY_REQUIRED")
            }
            throw originalError
        }
    }

    @discardableResult
    func resumePendingMigration() throws -> Bool {
        guard let record = try migrationVault.load() else { return false }
        do { try complete(record) }
        catch {
            try? transferBlockVault.block(oldUser: record.oldUser)
            throw error
        }
        return true
    }

    private func complete(_ record: NativeAppleTransferMigrationRecord) throws {
        try recoveryVault.migrateAccountBinding(
            from: record.oldUser,
            to: record.newUser,
            allowAlreadyMigrated: true
        )
        try workspaceBindingVault.migrateAccountBinding(
            from: record.oldUser,
            to: record.newUser,
            expectedDirectoryName: record.workspaceDirectoryName,
            allowAlreadyMigrated: true
        )
        try accountModeVault.save(record.verifiedAccountMode, accountBinding: record.newUser)
        try writeUser(record.newUser)
        guard try readUser() == record.newUser,
              try accountModeVault.load(accountBinding: record.newUser) == record.verifiedAccountMode else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_PERSISTENCE_FAILED")
        }
        try transferBlockVault.clearChecked(oldUser: record.oldUser)
        try migrationVault.clearChecked()
    }

    private func rollback(_ record: NativeAppleTransferMigrationRecord) throws {
        try transferBlockVault.block(oldUser: record.oldUser)
        try writeUser(record.oldUser)
        if record.recoveryBindingState == .requiresMigration {
            try recoveryVault.migrateAccountBinding(
                from: record.newUser,
                to: record.oldUser,
                allowAlreadyMigrated: true
            )
        }
        try workspaceBindingVault.migrateAccountBinding(
            from: record.newUser,
            to: record.oldUser,
            expectedDirectoryName: record.workspaceDirectoryName,
            allowAlreadyMigrated: true
        )
        if let previousAccountMode = record.previousAccountMode {
            try accountModeVault.save(previousAccountMode, accountBinding: record.oldUser)
        } else {
            try accountModeVault.clearChecked()
        }
        guard try readUser() == record.oldUser,
              try accountModeVault.load(accountBinding: record.oldUser) == record.previousAccountMode else {
            throw SandboxError.blocked("APPLE_TRANSFER_LOCAL_MIGRATION_RECOVERY_REQUIRED")
        }
    }
}

struct NativeSyncWorkspaceSummary: Codable, Equatable, Identifiable {
    let workspaceId: String
    let epoch: String
    let updatedAt: String
    var id: String { workspaceId }
}

struct NativeStoredEncryptedRecord: Codable, Equatable {
    let revision: Int
    let envelope: EncryptedWorkspaceRecord
}

struct NativeSyncWorkspaceSnapshot: Codable, Equatable {
    let workspaceId: String
    let epoch: String
    let recovery: WorkspaceRecoveryEnvelope
    let snapshotRevision: Int
    let records: [NativeStoredEncryptedRecord]
}

private struct NativeSyncWorkspaceList: Decodable { let workspaces: [NativeSyncWorkspaceSummary] }
private struct NativeSyncWorkspacePage: Decodable {
    let workspaceId: String
    let epoch: String
    let recovery: WorkspaceRecoveryEnvelope
    let snapshotRevision: Int
    let records: [NativeStoredEncryptedRecord]
    let nextCursor: String?

    private enum CodingKeys: String, CodingKey {
        case workspaceId, epoch, recovery, snapshotRevision, records, nextCursor
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard container.contains(.nextCursor) else {
            throw DecodingError.keyNotFound(CodingKeys.nextCursor, .init(codingPath: decoder.codingPath, debugDescription: "nextCursor must be present and may be null"))
        }
        workspaceId = try container.decode(String.self, forKey: .workspaceId)
        epoch = try container.decode(String.self, forKey: .epoch)
        recovery = try container.decode(WorkspaceRecoveryEnvelope.self, forKey: .recovery)
        snapshotRevision = try container.decode(Int.self, forKey: .snapshotRevision)
        records = try container.decode([NativeStoredEncryptedRecord].self, forKey: .records)
        nextCursor = try container.decodeIfPresent(String.self, forKey: .nextCursor)
    }
}
private struct NativeSyncRecordResponse: Decodable { let workspaceId: String; let epoch: String; let record: NativeStoredEncryptedRecord }
private struct NativeSyncEnrollmentResponse: Decodable { let workspaceId: String; let epoch: String; let recovery: WorkspaceRecoveryEnvelope; let created: Bool }
private struct NativeSyncRecoveryReplacementResponse: Decodable { let workspaceId: String; let epoch: String; let recovery: WorkspaceRecoveryEnvelope; let snapshotRevision: Int; let idempotent: Bool }
private struct NativeSyncWorkspaceDeletionResponse: Decodable { let workspaceId: String; let deleted: Bool; let idempotent: Bool }
private struct NativeSyncWriteResponse: Decodable { let record: NativeStoredEncryptedRecord; let idempotent: Bool }
private struct NativeSyncEnrollRequest: Encodable { let kind = "enroll"; let workspaceId: String; let epoch: String; let recovery: WorkspaceRecoveryEnvelope }
private struct NativeSyncReplaceRecoveryRequest: Encodable { let kind = "replaceRecovery"; let workspaceId: String; let expectedEpoch: String; let expectedRevision: Int; let recovery: WorkspaceRecoveryEnvelope }
private struct NativeSyncDeleteWorkspaceRequest: Encodable { let kind = "deleteWorkspace"; let workspaceId: String; let expectedEpoch: String; let expectedRevision: Int }
private struct NativeSyncWriteRequest: Encodable {
    let kind = "write"
    let workspaceId: String
    let expectedRevision: Int?
    let envelope: EncryptedWorkspaceRecord
    private enum CodingKeys: String, CodingKey { case kind, workspaceId, expectedRevision, envelope }
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind);try container.encode(workspaceId, forKey: .workspaceId)
        if let expectedRevision { try container.encode(expectedRevision, forKey: .expectedRevision) }
        else { try container.encodeNil(forKey: .expectedRevision) }
        try container.encode(envelope, forKey: .envelope)
    }
}

struct NativeWorkspaceSyncAPI: Sendable {
    private static let maximumSafeInteger = 9_007_199_254_740_991
    let endpoints: NativeServiceEndpoints
    let transport: NativeHTTPPerforming

    init(
        endpoints: NativeServiceEndpoints = try! NativeServiceEndpoints(),
        transport: NativeHTTPPerforming = NativeURLSessionTransport()
    ) {
        self.endpoints = endpoints
        self.transport = transport
    }

    func list(bearer: String) async throws -> [NativeSyncWorkspaceSummary] {
        let response: NativeSyncWorkspaceList = try await get(queryItems: [], bearer: bearer)
        let workspaceIds = Set(response.workspaces.map(\.workspaceId))
        guard response.workspaces.count <= 20, workspaceIds.count == response.workspaces.count,
              response.workspaces.allSatisfy({ validWorkspaceIdentity($0.workspaceId, $0.epoch) && validTimestamp($0.updatedAt) }) else {
            throw SandboxError.blocked("SYNC_WORKSPACE_LIST_INVALID")
        }
        return response.workspaces
    }

    func readWorkspace(workspaceId: String, bearer: String) async throws -> NativeSyncWorkspaceSnapshot {
        guard validWorkspaceId(workspaceId) else { throw SandboxError.invalid("INVALID_WORKSPACE_ID") }
        for attempt in 0...1 {
            do { return try await readWorkspaceSnapshot(workspaceId: workspaceId, bearer: bearer) }
            catch let error as NativeServiceError where error.status == 409 && error.code == "SYNC_SNAPSHOT_CHANGED" && attempt == 0 {
                continue
            }
        }
        throw SandboxError.conflict("SYNC_SNAPSHOT_CHANGED")
    }

    func readRecord(workspaceId: String, recordId: String, bearer: String) async throws -> NativeStoredEncryptedRecord? {
        guard validWorkspaceId(workspaceId), recordId.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil else {
            throw SandboxError.invalid("INVALID_SYNC_RECORD_ID")
        }
        do {
            let response: NativeSyncRecordResponse = try await get(
                queryItems: [.init(name: "workspaceId", value: workspaceId), .init(name: "recordId", value: recordId)],
                bearer: bearer
            )
            guard response.workspaceId == workspaceId,
                  validWorkspaceIdentity(response.workspaceId, response.epoch),
                  response.record.envelope.recordId == recordId,
                  validStoredRecord(response.record, workspaceId: workspaceId, epoch: response.epoch) else {
                throw SandboxError.blocked("SYNC_RECORD_RESPONSE_INVALID")
            }
            return response.record
        } catch let error as NativeServiceError where error.status == 404 && error.code == "SYNC_RECORD_NOT_FOUND" {
            return nil
        }
    }

    func enroll(recovery: WorkspaceRecoveryEnvelope, bearer: String) async throws {
        guard validRecoveryWire(recovery) else { throw SandboxError.invalid("SYNC_RECOVERY_INVALID") }
        let value = NativeSyncEnrollRequest(workspaceId: recovery.workspaceId, epoch: recovery.epoch, recovery: recovery)
        let body = try NativeJSON.body(value, maximumBytes: NativeServiceLimits.syncRequestBytes)
        let request = try NativeRequestFactory.sync(endpoints: endpoints, method: "POST", body: body, bearer: bearer)
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.syncResponseBytes)
        let response = try NativeJSON.decode(NativeSyncEnrollmentResponse.self, from: result, maximumBytes: NativeServiceLimits.syncResponseBytes)
        guard response.workspaceId == recovery.workspaceId, response.epoch == recovery.epoch,
              response.recovery == recovery, validRecoveryWire(response.recovery) else {
            throw SandboxError.blocked("SYNC_ENROLLMENT_RESPONSE_INVALID")
        }
    }

    func replaceRecovery(
        workspaceId: String,
        expectedEpoch: String,
        expectedRevision: Int,
        recovery: WorkspaceRecoveryEnvelope,
        bearer: String
    ) async throws -> Int {
        guard validWorkspaceIdentity(workspaceId, expectedEpoch),
              (0...Self.maximumSafeInteger).contains(expectedRevision),
              recovery.workspaceId == workspaceId, recovery.epoch == expectedEpoch,
              validRecoveryWire(recovery) else {
            throw SandboxError.invalid("SYNC_RECOVERY_ROTATION_INVALID")
        }
        let value = NativeSyncReplaceRecoveryRequest(
            workspaceId: workspaceId,
            expectedEpoch: expectedEpoch,
            expectedRevision: expectedRevision,
            recovery: recovery
        )
        let body = try NativeJSON.body(value, maximumBytes: NativeServiceLimits.syncRequestBytes)
        let request = try NativeRequestFactory.sync(endpoints: endpoints, method: "POST", body: body, bearer: bearer)
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.syncResponseBytes)
        let response = try NativeJSON.decode(NativeSyncRecoveryReplacementResponse.self, from: result, maximumBytes: NativeServiceLimits.syncResponseBytes)
        guard response.workspaceId == workspaceId, response.epoch == expectedEpoch,
              response.recovery == recovery, validRecoveryWire(response.recovery),
              (expectedRevision...Self.maximumSafeInteger).contains(response.snapshotRevision),
              response.idempotent || response.snapshotRevision == expectedRevision + 1 else {
            throw SandboxError.blocked("SYNC_RECOVERY_ROTATION_RESPONSE_INVALID")
        }
        return response.snapshotRevision
    }

    func deleteWorkspace(
        workspaceId: String,
        expectedEpoch: String,
        expectedRevision: Int,
        bearer: String
    ) async throws {
        guard validWorkspaceIdentity(workspaceId, expectedEpoch),
              (0...Self.maximumSafeInteger).contains(expectedRevision) else {
            throw SandboxError.invalid("SYNC_WORKSPACE_DELETE_INVALID")
        }
        let value = NativeSyncDeleteWorkspaceRequest(
            workspaceId: workspaceId,
            expectedEpoch: expectedEpoch,
            expectedRevision: expectedRevision
        )
        let body = try NativeJSON.body(value, maximumBytes: NativeServiceLimits.syncRequestBytes)
        let request = try NativeRequestFactory.sync(endpoints: endpoints, method: "POST", body: body, bearer: bearer)
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.syncResponseBytes)
        let response = try NativeJSON.decode(NativeSyncWorkspaceDeletionResponse.self, from: result, maximumBytes: NativeServiceLimits.syncResponseBytes)
        guard response.workspaceId == workspaceId, response.deleted else {
            throw SandboxError.blocked("SYNC_WORKSPACE_DELETE_RESPONSE_INVALID")
        }
    }

    func write(workspaceId: String, expectedRevision: Int?, envelope: EncryptedWorkspaceRecord, bearer: String) async throws -> NativeStoredEncryptedRecord {
        let revisionIsValid = expectedRevision.map { (0...Self.maximumSafeInteger).contains($0) } ?? true
        guard validWorkspaceId(workspaceId),
              revisionIsValid,
              envelope.workspaceId == workspaceId, envelope.baseRevision == expectedRevision,
              validEncryptedEnvelopeWire(envelope) else {
            throw SandboxError.invalid("SYNC_WRITE_METADATA_MISMATCH")
        }
        let value = NativeSyncWriteRequest(workspaceId: workspaceId, expectedRevision: expectedRevision, envelope: envelope)
        let body = try NativeJSON.body(value, maximumBytes: NativeServiceLimits.syncRequestBytes)
        let request = try NativeRequestFactory.sync(endpoints: endpoints, method: "POST", body: body, bearer: bearer)
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.syncResponseBytes)
        do {
            let response = try NativeJSON.decode(NativeSyncWriteResponse.self, from: result, maximumBytes: NativeServiceLimits.syncResponseBytes)
            let nextRevision = expectedRevision.map { $0 + 1 } ?? 0
            guard response.record.revision == nextRevision, response.record.envelope == envelope,
                  validStoredRecord(response.record, workspaceId: workspaceId, epoch: envelope.epoch) else {
                throw SandboxError.blocked("SYNC_WRITE_RESPONSE_INVALID")
            }
            return response.record
        } catch let error as NativeServiceError {
            if let record = error.conflictRecord {
                guard record.envelope.recordId == envelope.recordId,
                      validStoredRecord(record, workspaceId: workspaceId, epoch: envelope.epoch) else {
                    throw SandboxError.blocked("SYNC_CONFLICT_RESPONSE_INVALID")
                }
            }
            throw error
        }
    }

    private func get<T: Decodable>(queryItems: [URLQueryItem], bearer: String) async throws -> T {
        try Task.checkCancellation()
        let request = try NativeRequestFactory.sync(endpoints: endpoints, method: "GET", queryItems: queryItems, bearer: bearer)
        let result = try await transport.perform(request, maximumResponseBytes: NativeServiceLimits.syncResponseBytes)
        return try NativeJSON.decode(T.self, from: result, maximumBytes: NativeServiceLimits.syncResponseBytes)
    }

    private func readWorkspaceSnapshot(workspaceId: String, bearer: String) async throws -> NativeSyncWorkspaceSnapshot {
        var cursor: String?
        var expectedRevision: Int?
        var expectedEpoch: String?
        var expectedRecovery: WorkspaceRecoveryEnvelope?
        var records: [NativeStoredEncryptedRecord] = []
        var recordIds = Set<String>()
        var previousRecordId: String?

        for pageNumber in 0..<250 {
            var query = [URLQueryItem(name: "workspaceId", value: workspaceId)]
            if let cursor, let expectedRevision {
                query.append(URLQueryItem(name: "cursor", value: cursor))
                query.append(URLQueryItem(name: "snapshotRevision", value: String(expectedRevision)))
            } else if cursor != nil || expectedRevision != nil {
                throw SandboxError.blocked("SYNC_PAGINATION_STATE_INVALID")
            }
            let page: NativeSyncWorkspacePage = try await get(queryItems: query, bearer: bearer)
            guard page.workspaceId == workspaceId, validWorkspaceIdentity(page.workspaceId, page.epoch),
                  (0...Self.maximumSafeInteger).contains(page.snapshotRevision), page.records.count <= 4,
                  validRecoveryWire(page.recovery), page.recovery.workspaceId == workspaceId, page.recovery.epoch == page.epoch,
                  page.records.allSatisfy({ validStoredRecord($0, workspaceId: workspaceId, epoch: page.epoch) }) else {
                throw SandboxError.blocked("SYNC_WORKSPACE_PAGE_INVALID")
            }
            if pageNumber == 0 {
                expectedRevision = page.snapshotRevision
                expectedEpoch = page.epoch
                expectedRecovery = page.recovery
            } else {
                guard page.snapshotRevision == expectedRevision, page.epoch == expectedEpoch, page.recovery == expectedRecovery else {
                    throw SandboxError.conflict("SYNC_SNAPSHOT_CHANGED")
                }
            }
            for record in page.records {
                let recordId = record.envelope.recordId
                let followsPrevious = previousRecordId.map { recordId > $0 } ?? true
                guard followsPrevious, recordIds.insert(recordId).inserted else {
                    throw SandboxError.blocked("SYNC_RECORD_ORDER_INVALID")
                }
                previousRecordId = recordId
                records.append(record)
                guard records.count <= 1_000 else { throw SandboxError.blocked("SYNC_RECORD_LIMIT") }
            }
            if let next = page.nextCursor {
                guard page.records.count == 4, next == page.records.last?.envelope.recordId,
                      next.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil,
                      pageNumber < 249 else {
                    throw SandboxError.blocked("SYNC_CURSOR_INVALID")
                }
                cursor = next
            } else {
                guard let revision = expectedRevision, let epoch = expectedEpoch, let recovery = expectedRecovery else {
                    throw SandboxError.blocked("SYNC_WORKSPACE_PAGE_INVALID")
                }
                return NativeSyncWorkspaceSnapshot(
                    workspaceId: workspaceId,
                    epoch: epoch,
                    recovery: recovery,
                    snapshotRevision: revision,
                    records: records
                )
            }
        }
        throw SandboxError.blocked("SYNC_PAGE_LIMIT")
    }

    private func validWorkspaceIdentity(_ workspaceId: String, _ epoch: String) -> Bool {
        validWorkspaceId(workspaceId) && epoch.range(of: "^[A-Za-z0-9_-]{16,64}$", options: .regularExpression) != nil
    }

    private func validWorkspaceId(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9_-]{32}$", options: .regularExpression) != nil
    }

    private func validEncryptedEnvelopeWire(_ value: EncryptedWorkspaceRecord) -> Bool {
        let revisionIsValid = value.baseRevision.map { (0...Self.maximumSafeInteger).contains($0) } ?? true
        let maximumDataCharacters: Int
        switch value.version {
        case 1: maximumDataCharacters = WorkspaceCrypto.legacyMaximumCiphertextCharacters
        case 2: maximumDataCharacters = WorkspaceCrypto.maximumCiphertextCharacters
        default: maximumDataCharacters = 0
        }
        return value.format == WorkspaceCrypto.recordFormat && maximumDataCharacters > 0 &&
        validWorkspaceIdentity(value.workspaceId, value.epoch) &&
        value.recordId.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil &&
        value.mutationId.range(of: "^[A-Za-z0-9_-]{16,64}$", options: .regularExpression) != nil &&
        value.iv.range(of: "^[A-Za-z0-9_-]{16}$", options: .regularExpression) != nil &&
        (22...maximumDataCharacters).contains(value.data.count) &&
        value.data.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil && revisionIsValid
    }

    private func validRecoveryWire(_ value: WorkspaceRecoveryEnvelope) -> Bool {
        value.format == WorkspaceCrypto.recoveryFormat && value.version == 1 &&
        validWorkspaceIdentity(value.workspaceId, value.epoch) &&
        value.kdf.name == "PBKDF2" && value.kdf.hash == "SHA-256" && value.kdf.iterations == WorkspaceCrypto.recoveryIterations &&
        value.kdf.salt.range(of: "^[A-Za-z0-9_-]{22}$", options: .regularExpression) != nil &&
        value.cipher.name == "AES-GCM" && value.cipher.iv.range(of: "^[A-Za-z0-9_-]{16}$", options: .regularExpression) != nil &&
        (22...4_096).contains(value.cipher.data.count) &&
        value.cipher.data.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil
    }

    private func validStoredRecord(_ value: NativeStoredEncryptedRecord, workspaceId: String, epoch: String) -> Bool {
        (0...Self.maximumSafeInteger).contains(value.revision) &&
        value.envelope.workspaceId == workspaceId && value.envelope.epoch == epoch &&
        validEncryptedEnvelopeWire(value.envelope)
    }

    private func validTimestamp(_ value: String) -> Bool {
        let standard = ISO8601DateFormatter()
        if standard.date(from: value) != nil { return true }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions.insert(.withFractionalSeconds)
        return fractional.date(from: value) != nil
    }
}

func isNativeDefaultSyncPath(_ path: String) -> Bool {
    let segments = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    guard segments.count >= 2,
          ["workspace", "output"].contains(segments[0]),
          !segments.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else { return false }
    let relativeSegments = segments.dropFirst().map { $0.lowercased() }
    let privateSegments: Set<String> = [
        "credential", "credentials", "private-export", "private-exports", "private_exports",
        "profile", "profiles", "signing", "signing-material"
    ]
    let privateFileNames: Set<String> = ["auth.json", "credential.json", "credentials.json", "profile.json"]
    let privateSuffixes = [".cer", ".key", ".mobileprovision", ".p12", ".p8", ".pem"]
    guard let fileName = relativeSegments.last else { return false }
    return !relativeSegments.contains(where: { privateSegments.contains($0) || $0 == ".env" || $0.hasPrefix(".env.") }) &&
        !privateFileNames.contains(fileName) &&
        !privateSuffixes.contains(where: fileName.hasSuffix)
}
