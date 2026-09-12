import Foundation

enum GitHubTransportLimits {
    // GitHub's recursive tree API truncates at roughly 7 MB. This cap admits that
    // documented response while preventing an unbounded allocation on the phone.
    static let responseBytes = 8 * 1_024 * 1_024
}

struct GitHubHTTPResult {
    let data: Data
    let response: HTTPURLResponse
}

struct GitHubCredentialDisconnect {
    let deleteChecked: () throws -> Void
    let readChecked: () throws -> String?

    func perform() throws {
        try deleteChecked()
        guard try readChecked() == nil else {
            throw SandboxError.blocked("GITHUB_CREDENTIAL_DELETE_FAILED")
        }
    }
}

protocol GitHubHTTPPerforming: Sendable {
    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> GitHubHTTPResult
}

private final class GitHubRedirectRefusalDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
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

final class GitHubURLSessionTransport: GitHubHTTPPerforming, @unchecked Sendable {
    private let protocolClasses: [AnyClass]?

    init(protocolClasses: [AnyClass]? = nil) {
        self.protocolClasses = protocolClasses
    }

    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> GitHubHTTPResult {
        guard maximumResponseBytes > 0 else {
            throw SandboxError.invalid("GITHUB_RESPONSE_BOUND_INVALID")
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpCookieStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 25
        configuration.timeoutIntervalForResource = 30
        if let protocolClasses { configuration.protocolClasses = protocolClasses }
        let delegate = GitHubRedirectRefusalDelegate()
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)

        return try await withTaskCancellationHandler {
            defer { session.invalidateAndCancel() }
            do {
                let (bytes, rawResponse) = try await session.bytes(for: request)
                try Task.checkCancellation()
                guard let response = rawResponse as? HTTPURLResponse else {
                    throw SandboxError.blocked("GITHUB_RESPONSE_INVALID")
                }
                guard (200...299).contains(response.statusCode) else {
                    throw SandboxError.blocked("GITHUB_REQUEST_FAILED")
                }
                guard Self.isJSON(response.value(forHTTPHeaderField: "Content-Type")) else {
                    throw SandboxError.blocked("GITHUB_RESPONSE_CONTENT_TYPE_INVALID")
                }
                guard response.expectedContentLength < 0
                        || response.expectedContentLength <= Int64(maximumResponseBytes) else {
                    throw SandboxError.blocked("GITHUB_RESPONSE_TOO_LARGE")
                }

                var data = Data()
                if response.expectedContentLength > 0 {
                    data.reserveCapacity(min(Int(response.expectedContentLength), maximumResponseBytes))
                }
                for try await byte in bytes {
                    try Task.checkCancellation()
                    guard data.count < maximumResponseBytes else {
                        throw SandboxError.blocked("GITHUB_RESPONSE_TOO_LARGE")
                    }
                    data.append(byte)
                }
                try Task.checkCancellation()
                return GitHubHTTPResult(data: data, response: response)
            } catch let error as URLError where error.code == .cancelled && Task.isCancelled {
                throw CancellationError()
            }
        } onCancel: {
            session.invalidateAndCancel()
        }
    }

    private static func isJSON(_ rawContentType: String?) -> Bool {
        guard let rawContentType,
              let mediaType = rawContentType
                .split(separator: ";", maxSplits: 1)
                .first?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased() else {
            return false
        }
        return mediaType == "application/json"
            || (mediaType.hasPrefix("application/") && mediaType.hasSuffix("+json"))
    }
}
