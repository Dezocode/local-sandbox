import Foundation

private final class ChunkedGitHubURLProtocol: URLProtocol, @unchecked Sendable {
    static let exactBody = Data("1234567890123456".utf8)
    static let stallStarted = DispatchSemaphore(value: 0)
    static let stallStopped = DispatchSemaphore(value: 0)

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "github-stream.test"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: SandboxError.blocked("TEST_URL_INVALID"))
            return
        }
        let path = url.path
        let status = path == "/bad-status" ? 503 : 200
        var headers = ["Content-Type": path == "/bad-type" ? "text/html" : "application/vnd.github+json; charset=utf-8"]
        if path == "/exact-length" {
            headers["Content-Length"] = String(Self.exactBody.count)
        } else if path == "/oversized-length" {
            headers["Content-Length"] = String(Self.exactBody.count + 1)
        }
        guard let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        ) else {
            client?.urlProtocol(self, didFailWithError: SandboxError.blocked("TEST_RESPONSE_INVALID"))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        switch path {
        case "/exact-length":
            client?.urlProtocol(self, didLoad: Self.exactBody)
            client?.urlProtocolDidFinishLoading(self)
        case "/exact-chunked":
            client?.urlProtocol(self, didLoad: Data(Self.exactBody.prefix(5)))
            client?.urlProtocol(self, didLoad: Data(Self.exactBody.dropFirst(5).prefix(7)))
            client?.urlProtocol(self, didLoad: Data(Self.exactBody.dropFirst(12)))
            client?.urlProtocolDidFinishLoading(self)
        case "/oversized-chunked":
            client?.urlProtocol(self, didLoad: Data(Self.exactBody.prefix(8)))
            client?.urlProtocol(self, didLoad: Data(Self.exactBody.dropFirst(8)))
            client?.urlProtocol(self, didLoad: Data("X".utf8))
            client?.urlProtocolDidFinishLoading(self)
        case "/oversized-length":
            break
        case "/stall":
            client?.urlProtocol(self, didLoad: Data("{".utf8))
            Self.stallStarted.signal()
        default:
            client?.urlProtocol(self, didLoad: Data("{}".utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }

    override func stopLoading() {
        if request.url?.path == "/stall" { Self.stallStopped.signal() }
    }
}

@main
enum GitHubTransportContractTests {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }

    static func request(_ path: String) -> URLRequest {
        URLRequest(url: URL(string: "https://github-stream.test\(path)")!)
    }

    static func main() async throws {
        let maximumBytes = ChunkedGitHubURLProtocol.exactBody.count
        let transport = GitHubURLSessionTransport(protocolClasses: [ChunkedGitHubURLProtocol.self])

        let exactLength = try await transport.perform(
            request("/exact-length"),
            maximumResponseBytes: maximumBytes
        )
        require(exactLength.data == ChunkedGitHubURLProtocol.exactBody, "exact Content-Length boundary was rejected")

        let exactChunked = try await transport.perform(
            request("/exact-chunked"),
            maximumResponseBytes: maximumBytes
        )
        require(exactChunked.data == ChunkedGitHubURLProtocol.exactBody, "exact chunked boundary changed bytes")

        try await requireFailure(
            path: "/oversized-length",
            maximumBytes: maximumBytes,
            expected: "GITHUB_RESPONSE_TOO_LARGE",
            transport: transport
        )
        try await requireFailure(
            path: "/oversized-chunked",
            maximumBytes: maximumBytes,
            expected: "GITHUB_RESPONSE_TOO_LARGE",
            transport: transport
        )
        try await requireFailure(
            path: "/bad-status",
            maximumBytes: maximumBytes,
            expected: "GITHUB_REQUEST_FAILED",
            transport: transport
        )
        try await requireFailure(
            path: "/bad-type",
            maximumBytes: maximumBytes,
            expected: "GITHUB_RESPONSE_CONTENT_TYPE_INVALID",
            transport: transport
        )

        let stalled = Task.detached {
            try await transport.perform(request("/stall"), maximumResponseBytes: maximumBytes)
        }
        require(
            ChunkedGitHubURLProtocol.stallStarted.wait(timeout: .now() + 2) == .success,
            "stalled GitHub response did not begin"
        )
        stalled.cancel()
        do {
            _ = try await stalled.value
            fatalError("cancelled GitHub response reported success")
        } catch is CancellationError {}
        require(
            ChunkedGitHubURLProtocol.stallStopped.wait(timeout: .now() + 2) == .success,
            "task cancellation did not cancel the underlying GitHub request"
        )

        var credential: String? = "github_pat_test"
        try GitHubCredentialDisconnect(
            deleteChecked: { credential = nil },
            readChecked: { credential }
        ).perform()
        require(credential == nil, "checked GitHub disconnect retained the credential")

        credential = "github_pat_test"
        do {
            try GitHubCredentialDisconnect(
                deleteChecked: { throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED") },
                readChecked: { credential }
            ).perform()
            fatalError("failing GitHub credential deletion reported success")
        } catch let error as SandboxError {
            require(error.localizedDescription == "KEYCHAIN_DELETE_FAILED", "GitHub disconnect hid the Keychain deletion failure")
        }
        require(credential != nil, "failing GitHub credential deletion cleared the test credential")

        do {
            try GitHubCredentialDisconnect(
                deleteChecked: {},
                readChecked: { credential }
            ).perform()
            fatalError("GitHub disconnect accepted a credential that remained after deletion")
        } catch let error as SandboxError {
            require(error.localizedDescription == "GITHUB_CREDENTIAL_DELETE_FAILED", "GitHub disconnect returned the wrong absent-state error")
        }
        require(credential != nil, "absent-state failure changed the retained credential")

        print("GitHub transport contracts passed: JSON/status validation, exact byte boundaries, chunked overflow rejection, cancellation, and checked credential disconnect.")
    }

    static func requireFailure(
        path: String,
        maximumBytes: Int,
        expected: String,
        transport: GitHubURLSessionTransport
    ) async throws {
        do {
            _ = try await transport.perform(request(path), maximumResponseBytes: maximumBytes)
            fatalError("GitHub transport accepted \(path)")
        } catch let error as SandboxError {
            require(error.localizedDescription == expected, "\(path) returned \(error.localizedDescription), expected \(expected)")
        }
    }
}
