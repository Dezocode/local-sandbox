import CryptoKit
import Foundation

struct ShortcutPackage: Identifiable, Equatable, Sendable {
    let id: String
    let name: String
    let url: URL
    let sha256: String
    let bytes: Int
    let requires: [String]
}

struct ShortcutCatalog: Equatable, Sendable {
    let version: Int
    let release: String
    let status: String
    let packages: [ShortcutPackage]

    func validated(distributionOrigin: String = ShortcutPackageContract.canonicalOrigin) throws -> [ShortcutPackage] {
        try ShortcutPackageContract.validatedPackages(in: self, distributionOrigin: distributionOrigin)
    }

    func candidateDistributionOrigin() throws -> String {
        try ShortcutPackageContract.candidateDistributionOrigin(in: self)
    }
}

private struct ShortcutCatalogJSONKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private func requireExactJSONKeys(
    _ decoder: Decoder,
    expected: Set<String>,
    label: String
) throws {
    let container = try decoder.container(keyedBy: ShortcutCatalogJSONKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else {
        throw DecodingError.dataCorrupted(
            .init(codingPath: decoder.codingPath, debugDescription: "\(label) has missing or unexpected fields.")
        )
    }
}

extension ShortcutPackage: Decodable {
    private enum CodingKeys: String, CodingKey { case id, name, url, sha256, bytes, requires }

    init(from decoder: Decoder) throws {
        try requireExactJSONKeys(
            decoder,
            expected: ["bytes", "id", "name", "requires", "sha256", "url"],
            label: "Shortcut package"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        url = try container.decode(URL.self, forKey: .url)
        sha256 = try container.decode(String.self, forKey: .sha256)
        bytes = try container.decode(Int.self, forKey: .bytes)
        requires = try container.decode([String].self, forKey: .requires)
    }
}

extension ShortcutCatalog: Decodable {
    private enum CodingKeys: String, CodingKey { case version, release, status, packages }

    init(from decoder: Decoder) throws {
        try requireExactJSONKeys(
            decoder,
            expected: ["packages", "release", "status", "version"],
            label: "Shortcut catalog"
        )
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        release = try container.decode(String.self, forKey: .release)
        status = try container.decode(String.self, forKey: .status)
        packages = try container.decode([ShortcutPackage].self, forKey: .packages)
    }
}

enum ShortcutPackageOpenOutcome: Equatable, Sendable {
    case verified(String)
    case accepted(String)
    case rejected(String)

    var message: String {
        switch self {
        case .verified(let name):
            return "Verified \(name) from a local temporary copy. Waiting for iOS to answer the open request. Installation remains unconfirmed."
        case .accepted(let name):
            return "iOS accepted the request to open \(name) in the local Shortcut import flow. Installation remains unconfirmed until you accept it in Shortcuts."
        case .rejected(let name):
            return "Verified \(name), but iOS rejected the request to open its local copy. Installation remains unconfirmed."
        }
    }
}

enum ShortcutPackageValidationError: LocalizedError, Equatable, Sendable {
    case invalidCatalog
    case unavailableCatalogStatusRequired
    case signedCatalogRequired
    case invalidDistributionOrigin
    case invalidPackage
    case missingOrCircularDependency
    case redirectRejected
    case invalidHTTPResponse
    case httpStatus(Int)
    case sizeMismatch(expected: Int, actual: Int)
    case digestMismatch
    case temporaryFileVerificationFailed

    var errorDescription: String? {
        switch self {
        case .invalidCatalog:
            return "The Shortcut catalog is not the canonical Local Sandbox 0.3.0 catalog."
        case .unavailableCatalogStatusRequired:
            return "An empty Shortcut catalog must explicitly report that signed exports are unavailable."
        case .signedCatalogRequired:
            return "A nonempty Shortcut catalog must contain signed 0.3.0 packages awaiting device acceptance."
        case .invalidDistributionOrigin:
            return "Use one exact canonical HTTPS origin with no credentials, path, query, fragment, or explicit default port."
        case .invalidPackage:
            return "A Shortcut package did not match the canonical 0.3.0 package metadata."
        case .missingOrCircularDependency:
            return "A Shortcut package dependency is missing or circular."
        case .redirectRejected:
            return "Shortcut package redirects are not accepted."
        case .invalidHTTPResponse:
            return "The Shortcut package server did not return an HTTP response."
        case .httpStatus(let status):
            return "The Shortcut package server returned HTTP \(status), not 200."
        case .sizeMismatch(let expected, let actual):
            return "The Shortcut package size did not match its catalog entry (expected \(expected), received \(actual))."
        case .digestMismatch:
            return "The Shortcut package SHA-256 did not match its catalog entry."
        case .temporaryFileVerificationFailed:
            return "The verified Shortcut package could not be prepared as a local temporary file."
        }
    }
}

enum ShortcutPackageContract {
    static let catalogVersion = 1
    static let release = "0.3.0"
    static let canonicalOrigin = "https://local-sandbox.ctyy4wd4c2.chatgpt.site"
    static let signedStatus = "signed-awaiting-device-acceptance"
    static let unavailableStatus = "awaiting-signed-device-exports"
    static let maximumPackageBytes = 5_000_000

    static func canonicalPackageURL(id: String, distributionOrigin: String = canonicalOrigin) -> URL {
        URL(string: "\(distributionOrigin)/shortcuts/\(release)/\(id).shortcut")!
    }

    static func validatedDistributionOrigin(_ raw: String) throws -> String {
        guard let url = URL(string: raw),
              url.scheme == "https",
              url.host != nil,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil,
              url.path.isEmpty,
              url.port != 443 else {
            throw ShortcutPackageValidationError.invalidDistributionOrigin
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = url.host
        components.port = url.port
        guard let normalized = components.string, normalized == raw else {
            throw ShortcutPackageValidationError.invalidDistributionOrigin
        }
        return normalized
    }

    static func candidateDistributionOrigin(in catalog: ShortcutCatalog) throws -> String {
        guard let first = catalog.packages.first else {
            _ = try validatedPackages(in: catalog, distributionOrigin: canonicalOrigin)
            return canonicalOrigin
        }
        guard first.url.scheme == "https",
              first.url.host != nil,
              first.url.user == nil,
              first.url.password == nil,
              first.url.query == nil,
              first.url.fragment == nil else {
            throw ShortcutPackageValidationError.invalidDistributionOrigin
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = first.url.host
        components.port = first.url.port
        guard let candidate = components.string else {
            throw ShortcutPackageValidationError.invalidDistributionOrigin
        }
        let origin = try validatedDistributionOrigin(candidate)
        _ = try validatedPackages(in: catalog, distributionOrigin: origin)
        return origin
    }

    static func validatedPackages(in catalog: ShortcutCatalog, distributionOrigin rawOrigin: String) throws -> [ShortcutPackage] {
        let distributionOrigin = try validatedDistributionOrigin(rawOrigin)
        guard catalog.version == catalogVersion,
              catalog.release == release,
              catalog.packages.count <= 30,
              Set(catalog.packages.map(\.id)).count == catalog.packages.count,
              Set(catalog.packages.map(\.name)).count == catalog.packages.count else {
            throw ShortcutPackageValidationError.invalidCatalog
        }
        if catalog.packages.isEmpty {
            guard catalog.status == unavailableStatus else {
                throw ShortcutPackageValidationError.unavailableCatalogStatusRequired
            }
            return []
        }
        guard catalog.status == signedStatus else {
            throw ShortcutPackageValidationError.signedCatalogRequired
        }

        for package in catalog.packages {
            let nameScalars = package.name.unicodeScalars
            guard package.id.range(of: "^[a-z][a-z0-9-]{0,40}$", options: .regularExpression) != nil,
                  (1...80).contains(nameScalars.count),
                  nameScalars.allSatisfy({ (0x20...0x7e).contains($0.value) }),
                  nameScalars.first.map({ (0x21...0x7e).contains($0.value) }) == true,
                  nameScalars.last.map({ (0x21...0x7e).contains($0.value) }) == true else {
                throw ShortcutPackageValidationError.invalidPackage
            }
            let canonicalURL = canonicalPackageURL(id: package.id, distributionOrigin: distributionOrigin)
            guard package.url.absoluteString == canonicalURL.absoluteString,
                  (1...maximumPackageBytes).contains(package.bytes),
                  package.sha256.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                  Set(package.requires).count == package.requires.count,
                  package.requires.allSatisfy({ $0.range(of: "^[a-z][a-z0-9-]{0,40}$", options: .regularExpression) != nil }) else {
                throw ShortcutPackageValidationError.invalidPackage
            }
        }

        let packagesByID = Dictionary(uniqueKeysWithValues: catalog.packages.map { ($0.id, $0) })
        var ordered: [ShortcutPackage] = []
        var active = Set<String>()
        var visited = Set<String>()
        func visit(_ id: String) throws {
            if visited.contains(id) { return }
            guard !active.contains(id), let package = packagesByID[id] else {
                throw ShortcutPackageValidationError.missingOrCircularDependency
            }
            active.insert(id)
            for dependency in package.requires { try visit(dependency) }
            active.remove(id)
            visited.insert(id)
            ordered.append(package)
        }
        for package in catalog.packages { try visit(package.id) }
        return ordered
    }

    static func validateHTTPResponse(_ response: URLResponse, for package: ShortcutPackage) throws {
        guard let http = response as? HTTPURLResponse else {
            throw ShortcutPackageValidationError.invalidHTTPResponse
        }
        guard http.url?.absoluteString == package.url.absoluteString else {
            throw ShortcutPackageValidationError.redirectRejected
        }
        guard !(300...399).contains(http.statusCode) else {
            throw ShortcutPackageValidationError.redirectRejected
        }
        guard http.statusCode == 200 else {
            throw ShortcutPackageValidationError.httpStatus(http.statusCode)
        }
    }

    static func verifyDownloadedData(_ data: Data, for package: ShortcutPackage) throws {
        guard data.count == package.bytes else {
            throw ShortcutPackageValidationError.sizeMismatch(expected: package.bytes, actual: data.count)
        }
        guard sha256(data) == package.sha256 else {
            throw ShortcutPackageValidationError.digestMismatch
        }
    }

    static func materializeVerifiedPackage(
        _ data: Data,
        for package: ShortcutPackage,
        temporaryRoot: URL = FileManager.default.temporaryDirectory
    ) throws -> VerifiedShortcutPackage {
        try verifyDownloadedData(data, for: package)
        let manager = FileManager.default
        let directory = temporaryRoot
            .appendingPathComponent("LocalSandboxVerifiedShortcuts", isDirectory: true)
            .appendingPathComponent(release, isDirectory: true)
        let fileURL = directory.appendingPathComponent("\(package.id)-\(package.sha256.prefix(16)).shortcut")
        do {
            try manager.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(to: fileURL, options: .atomic)
            let readback = try Data(contentsOf: fileURL, options: .mappedIfSafe)
            try verifyDownloadedData(readback, for: package)
            return try VerifiedShortcutPackage(fileURL: fileURL)
        } catch {
            try? manager.removeItem(at: fileURL)
            if let validationError = error as? ShortcutPackageValidationError { throw validationError }
            throw ShortcutPackageValidationError.temporaryFileVerificationFailed
        }
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct VerifiedShortcutPackage: Equatable, Sendable {
    let fileURL: URL

    fileprivate init(fileURL: URL) throws {
        guard fileURL.isFileURL, fileURL.pathExtension == "shortcut" else {
            throw ShortcutPackageValidationError.temporaryFileVerificationFailed
        }
        self.fileURL = fileURL
    }
}

struct ShortcutPackageInstallGate: Equatable, Sendable {
    private(set) var activePackageID: String?
    var isBusy: Bool { activePackageID != nil }

    mutating func begin(_ packageID: String) -> Bool {
        guard activePackageID == nil else { return false }
        activePackageID = packageID
        return true
    }

    mutating func finish(_ packageID: String) {
        guard activePackageID == packageID else { return }
        activePackageID = nil
    }
}

private final class ShortcutPackageRedirectRejector: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

enum ShortcutPackageInstaller {
    static func downloadVerifiedPackage(_ package: ShortcutPackage) async throws -> VerifiedShortcutPackage {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.waitsForConnectivity = false
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: ShortcutPackageRedirectRejector(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        var request = URLRequest(url: package.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.httpMethod = "GET"
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        let (bytes, response) = try await session.bytes(for: request)
        try ShortcutPackageContract.validateHTTPResponse(response, for: package)

        var data = Data()
        data.reserveCapacity(package.bytes)
        for try await byte in bytes {
            guard data.count < package.bytes else {
                throw ShortcutPackageValidationError.sizeMismatch(expected: package.bytes, actual: data.count + 1)
            }
            data.append(byte)
            if data.count.isMultiple(of: 65_536) { try Task.checkCancellation() }
        }
        try Task.checkCancellation()
        return try ShortcutPackageContract.materializeVerifiedPackage(data, for: package)
    }
}
