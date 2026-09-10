import Foundation
import CryptoKit

@MainActor
final class SandboxStore {
    static let shared = SandboxStore()
    private var root: URL?
    private var scoped = false
    private let manager = FileManager.default
    private let encoder = JSONEncoder()
    private init() { encoder.outputFormatting = [.prettyPrinted, .sortedKeys] }
    var connected: Bool { root != nil }
    var folderName: String { root == nil ? "Not prepared" : scoped ? (root?.lastPathComponent ?? "Selected folder") : "On this iPhone" }
    func connect(_ url: URL) throws {
        guard url.startAccessingSecurityScopedResource() else { throw SandboxError.blocked("FOLDER_PERMISSION_REQUIRED") }
        defer { url.stopAccessingSecurityScopedResource() }
        let bookmark = try url.bookmarkData(options: .minimalBookmark, includingResourceValuesForKeys: nil, relativeTo: nil)
        UserDefaults.standard.set(bookmark, forKey: "sandboxBookmark")
        scoped = true
        root = url.standardizedFileURL
        for name in ["config", "workspace", "state", "logs", "output"] {
            try manager.createDirectory(at: url.appendingPathComponent(name), withIntermediateDirectories: true)
        }
    }
    func restore() throws {
        guard Keychain.get("appleUser") != nil else { return }
        guard let data = UserDefaults.standard.data(forKey: "sandboxBookmark") else { try useLocal(); return }
        var stale = false
        let url = try URL(resolvingBookmarkData: data, options: [], relativeTo: nil, bookmarkDataIsStale: &stale)
        try connect(url)
    }
    func useLocal() throws {
        guard let user = Keychain.get("appleUser") else { throw SandboxError.blocked("Sign in with Apple first.") }
        let base = try manager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let folder = base.appendingPathComponent("LocalSandbox").appendingPathComponent(Self.hash(user))
        for name in ["config", "workspace", "state", "logs", "output"] {
            try manager.createDirectory(at: folder.appendingPathComponent(name), withIntermediateDirectories: true, attributes: [.protectionKey: FileProtectionType.complete])
        }
        root = folder; scoped = false
        UserDefaults.standard.removeObject(forKey: "sandboxBookmark")
    }
    func disconnect() { root = nil; UserDefaults.standard.removeObject(forKey: "sandboxBookmark") }
    private func access<T>(_ operation: (URL) throws -> T) throws -> T {
        guard Keychain.get("appleUser") != nil, let root else { throw SandboxError.blocked("Sign in and prepare your workspace first.") }
        if scoped && !root.startAccessingSecurityScopedResource() { throw SandboxError.blocked("FOLDER_PERMISSION_REQUIRED") }
        defer { if scoped { root.stopAccessingSecurityScopedResource() } }
        return try operation(root)
    }
    private func resolve(_ path: SandboxPath, under root: URL) throws -> URL {
        let base = root.resolvingSymlinksInPath().standardizedFileURL
        let target = base.appendingPathComponent(path.value).resolvingSymlinksInPath().standardizedFileURL
        guard target.path.hasPrefix(base.path + "/") else { throw SandboxError.invalid("SYMLINK_OUTSIDE_SANDBOX") }
        return target
    }
    func read(_ path: SandboxPath) throws -> String {
        try access { root in
            let url = try resolve(path, under: root)
            var error: NSError?; var output: Result<String, Error>?
            NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &error) { coordinated in
                output = Result {
                    let size = try coordinated.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= 64000 else { throw SandboxError.invalid("FILE_TOO_LARGE") }
                    return try String(contentsOf: coordinated, encoding: .utf8)
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_READ_UNAVAILABLE") }
            return try output.get()
        }
    }
    func write(_ path: SandboxPath, content: String, createOnly: Bool = false, expectedSHA256: String? = nil) throws {
        guard content.utf8.count <= 64000 else { throw SandboxError.invalid("FILE_TOO_LARGE") }
        try access { root in
            let url = try resolve(path, under: root)
            try manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            var error: NSError?; var output: Result<Void, Error>?
            NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &error) { coordinated in
                output = Result {
                    if createOnly && manager.fileExists(atPath: coordinated.path) { throw SandboxError.conflict("FILE_EXISTS") }
                    if let expectedSHA256 {
                        let actual = try String(contentsOf: coordinated, encoding: .utf8)
                        guard Self.hash(actual) == expectedSHA256 else { throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED") }
                    }
                    try content.write(to: coordinated, atomically: true, encoding: .utf8)
                    if !self.scoped { try self.manager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: coordinated.path) }
                    guard try String(contentsOf: coordinated, encoding: .utf8) == content else { throw SandboxError.conflict("READBACK_FAILED") }
                }
            }
            if let error { throw error }
            guard let output else { throw SandboxError.blocked("ICLOUD_WRITE_UNAVAILABLE") }
            try output.get()
        }
    }
    func list(_ folder: String) throws -> [String] {
        guard ["workspace", "config", "state", "logs", "output"].contains(folder) else { throw SandboxError.invalid("INVALID_FOLDER") }
        return try access { root in
            let directory = root.appendingPathComponent(folder).resolvingSymlinksInPath()
            guard directory.path.hasPrefix(root.resolvingSymlinksInPath().path + "/") else { throw SandboxError.invalid("SYMLINK_OUTSIDE_SANDBOX") }
            return try manager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).prefix(100).map { folder + "/" + $0.lastPathComponent }.sorted()
        }
    }
    func save<T: Encodable>(_ value: T, path: String) throws { try write(SandboxPath(path), content: String(decoding: encoder.encode(value), as: UTF8.self)) }
    func load<T: Decodable>(_ type: T.Type, path: String) throws -> T { try JSONDecoder().decode(type, from: Data(read(SandboxPath(path)).utf8)) }
    func receipts() throws -> [RunReceipt] { try list("logs").filter { $0.hasSuffix(".json") && !$0.contains("call-") }.compactMap { try? load(RunReceipt.self, path: $0) }.sorted { $0.createdAt > $1.createdAt } }
    static func hash(_ text: String) -> String { SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined() }
}
