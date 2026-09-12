import Foundation

@MainActor
final class SandboxStore {
    static let shared = SandboxStore()
    var connected = true

    func exists(_ path: SandboxPath) throws -> Bool { false }
    func write(_ path: SandboxPath, content: String, createOnly: Bool = false) throws {}
    func load<T: Decodable>(_ type: T.Type, path: String) throws -> T {
        fatalError("Workspace preparation tests inject storage operations")
    }
    func save<T: Encodable>(_ value: T, path: String) throws {}
}

@MainActor
enum ProviderQualificationStore {
    static func prepare() throws {}
}

@MainActor
enum LocalSandboxShortcuts {
    static func updateAppShortcutParameters() {}
}

let nativeOraclePolicy = "portable workspace preparation policy"
