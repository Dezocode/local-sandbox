import Foundation

extension JSONEncoder {
    static var sorted: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

extension ToolName {
    static var allNames: [String] {
        [read, list, create, append, patch, clipboardGet, clipboardSet, notify].map(\.rawValue)
    }
}

@MainActor
enum ProviderRuntimeCapabilities {
    static var appleModel: AppleModelAvailability = .available
    static var shortcutsAvailable = true
}

@MainActor
enum AdapterSettings {
    private static var values: [AppProvider: ShortcutAdapter] = [:]

    static func get(_ provider: AppProvider) -> ShortcutAdapter {
        values[provider] ?? ShortcutAdapter(name: provider.shortcut)
    }

    static func set(_ value: ShortcutAdapter, for provider: AppProvider) {
        values[provider] = value
    }

    static func markMeasuredRoundTrip(for provider: AppProvider) throws {
        var value = get(provider)
        value.tested = true
        values[provider] = value
    }

    static func invalidateMeasuredRoundTrip(for provider: AppProvider) throws {
        var value = get(provider)
        value.tested = false
        values[provider] = value
    }
}

@MainActor
final class SandboxStore {
    static let shared = SandboxStore()
    var connected = true
}

@MainActor
final class AgentRunner {
    static let shared = AgentRunner()
    var running = false
}

struct QualificationShortcutSession {
    let phase: String
}

@MainActor
final class ShortcutCoordinator {
    static let shared = ShortcutCoordinator()
    func current() -> QualificationShortcutSession? { nil }
}

@MainActor
enum Keychain {
    private static var values: [String: String] = ["appleUser": "portable-test-user"]

    static func get(_ key: String) -> String? { values[key] }
    static func getChecked(_ key: String) throws -> String? { values[key] }
    static func set(_ value: String, for key: String, synchronizable: Bool = false) throws { values[key] = value }
    static func delete(_ key: String) { values.removeValue(forKey: key) }
    static func deleteChecked(_ key: String) throws { values.removeValue(forKey: key) }
}

struct AppleProvider {
    func step(goal: String, capsule: String, latest: String, policy: ResourcePolicy) async throws -> String {
        "{\"kind\":\"final\",\"summary\":\"portable-typecheck-only\"}"
    }

    func qualificationResponse(prompt: String) async throws -> String {
        "{\"kind\":\"final\",\"summary\":\"portable-typecheck-only\"}"
    }
}
