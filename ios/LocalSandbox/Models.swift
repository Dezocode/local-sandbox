import Foundation

struct ResourcePolicy: Codable, Equatable {
    var batteryBudget = 15
    var batteryReserve = 20
    var memoryTarget = 35
    var maxSteps = 6
    var maxFailures = 3
    var contextChars = 6000
    var cloudAllowed = false
    var notifications = true
    var provider = "local"
    var localShortcut = "Agent Step - Local"
    func validated() throws -> Self {
        guard (1...80).contains(batteryBudget), (5...80).contains(batteryReserve),
              (10...80).contains(memoryTarget), (1...24).contains(maxSteps),
              (1...3).contains(maxFailures), (2000...12000).contains(contextChars),
              ["local", "apple", "chatgpt", "grok", "grokbot", "claude"].contains(provider), !localShortcut.isEmpty,
              localShortcut.count <= 80 else { throw SandboxError.invalid("INVALID_POLICY") }
        return self
    }
}
enum SandboxError: LocalizedError {
    case invalid(String), blocked(String), conflict(String)
    var errorDescription: String? {
        switch self { case .invalid(let value), .blocked(let value), .conflict(let value): return value }
    }
}
struct SandboxPath: Hashable {
    let value: String
    init(_ raw: String) throws {
        let segments = raw.split(separator: "/", omittingEmptySubsequences: false)
        guard raw.utf8.count <= 180, segments.count >= 2,
              ["workspace", "config", "state", "logs", "output"].contains(String(segments[0])),
              segments.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              raw.range(of: "^[A-Za-z0-9][A-Za-z0-9._/-]*$", options: .regularExpression) != nil
        else { throw SandboxError.invalid("PATH_OUTSIDE_SANDBOX") }
        self.value = raw
    }
}
enum ToolName: String, Codable {
    case read = "file.read", list = "file.list", create = "file.create", append = "file.append", patch = "file.patch"
    case clipboardGet = "device.clipboard_get", clipboardSet = "device.clipboard_set", notify = "device.notify"
}
struct ToolCall: Codable {
    let tool: ToolName
    let arguments: [String: String]
    func validated() throws -> Self {
        let keys: Set<String>
        switch tool {
        case .read, .list: keys = ["path"]
        case .create: keys = ["path", "content"]
        case .append: keys = ["path", "content", "expectedSHA256"]
        case .patch: keys = ["path", "old", "replacement", "expectedSHA256"]
        case .clipboardGet: keys = []
        case .clipboardSet, .notify: keys = ["content"]
        }
        guard Set(arguments.keys) == keys, arguments.values.allSatisfy({ $0.utf8.count <= 32000 }) else { throw SandboxError.invalid("INVALID_ARGUMENT") }
        return self
    }
}
enum AgentAction {
    case tool(ToolCall)
    case final(String)
    static func parse(_ text: String) throws -> Self {
        guard let bytes = text.data(using: .utf8), bytes.count <= 16000,
              let json = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let kind = json["kind"] as? String else { throw SandboxError.invalid("INVALID_ACTION_JSON") }
        switch kind {
        case "tool":
            guard Set(json.keys) == ["kind", "tool", "arguments"], let name = json["tool"] as? String,
                  let tool = ToolName(rawValue: name), let arguments = json["arguments"] as? [String: String]
            else { throw SandboxError.invalid("INVALID_TOOL_ACTION") }
            return .tool(try ToolCall(tool: tool, arguments: arguments).validated())
        case "final":
            guard Set(json.keys).isSubset(of: ["kind", "summary", "verified"]), let summary = json["summary"] as? String, !summary.isEmpty, summary.count <= 2000
            else { throw SandboxError.invalid("INVALID_FINAL_ACTION") }
            return .final(summary)
        default: throw SandboxError.invalid("UNKNOWN_ACTION_KIND")
        }
    }
}
struct ToolResult: Codable {
    let ok: Bool
    let tool: String
    let result: String
    let sha256: String?
    let error_code: String?
    var json: String { (try? String(decoding: JSONEncoder().encode(self), as: UTF8.self)) ?? "{}" }
}
enum RunStatus: String, Codable { case verified, blocked, cancelled }
struct TraceEntry: Codable { let tool: String; let status: String; let detail: String }
struct RunReceipt: Codable, Identifiable {
    let id: String
    let goal: String
    let status: RunStatus
    let origin: String
    let summary: String
    let steps: Int
    let failures: Int
    let durationMs: Double
    let createdAt: String
    let trace: [TraceEntry]
}
struct RunCheckpoint: Codable {
    let runID: String
    let goal: String
    let nextStep: Int
    let capsule: String
    let lastResult: String
    let phase: String
}
func exactPatch(_ content: String, old: String, replacement: String) throws -> String {
    guard !old.isEmpty, let range = content.range(of: old) else { throw SandboxError.conflict("PATCH_CONTEXT_NOT_FOUND") }
    let nextStart = content.index(after: range.lowerBound)
    guard content.range(of: old, range: nextStart..<content.endIndex) == nil else { throw SandboxError.conflict("PATCH_CONTEXT_AMBIGUOUS") }
    var result = content; result.replaceSubrange(range, with: replacement); return result
}
