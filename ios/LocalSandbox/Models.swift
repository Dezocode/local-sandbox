import CryptoKit
import Foundation

enum NativeDigest {
    static func sha256(_ text: String) -> String {
        sha256(Data(text.utf8))
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct ResourcePolicy: Codable, Equatable {
    var batteryBudget = 15
    var batteryReserve = 20
    var memoryTarget = 35
    var maxSteps = 6
    var maxFailures = 3
    var contextChars = 6000
    var cloudAllowed = false
    var notifications = true
    var clipboardReadAllowed = false
    var clipboardWriteAllowed = false
    var provider = "local"
    var localShortcut = "Agent Step - Local"

    init() {}

    private enum CodingKeys: String, CodingKey {
        case recordType, schemaVersion, batteryBudget, batteryReserve, memoryTarget
        case maxSteps, maxFailures, contextChars, cloudAllowed, notifications, clipboardReadAllowed, clipboardWriteAllowed, provider, localShortcut
    }

    init(from decoder: Decoder) throws {
        self.init()
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0
        guard version <= 2 else { throw SandboxError.invalid("UNSUPPORTED_POLICY_VERSION") }
        if let recordType = try container.decodeIfPresent(String.self, forKey: .recordType), recordType != "resource-policy" {
            throw SandboxError.invalid("WRONG_POLICY_RECORD_TYPE")
        }
        batteryBudget = try container.decodeIfPresent(Int.self, forKey: .batteryBudget) ?? batteryBudget
        batteryReserve = try container.decodeIfPresent(Int.self, forKey: .batteryReserve) ?? batteryReserve
        memoryTarget = try container.decodeIfPresent(Int.self, forKey: .memoryTarget) ?? memoryTarget
        maxSteps = try container.decodeIfPresent(Int.self, forKey: .maxSteps) ?? maxSteps
        maxFailures = try container.decodeIfPresent(Int.self, forKey: .maxFailures) ?? maxFailures
        contextChars = try container.decodeIfPresent(Int.self, forKey: .contextChars) ?? contextChars
        cloudAllowed = try container.decodeIfPresent(Bool.self, forKey: .cloudAllowed) ?? cloudAllowed
        notifications = try container.decodeIfPresent(Bool.self, forKey: .notifications) ?? notifications
        clipboardReadAllowed = try container.decodeIfPresent(Bool.self, forKey: .clipboardReadAllowed) ?? false
        clipboardWriteAllowed = try container.decodeIfPresent(Bool.self, forKey: .clipboardWriteAllowed) ?? false
        provider = try container.decodeIfPresent(String.self, forKey: .provider) ?? provider
        if provider == "openai" { provider = "chatgpt" }
        localShortcut = try container.decodeIfPresent(String.self, forKey: .localShortcut) ?? localShortcut
        _ = try validated()
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("resource-policy", forKey: .recordType)
        try container.encode(2, forKey: .schemaVersion)
        try container.encode(batteryBudget, forKey: .batteryBudget)
        try container.encode(batteryReserve, forKey: .batteryReserve)
        try container.encode(memoryTarget, forKey: .memoryTarget)
        try container.encode(maxSteps, forKey: .maxSteps)
        try container.encode(maxFailures, forKey: .maxFailures)
        try container.encode(contextChars, forKey: .contextChars)
        try container.encode(cloudAllowed, forKey: .cloudAllowed)
        try container.encode(notifications, forKey: .notifications)
        try container.encode(clipboardReadAllowed, forKey: .clipboardReadAllowed)
        try container.encode(clipboardWriteAllowed, forKey: .clipboardWriteAllowed)
        try container.encode(provider, forKey: .provider)
        try container.encode(localShortcut, forKey: .localShortcut)
    }

    func validated() throws -> Self {
        guard (1...80).contains(batteryBudget), (5...80).contains(batteryReserve),
              (10...80).contains(memoryTarget), (1...24).contains(maxSteps),
              (1...3).contains(maxFailures), (2000...12000).contains(contextChars),
              ["local", "apple", "chatgpt", "grok", "grokbot", "claude"].contains(provider), !localShortcut.isEmpty,
              localShortcut.count <= 80 else { throw SandboxError.invalid("INVALID_POLICY") }
        return self
    }
}

@MainActor
enum SavedExecutionAuthorization {
    static func load() throws -> ResourcePolicy {
        guard let data = UserDefaults.standard.data(forKey: "policy"),
              let saved = try? JSONDecoder().decode(ResourcePolicy.self, from: data).validated() else {
            throw SandboxError.blocked("SAVE_AUTHORIZATION_BEFORE_RUNNING")
        }
        return saved
    }

    static func requireExact(_ expected: ResourcePolicy) throws {
        guard try load() == expected else {
            throw SandboxError.blocked("SAVE_AUTHORIZATION_BEFORE_RUNNING")
        }
    }
}

enum ProviderTaskOrigin: String, Codable {
    case app = "app-handoff"
    case appIntent = "app-intent"
}

enum SandboxError: LocalizedError {
    case invalid(String), blocked(String), conflict(String)
    var errorDescription: String? {
        switch self {
        case .invalid(let value), .blocked(let value), .conflict(let value): return value
        }
    }
}

enum ReceiptWireContract {
    /// Leaves storage-row margin below the hosted database's 2,000,000-byte value limit.
    static let maximumSerializedUTF8Bytes = 1_900_000

    static func scalarCount(_ value: String) -> Int {
        value.unicodeScalars.count
    }

    static func containsScalarCount(_ value: String, in range: ClosedRange<Int>) -> Bool {
        range.contains(scalarCount(value))
    }

    static func validateSerializedByteCount(_ count: Int) throws {
        guard (0...maximumSerializedUTF8Bytes).contains(count) else {
            throw SandboxError.invalid("RECEIPT_WIRE_TOO_LARGE")
        }
    }

    /// RFC 3339 full-date/time with seconds, 0...9 fractional digits, and Z/z or ±HH:MM.
    /// Components are checked explicitly because formatter grammars differ across OS versions.
    static func isValidDateTime(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard (20...35).contains(bytes.count),
              bytes[4] == 0x2D, bytes[7] == 0x2D, bytes[10] == 0x54,
              bytes[13] == 0x3A, bytes[16] == 0x3A else { return false }

        func decimal(_ start: Int, _ end: Int) -> Int? {
            var result = 0
            for index in start..<end {
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { return nil }
                result = result * 10 + Int(bytes[index] - 0x30)
            }
            return result
        }

        guard let year = decimal(0, 4),
              let month = decimal(5, 7),
              let day = decimal(8, 10),
              let hour = decimal(11, 13),
              let minute = decimal(14, 16),
              let second = decimal(17, 19),
              (1...12).contains(month),
              (0...23).contains(hour),
              (0...59).contains(minute),
              (0...59).contains(second) else { return false }

        let leapYear = year.isMultiple(of: 4) && (!year.isMultiple(of: 100) || year.isMultiple(of: 400))
        let maximumDay: Int
        switch month {
        case 2: maximumDay = leapYear ? 29 : 28
        case 4, 6, 9, 11: maximumDay = 30
        default: maximumDay = 31
        }
        guard (1...maximumDay).contains(day) else { return false }

        var index = 19
        if bytes[index] == 0x2E {
            index += 1
            let fractionStart = index
            while index < bytes.count,
                  (0x30...0x39).contains(bytes[index]),
                  index - fractionStart < 9 {
                index += 1
            }
            guard (1...9).contains(index - fractionStart) else { return false }
        }
        guard index < bytes.count else { return false }
        if bytes[index] == 0x5A || bytes[index] == 0x7A {
            return index + 1 == bytes.count
        }
        guard bytes[index] == 0x2B || bytes[index] == 0x2D,
              index + 6 == bytes.count,
              bytes[index + 3] == 0x3A,
              let offsetHour = decimal(index + 1, index + 3),
              let offsetMinute = decimal(index + 4, index + 6),
              (0...23).contains(offsetHour),
              (0...59).contains(offsetMinute) else { return false }
        return true
    }
}

struct StrictJSONLimits: Sendable, Equatable {
    let maximumBytes: Int
    let maximumDepth: Int
    /// Counts object members and array elements across the entire document.
    let maximumMembers: Int

    static let providerResponse = Self(maximumBytes: 16_000, maximumDepth: 16, maximumMembers: 128)
    static let receipt = Self(maximumBytes: ReceiptWireContract.maximumSerializedUTF8Bytes, maximumDepth: 32, maximumMembers: 4_096)
    static let traceDetail = Self(maximumBytes: 64_000, maximumDepth: 16, maximumMembers: 64)
    static let qualificationLedger = Self(maximumBytes: 512_000, maximumDepth: 16, maximumMembers: 8_192)
}

/// Validates raw JSON before Foundation can collapse duplicate object members.
enum StrictJSON {
    static func validate(_ data: Data, limits: StrictJSONLimits) throws {
        guard (1...ReceiptWireContract.maximumSerializedUTF8Bytes).contains(limits.maximumBytes),
              (1...64).contains(limits.maximumDepth),
              (1...16_384).contains(limits.maximumMembers) else {
            throw SandboxError.invalid("INVALID_STRICT_JSON_LIMITS")
        }
        guard data.count <= limits.maximumBytes else {
            throw SandboxError.invalid("STRICT_JSON_INPUT_TOO_LARGE")
        }
        guard String(data: data, encoding: .utf8) != nil else {
            throw SandboxError.invalid("INVALID_JSON_UTF8")
        }
        var parser = Parser(bytes: Array(data), limits: limits)
        try parser.parseDocument()
    }

    static func object(_ data: Data, limits: StrictJSONLimits) throws -> [String: Any] {
        try validate(data, limits: limits)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SandboxError.invalid("JSON_OBJECT_REQUIRED")
        }
        return object
    }

    static func decode<Value: Decodable>(
        _ type: Value.Type,
        from data: Data,
        limits: StrictJSONLimits
    ) throws -> Value {
        try validate(data, limits: limits)
        return try JSONDecoder().decode(type, from: data)
    }

    private struct Parser {
        let bytes: [UInt8]
        let limits: StrictJSONLimits
        var index = 0
        var memberCount = 0

        mutating func parseDocument() throws {
            skipWhitespace()
            guard index < bytes.count else { throw invalidJSON() }
            try parseValue(containerDepth: 0)
            skipWhitespace()
            guard index == bytes.count else { throw invalidJSON() }
        }

        private mutating func parseValue(containerDepth: Int) throws {
            guard index < bytes.count else { throw invalidJSON() }
            switch bytes[index] {
            case 0x7B:
                guard containerDepth < limits.maximumDepth else {
                    throw SandboxError.invalid("STRICT_JSON_DEPTH_EXCEEDED")
                }
                try parseObject(containerDepth: containerDepth + 1)
            case 0x5B:
                guard containerDepth < limits.maximumDepth else {
                    throw SandboxError.invalid("STRICT_JSON_DEPTH_EXCEEDED")
                }
                try parseArray(containerDepth: containerDepth + 1)
            case 0x22:
                _ = try parseString(capturingValue: false)
            case 0x74:
                try parseLiteral([0x74, 0x72, 0x75, 0x65])
            case 0x66:
                try parseLiteral([0x66, 0x61, 0x6C, 0x73, 0x65])
            case 0x6E:
                try parseLiteral([0x6E, 0x75, 0x6C, 0x6C])
            case 0x2D, 0x30...0x39:
                try parseNumber()
            default:
                throw invalidJSON()
            }
        }

        private mutating func parseObject(containerDepth: Int) throws {
            try expect(0x7B)
            skipWhitespace()
            if consume(0x7D) { return }
            var keys = Set<String>()
            while true {
                guard index < bytes.count, bytes[index] == 0x22 else { throw invalidJSON() }
                let key = try parseString(capturingValue: true)
                guard keys.insert(key).inserted else {
                    throw SandboxError.invalid("DUPLICATE_JSON_MEMBER")
                }
                try countMember()
                skipWhitespace()
                try expect(0x3A)
                skipWhitespace()
                try parseValue(containerDepth: containerDepth)
                skipWhitespace()
                if consume(0x7D) { return }
                try expect(0x2C)
                skipWhitespace()
            }
        }

        private mutating func parseArray(containerDepth: Int) throws {
            try expect(0x5B)
            skipWhitespace()
            if consume(0x5D) { return }
            while true {
                try countMember()
                try parseValue(containerDepth: containerDepth)
                skipWhitespace()
                if consume(0x5D) { return }
                try expect(0x2C)
                skipWhitespace()
            }
        }

        private mutating func parseString(capturingValue: Bool) throws -> String {
            try expect(0x22)
            var decoded: [UInt8] = []
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                switch byte {
                case 0x22:
                    guard capturingValue else { return "" }
                    guard let value = String(bytes: decoded, encoding: .utf8) else {
                        throw SandboxError.invalid("INVALID_JSON_UTF8")
                    }
                    return value
                case 0x5C:
                    guard index < bytes.count else { throw invalidJSON() }
                    let escaped = bytes[index]
                    index += 1
                    switch escaped {
                    case 0x22, 0x5C, 0x2F:
                        if capturingValue { decoded.append(escaped) }
                    case 0x62:
                        if capturingValue { decoded.append(0x08) }
                    case 0x66:
                        if capturingValue { decoded.append(0x0C) }
                    case 0x6E:
                        if capturingValue { decoded.append(0x0A) }
                    case 0x72:
                        if capturingValue { decoded.append(0x0D) }
                    case 0x74:
                        if capturingValue { decoded.append(0x09) }
                    case 0x75:
                        let first = try parseHexCodeUnit()
                        let scalarValue: UInt32
                        if (0xD800...0xDBFF).contains(first) {
                            guard index + 6 <= bytes.count,
                                  bytes[index] == 0x5C,
                                  bytes[index + 1] == 0x75 else { throw invalidJSON() }
                            index += 2
                            let second = try parseHexCodeUnit()
                            guard (0xDC00...0xDFFF).contains(second) else { throw invalidJSON() }
                            scalarValue = 0x10000 + (UInt32(first - 0xD800) << 10) + UInt32(second - 0xDC00)
                        } else {
                            guard !(0xDC00...0xDFFF).contains(first) else { throw invalidJSON() }
                            scalarValue = UInt32(first)
                        }
                        guard let scalar = UnicodeScalar(scalarValue) else { throw invalidJSON() }
                        if capturingValue { decoded.append(contentsOf: String(scalar).utf8) }
                    default:
                        throw invalidJSON()
                    }
                case 0x00...0x1F:
                    throw invalidJSON()
                default:
                    if capturingValue { decoded.append(byte) }
                }
            }
            throw invalidJSON()
        }

        private mutating func parseHexCodeUnit() throws -> UInt16 {
            guard index + 4 <= bytes.count else { throw invalidJSON() }
            var value: UInt16 = 0
            for _ in 0..<4 {
                let digit: UInt16
                switch bytes[index] {
                case 0x30...0x39: digit = UInt16(bytes[index] - 0x30)
                case 0x41...0x46: digit = UInt16(bytes[index] - 0x41 + 10)
                case 0x61...0x66: digit = UInt16(bytes[index] - 0x61 + 10)
                default: throw invalidJSON()
                }
                value = value * 16 + digit
                index += 1
            }
            return value
        }

        private mutating func parseNumber() throws {
            _ = consume(0x2D)
            guard index < bytes.count else { throw invalidJSON() }
            if consume(0x30) {
                guard index == bytes.count || !(0x30...0x39).contains(bytes[index]) else { throw invalidJSON() }
            } else {
                guard index < bytes.count, (0x31...0x39).contains(bytes[index]) else { throw invalidJSON() }
                index += 1
                while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
            }
            if consume(0x2E) {
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw invalidJSON() }
                while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
            }
            if index < bytes.count, (bytes[index] == 0x65 || bytes[index] == 0x45) {
                index += 1
                if index < bytes.count, (bytes[index] == 0x2B || bytes[index] == 0x2D) { index += 1 }
                guard index < bytes.count, (0x30...0x39).contains(bytes[index]) else { throw invalidJSON() }
                while index < bytes.count, (0x30...0x39).contains(bytes[index]) { index += 1 }
            }
        }

        private mutating func parseLiteral(_ literal: [UInt8]) throws {
            guard index + literal.count <= bytes.count else { throw invalidJSON() }
            for offset in literal.indices where bytes[index + offset] != literal[offset] {
                throw invalidJSON()
            }
            index += literal.count
        }

        private mutating func countMember() throws {
            memberCount += 1
            guard memberCount <= limits.maximumMembers else {
                throw SandboxError.invalid("STRICT_JSON_MEMBER_LIMIT_EXCEEDED")
            }
        }

        private mutating func skipWhitespace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }

        private mutating func expect(_ byte: UInt8) throws {
            guard consume(byte) else { throw invalidJSON() }
        }

        private mutating func consume(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        private func invalidJSON() -> SandboxError {
            .invalid("INVALID_JSON")
        }
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
        guard Set(arguments.keys) == keys, arguments.values.allSatisfy({ $0.utf8.count <= 32000 }) else {
            throw SandboxError.invalid("INVALID_ARGUMENT")
        }
        return self
    }
}

enum AgentAction {
    static let maximumResponseBytes = 16_000
    case tool(ToolCall)
    case final(String)
    static func requireBoundedResponse(_ text: String) throws {
        guard text.utf8.count <= maximumResponseBytes else {
            throw SandboxError.invalid("PROVIDER_RESPONSE_TOO_LARGE")
        }
    }
    static func parse(_ text: String) throws -> Self {
        try requireBoundedResponse(text)
        guard let bytes = text.data(using: .utf8),
              let json = try? StrictJSON.object(bytes, limits: .providerResponse),
              let kind = json["kind"] as? String else { throw SandboxError.invalid("INVALID_ACTION_JSON") }
        switch kind {
        case "tool":
            guard Set(json.keys) == ["kind", "tool", "arguments"], let name = json["tool"] as? String,
                  let tool = ToolName(rawValue: name), let arguments = json["arguments"] as? [String: String]
            else { throw SandboxError.invalid("INVALID_TOOL_ACTION") }
            return .tool(try ToolCall(tool: tool, arguments: arguments).validated())
        case "final":
            guard Set(json.keys) == ["kind", "summary"],
                  let summary = json["summary"] as? String, !summary.isEmpty, summary.count <= 2000
            else { throw SandboxError.invalid("INVALID_FINAL_ACTION") }
            return .final(summary)
        default: throw SandboxError.invalid("UNKNOWN_ACTION_KIND")
        }
    }
}

struct ToolEvidence: Codable, Equatable {
    let path: String?
    let sha256: String?
    let byteCount: Int?
    let readbackKind: String
    let contentComplete: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case path, sha256, byteCount, readbackKind, contentComplete
    }

    init(path: String?, sha256: String?, byteCount: Int?, readbackKind: String, contentComplete: Bool) {
        self.path = path
        self.sha256 = sha256
        self.byteCount = byteCount
        self.readbackKind = readbackKind
        self.contentComplete = contentComplete
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        guard Set(dynamic.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw SandboxError.invalid("INVALID_TOOL_EVIDENCE_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        path = try container.decode(String?.self, forKey: .path)
        sha256 = try container.decode(String?.self, forKey: .sha256)
        byteCount = try container.decode(Int?.self, forKey: .byteCount)
        readbackKind = try container.decode(String.self, forKey: .readbackKind)
        contentComplete = try container.decode(Bool.self, forKey: .contentComplete)
        try validate()
    }

    func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(path, forKey: .path)
        try container.encode(sha256, forKey: .sha256)
        try container.encode(byteCount, forKey: .byteCount)
        try container.encode(readbackKind, forKey: .readbackKind)
        try container.encode(contentComplete, forKey: .contentComplete)
    }

    private func validate() throws {
        let validPath = path.map { (try? SandboxPath($0)) != nil || ["workspace", "config", "state", "logs", "output"].contains($0) } ?? true
        guard validPath,
              sha256 == nil || ReceiptPrivacy.validSHA256(sha256) != nil,
              byteCount == nil || (0...64_000).contains(byteCount!),
              ReceiptWireContract.containsScalarCount(readbackKind, in: 1...40) else {
            throw SandboxError.invalid("INVALID_TOOL_EVIDENCE")
        }
    }
}

struct ToolResult: Codable {
    let ok: Bool
    let tool: String
    let result: String
    let sha256: String?
    let error_code: String?
    let evidence: ToolEvidence?

    init(ok: Bool, tool: String, result: String, sha256: String?, error_code: String?, evidence: ToolEvidence? = nil) {
        self.ok = ok
        self.tool = tool
        self.result = result
        self.sha256 = sha256
        self.error_code = error_code
        self.evidence = evidence
    }

    var json: String { promptJSON(maxCharacters: 16_000) }

    func isCompleteInPrompt(maxCharacters: Int) -> Bool {
        promptJSON(maxCharacters: maxCharacters).contains("\"bodyTruncated\":false")
    }

    func promptJSON(maxCharacters: Int) -> String {
        struct PromptValue: Encodable {
            let bodyTruncated: Bool
            let error_code: String?
            let evidence: ToolEvidence?
            let ok: Bool
            let result: String
            let sha256: String?
            let tool: String
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        func encode(_ body: String, truncated: Bool) -> String {
            let value = PromptValue(bodyTruncated: truncated, error_code: error_code, evidence: evidence, ok: ok, result: body, sha256: sha256, tool: tool)
            return (try? String(decoding: encoder.encode(value), as: UTF8.self)) ?? "{}"
        }
        let minimum = encode("", truncated: !result.isEmpty)
        guard minimum.count <= maxCharacters else { return String(minimum.prefix(maxCharacters)) }
        var low = 0
        var high = result.count
        var best = minimum
        while low <= high {
            let middle = (low + high) / 2
            let candidate = encode(String(result.prefix(middle)), truncated: middle < result.count)
            if candidate.count <= maxCharacters {
                best = candidate
                low = middle + 1
            } else {
                high = middle - 1
            }
        }
        return best
    }
}

enum GoalAssertion: Codable, Equatable {
    case exactText(path: String, expected: String)
    case sha256(path: String, expected: String)
    case containsText(path: String, expected: String)
    case pathExists(path: String)
    case pathAbsent(path: String)
    case folderContains(folder: String, path: String)

    enum Kind: String, Codable { case exactText, sha256, containsText, pathExists, pathAbsent, folderContains }
    private enum CodingKeys: String, CodingKey, CaseIterable { case kind, path, expected, folder }

    var kind: Kind {
        switch self {
        case .exactText: return .exactText
        case .sha256: return .sha256
        case .containsText: return .containsText
        case .pathExists: return .pathExists
        case .pathAbsent: return .pathAbsent
        case .folderContains: return .folderContains
        }
    }
    var path: String {
        switch self {
        case .exactText(let path, _), .sha256(let path, _), .containsText(let path, _), .pathExists(let path), .pathAbsent(let path): return path
        case .folderContains(_, let path): return path
        }
    }
    var expected: String? {
        switch self {
        case .exactText(_, let expected), .sha256(_, let expected), .containsText(_, let expected): return expected
        case .pathExists, .pathAbsent, .folderContains: return nil
        }
    }
    var folder: String? {
        if case .folderContains(let folder, _) = self { return folder }
        return nil
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(Kind.self, forKey: .kind)
        let path = try container.decode(String.self, forKey: .path)
        switch kind {
        case .exactText:
            guard fields == Set(["kind", "path", "expected"]) else {
                throw SandboxError.invalid("INVALID_GOAL_ASSERTION_FIELDS")
            }
            self = .exactText(path: path, expected: try container.decode(String.self, forKey: .expected))
        case .sha256:
            guard fields == Set(["kind", "path", "expected"]) else {
                throw SandboxError.invalid("INVALID_GOAL_ASSERTION_FIELDS")
            }
            self = .sha256(path: path, expected: try container.decode(String.self, forKey: .expected))
        case .containsText:
            guard fields == Set(["kind", "path", "expected"]) else {
                throw SandboxError.invalid("INVALID_GOAL_ASSERTION_FIELDS")
            }
            self = .containsText(path: path, expected: try container.decode(String.self, forKey: .expected))
        case .pathExists:
            guard fields == Set(["kind", "path"]) else { throw SandboxError.invalid("INVALID_GOAL_ASSERTION_FIELDS") }
            self = .pathExists(path: path)
        case .pathAbsent:
            guard fields == Set(["kind", "path"]) else { throw SandboxError.invalid("INVALID_GOAL_ASSERTION_FIELDS") }
            self = .pathAbsent(path: path)
        case .folderContains:
            guard fields == Set(["kind", "path", "folder"]) else { throw SandboxError.invalid("INVALID_GOAL_ASSERTION_FIELDS") }
            self = .folderContains(folder: try container.decode(String.self, forKey: .folder), path: path)
        }
        _ = try validated()
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        try container.encode(path, forKey: .path)
        try container.encodeIfPresent(expected, forKey: .expected)
        try container.encodeIfPresent(folder, forKey: .folder)
    }

    func validated() throws -> Self {
        _ = try SandboxPath(path)
        switch self {
        case .exactText(_, let expected):
            guard expected.utf8.count <= 64_000 else { throw SandboxError.invalid("VERIFICATION_VALUE_TOO_LARGE") }
        case .containsText(_, let expected):
            guard ReceiptWireContract.containsScalarCount(expected, in: 1...8_000) else { throw SandboxError.invalid("INVALID_VERIFICATION_TEXT") }
        case .sha256(_, let expected):
            guard expected.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw SandboxError.invalid("INVALID_VERIFICATION_SHA256") }
        case .folderContains(let folder, let path):
            guard ["workspace", "config", "state", "logs", "output"].contains(folder), path.hasPrefix(folder + "/") else {
                throw SandboxError.invalid("INVALID_VERIFICATION_FOLDER")
            }
        case .pathExists, .pathAbsent: break
        }
        return self
    }

    var promptDescription: String {
        switch self {
        case .exactText(let path, let expected): return path + " must exactly equal " + String(expected.prefix(200))
        case .sha256(let path, let expected): return path + " must have SHA-256 " + expected
        case .containsText(let path, let expected): return path + " must contain " + String(expected.prefix(200))
        case .pathExists(let path): return path + " must exist"
        case .pathAbsent(let path): return path + " must not exist"
        case .folderContains(let folder, let path): return folder + " must contain " + path
        }
    }
}

struct GoalContract: Codable, Equatable {
    let assertions: [GoalAssertion]

    init(assertions: [GoalAssertion]) throws {
        guard (1...20).contains(assertions.count) else { throw SandboxError.invalid("GOAL_CONTRACT_REQUIRES_ASSERTIONS") }
        self.assertions = try assertions.map { try $0.validated() }
    }

    private enum CodingKeys: String, CodingKey, CaseIterable { case recordType, schemaVersion, assertions }
    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        guard Set(dynamic.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw SandboxError.invalid("INVALID_GOAL_CONTRACT_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(Int.self, forKey: .schemaVersion) == 1 else {
            throw SandboxError.invalid("UNSUPPORTED_GOAL_CONTRACT_VERSION")
        }
        guard try container.decode(String.self, forKey: .recordType) == "goal-contract" else {
            throw SandboxError.invalid("WRONG_GOAL_CONTRACT_RECORD_TYPE")
        }
        try self.init(assertions: container.decode([GoalAssertion].self, forKey: .assertions))
    }
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("goal-contract", forKey: .recordType)
        try container.encode(1, forKey: .schemaVersion)
        try container.encode(assertions, forKey: .assertions)
    }
    var promptDescription: String { assertions.map(\.promptDescription).joined(separator: "; ") }

    func receiptSafe() throws -> Self {
        try Self(assertions: assertions.map { assertion in
            switch assertion {
            case .exactText(let path, let expected):
                return .exactText(path: path, expected: ReceiptPrivacy.safeExpected(kind: assertion.kind.rawValue, value: expected) ?? "")
            case .containsText(let path, let expected):
                return .containsText(path: path, expected: ReceiptPrivacy.safeExpected(kind: assertion.kind.rawValue, value: expected) ?? "")
            case .sha256, .pathExists, .pathAbsent, .folderContains:
                return assertion
            }
        })
    }
}

func filesystemGoalContract(mode: String, path: String, expected: String) throws -> GoalContract {
    let assertion: GoalAssertion
    switch mode {
    case "exactText": assertion = .exactText(path: path, expected: expected)
    case "containsText": assertion = .containsText(path: path, expected: expected)
    case "sha256": assertion = .sha256(path: path, expected: expected.lowercased())
    case "pathExists": assertion = .pathExists(path: path)
    case "pathAbsent": assertion = .pathAbsent(path: path)
    default: throw SandboxError.invalid("INVALID_VERIFICATION_MODE")
    }
    return try GoalContract(assertions: [assertion])
}

struct AssertionEvidence: Codable, Equatable {
    let kind: String
    let path: String
    let folder: String?
    let passed: Bool
    let expected: String?
    let observed: String?
    let observedSHA256: String?
    let byteCount: Int?
    let checkedAt: String
    let errorCode: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case kind, path, folder, passed, expected, observed, observedSHA256, byteCount, checkedAt, errorCode
    }

    init(kind: String, path: String, folder: String? = nil, passed: Bool, expected: String?, observed: String?, observedSHA256: String?, byteCount: Int?, checkedAt: String, errorCode: String?) {
        self.kind = kind
        self.path = path
        self.folder = folder
        self.passed = passed
        self.expected = expected
        self.observed = observed
        self.observedSHA256 = observedSHA256
        self.byteCount = byteCount
        self.checkedAt = checkedAt
        self.errorCode = errorCode
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        let required = allowed.subtracting([CodingKeys.folder.rawValue])
        guard fields.isSubset(of: allowed), required.isSubset(of: fields) else {
            throw SandboxError.invalid("INVALID_ASSERTION_EVIDENCE_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        kind = try container.decode(String.self, forKey: .kind)
        path = try container.decode(String.self, forKey: .path)
        folder = try container.decodeIfPresent(String.self, forKey: .folder)
        passed = try container.decode(Bool.self, forKey: .passed)
        expected = try container.decode(String?.self, forKey: .expected)
        observed = try container.decode(String?.self, forKey: .observed)
        observedSHA256 = try container.decode(String?.self, forKey: .observedSHA256)
        byteCount = try container.decode(Int?.self, forKey: .byteCount)
        checkedAt = try container.decode(String.self, forKey: .checkedAt)
        errorCode = try container.decode(String?.self, forKey: .errorCode)
        try validate()
    }

    func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(kind, forKey: .kind)
        try container.encode(path, forKey: .path)
        try container.encodeIfPresent(folder, forKey: .folder)
        try container.encode(passed, forKey: .passed)
        try container.encode(expected, forKey: .expected)
        try container.encode(observed, forKey: .observed)
        try container.encode(observedSHA256, forKey: .observedSHA256)
        try container.encode(byteCount, forKey: .byteCount)
        try container.encode(checkedAt, forKey: .checkedAt)
        try container.encode(errorCode, forKey: .errorCode)
    }

    private func validate() throws {
        guard GoalAssertion.Kind(rawValue: kind) != nil,
              (try? SandboxPath(path)) != nil,
              folder == nil || ["workspace", "config", "state", "logs", "output"].contains(folder!),
              expected == nil || expected!.utf8.count <= 64_000,
              observed == nil || ReceiptWireContract.scalarCount(observed!) <= 1_000,
              observedSHA256 == nil || ReceiptPrivacy.validSHA256(observedSHA256) != nil,
              byteCount == nil || (0...64_000).contains(byteCount!),
              ReceiptWireContract.isValidDateTime(checkedAt),
              errorCode == nil || ReceiptWireContract.scalarCount(errorCode!) <= 500 else {
            throw SandboxError.invalid("INVALID_ASSERTION_EVIDENCE")
        }
    }

    func matches(_ assertion: GoalAssertion) -> Bool {
        kind == assertion.kind.rawValue && path == assertion.path && expected == assertion.expected && folder == assertion.folder
    }

    func receiptSafe() -> Self {
        Self(
            kind: kind,
            path: path,
            folder: folder,
            passed: passed,
            expected: ReceiptPrivacy.safeExpected(kind: kind, value: expected),
            observed: nil,
            observedSHA256: ReceiptPrivacy.validSHA256(observedSHA256),
            byteCount: byteCount.flatMap { (0...64_000).contains($0) ? $0 : nil },
            checkedAt: checkedAt,
            errorCode: errorCode.map(ReceiptPrivacy.errorCode)
        )
    }
}

enum RunStatus: String, Codable, CaseIterable { case verified, completed, blocked, cancelled }

enum ReceiptTraceResultKind: String, Codable {
    case fileRead = "file-read"
    case directoryList = "directory-list"
    case fileMutation = "file-mutation"
    case clipboardRead = "clipboard-read"
    case clipboardWrite = "clipboard-write"
    case notification
    case error
    case legacyRedacted = "legacy-redacted"
}

struct ReceiptTraceDetail: Codable, Equatable {
    let recordType = "trace-metadata"
    let schemaVersion = 1
    let resultKind: ReceiptTraceResultKind
    let sha256: String?
    let byteCount: Int?
    let readbackKind: String?
    let errorCode: String?

    fileprivate enum CodingKeys: String, CodingKey, CaseIterable {
        case recordType, schemaVersion, resultKind, sha256, byteCount, readbackKind, errorCode
    }

    init(resultKind: ReceiptTraceResultKind, sha256: String?, byteCount: Int?, readbackKind: String?, errorCode: String?) {
        self.resultKind = resultKind
        self.sha256 = ReceiptPrivacy.validSHA256(sha256)
        self.byteCount = byteCount.flatMap { (0...64_000).contains($0) ? $0 : nil }
        self.readbackKind = ReceiptPrivacy.safeReadbackKind(readbackKind)
        self.errorCode = errorCode.map(ReceiptPrivacy.errorCode)
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let required = Set(["recordType", "schemaVersion", "resultKind"])
        guard fields.isSubset(of: allowed), required.isSubset(of: fields) else {
            throw SandboxError.invalid("INVALID_TRACE_METADATA_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(String.self, forKey: .recordType) == "trace-metadata",
              try container.decode(Int.self, forKey: .schemaVersion) == 1 else {
            throw SandboxError.invalid("UNSUPPORTED_TRACE_METADATA")
        }
        resultKind = try container.decode(ReceiptTraceResultKind.self, forKey: .resultKind)
        let decodedSHA256 = try container.decodeIfPresent(String.self, forKey: .sha256)
        guard decodedSHA256 == nil || ReceiptPrivacy.validSHA256(decodedSHA256) != nil else {
            throw SandboxError.invalid("INVALID_TRACE_SHA256")
        }
        sha256 = decodedSHA256
        byteCount = try container.decodeIfPresent(Int.self, forKey: .byteCount)
        let decodedReadbackKind = try container.decodeIfPresent(String.self, forKey: .readbackKind)
        guard decodedReadbackKind == nil || ReceiptPrivacy.safeReadbackKind(decodedReadbackKind) != nil else {
            throw SandboxError.invalid("INVALID_TRACE_READBACK_KIND")
        }
        readbackKind = decodedReadbackKind
        let decodedErrorCode = try container.decodeIfPresent(String.self, forKey: .errorCode)
        guard decodedErrorCode == nil || ReceiptPrivacy.errorCode(decodedErrorCode!) == decodedErrorCode else {
            throw SandboxError.invalid("INVALID_TRACE_ERROR_CODE")
        }
        errorCode = decodedErrorCode
        if let byteCount, !(0...64_000).contains(byteCount) { throw SandboxError.invalid("INVALID_TRACE_BYTE_COUNT") }
        if resultKind == .error {
            guard errorCode != nil, readbackKind == nil else { throw SandboxError.invalid("INVALID_ERROR_TRACE_METADATA") }
        } else if errorCode != nil {
            throw SandboxError.invalid("UNEXPECTED_TRACE_ERROR_CODE")
        }
    }
}

private struct ReceiptDynamicCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

enum ReceiptPrivacy {
    private static let readbackKinds = Set(["source-read", "directory-list", "write-readback", "independent-readback"])

    static func sha256(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func validSHA256(_ value: String?) -> String? {
        guard let value,
              value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { return nil }
        return value
    }

    static func safeExpected(kind: String, value: String?) -> String? {
        guard let value else { return nil }
        guard kind == "exactText" || kind == "containsText" else { return value }
        if value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil { return value }
        return "sha256:" + sha256(value)
    }

    static func safeGoal(_ value: String) -> String {
        if value.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil { return value }
        return "sha256:" + sha256(value)
    }

    static func safeReadbackKind(_ value: String?) -> String? {
        guard let value, readbackKinds.contains(value) else { return nil }
        return value
    }

    static func errorCode(_ message: String) -> String {
        let candidate = message.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
        if candidate.range(of: "^[A-Z][A-Z0-9_]{1,79}$", options: .regularExpression) != nil { return candidate }
        return "TASK_STEP_FAILED"
    }

    static func resultKind(tool: String) -> ReceiptTraceResultKind {
        switch tool {
        case ToolName.read.rawValue: return .fileRead
        case ToolName.list.rawValue: return .directoryList
        case ToolName.create.rawValue, ToolName.append.rawValue, ToolName.patch.rawValue: return .fileMutation
        case ToolName.clipboardGet.rawValue: return .clipboardRead
        case ToolName.clipboardSet.rawValue: return .clipboardWrite
        case ToolName.notify.rawValue: return .notification
        default: return .legacyRedacted
        }
    }

    static func safeProviderHandoffDetail(tool: String, detail: String) -> String? {
        guard let data = detail.data(using: .utf8),
              let object = try? StrictJSON.object(data, limits: .traceDetail),
              let direction = object["direction"] as? String,
              tool == "provider.handoff.\(direction)",
              object["recordType"] as? String == "provider-handoff",
              object["schemaVersion"] as? Int == 2,
              object["transport"] as? String == "app-shortcut",
              let provider = object["provider"] as? String,
              ["local", "apple", "chatgpt", "grok", "grokbot", "claude"].contains(provider),
              let selection = object["selection"] as? String,
              ["saved", "best-local", "apple", "local", "chatgpt", "grok", "grokbot", "claude"].contains(selection),
              let origin = object["origin"] as? String,
              ["app-handoff", "app-intent"].contains(origin),
              let adapterSHA256 = object["adapterSHA256"] as? String,
              validSHA256(adapterSHA256) != nil,
              let actionIndex = object["actionIndex"] as? Int,
              (0...100).contains(actionIndex) else { return nil }
        let digestKey: String
        switch direction {
        case "outbound": digestKey = "promptSHA256"
        case "inbound": digestKey = "responseSHA256"
        default: return nil
        }
        let expectedFields = Set(["recordType", "schemaVersion", "direction", "transport", "provider", "selection", "origin", "adapterSHA256", "actionIndex", digestKey])
        guard Set(object.keys) == expectedFields,
              let digest = object[digestKey] as? String,
              validSHA256(digest) != nil,
              let canonical = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return nil }
        return String(decoding: canonical, as: UTF8.self)
    }

    static func safeSummary(status: RunStatus) -> String {
        switch status {
        case .verified: return "Task completed and independent verification passed."
        case .completed: return "Task completed without a passing independent verification result."
        case .blocked: return "Task stopped at a policy or execution boundary."
        case .cancelled: return "Task was cancelled."
        }
    }
}

struct TraceEntry: Codable {
    let tool: String
    let status: String
    let detail: String
    let evidence: ToolEvidence?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case tool, status, detail, evidence
    }

    init(tool: String, status: String, detail: String, evidence: ToolEvidence? = nil) {
        self.tool = tool
        self.status = status
        self.detail = detail
        self.evidence = evidence
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        let required = allowed.subtracting([CodingKeys.evidence.rawValue])
        guard fields.isSubset(of: allowed), required.isSubset(of: fields) else {
            throw SandboxError.invalid("INVALID_TRACE_ENTRY_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        tool = try container.decode(String.self, forKey: .tool)
        status = try container.decode(String.self, forKey: .status)
        detail = try container.decode(String.self, forKey: .detail)
        evidence = try container.decodeIfPresent(ToolEvidence.self, forKey: .evidence)
        try validate()
    }

    func encode(to encoder: Encoder) throws {
        try validate()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(tool, forKey: .tool)
        try container.encode(status, forKey: .status)
        try container.encode(detail, forKey: .detail)
        try container.encodeIfPresent(evidence, forKey: .evidence)
    }

    private func validate() throws {
        guard ReceiptWireContract.scalarCount(tool) <= 100,
              ["ok", "error", "skipped"].contains(status),
              ReceiptWireContract.scalarCount(detail) <= 1_000 else {
            throw SandboxError.invalid("INVALID_TRACE_ENTRY")
        }
    }

    static func receiptSuccess(_ result: ToolResult) -> Self {
        let detail = ReceiptTraceDetail(
            resultKind: result.ok ? ReceiptPrivacy.resultKind(tool: result.tool) : .error,
            sha256: result.sha256 ?? ReceiptPrivacy.sha256(result.result),
            byteCount: result.evidence?.byteCount ?? min(result.result.utf8.count, 64_000),
            readbackKind: result.ok ? result.evidence?.readbackKind : nil,
            errorCode: result.ok ? nil : ReceiptPrivacy.errorCode(result.error_code ?? "TASK_STEP_FAILED")
        )
        return Self(tool: result.tool, status: result.ok ? "ok" : "error", detail: detail.json, evidence: result.evidence?.receiptSafe())
    }

    static func receiptError(tool: String, message: String) -> Self {
        let detail = ReceiptTraceDetail(
            resultKind: .error,
            sha256: ReceiptPrivacy.sha256(message),
            byteCount: min(message.utf8.count, 64_000),
            readbackKind: nil,
            errorCode: ReceiptPrivacy.errorCode(message)
        )
        return Self(tool: tool, status: "error", detail: detail.json)
    }

    func receiptSafe() -> Self {
        if tool == "provider.handoff.outbound" || tool == "provider.handoff.inbound" {
            if let safe = ReceiptPrivacy.safeProviderHandoffDetail(tool: tool, detail: detail) {
                return Self(tool: tool, status: status, detail: safe, evidence: nil)
            }
        }
        if let data = detail.data(using: .utf8),
           let parsed = try? StrictJSON.decode(ReceiptTraceDetail.self, from: data, limits: .traceDetail) {
            return Self(tool: tool, status: status, detail: parsed.json, evidence: evidence?.receiptSafe())
        }
        let redacted = ReceiptTraceDetail(
            resultKind: status == "error" ? .error : .legacyRedacted,
            sha256: ReceiptPrivacy.sha256(detail),
            byteCount: min(detail.utf8.count, 64_000),
            readbackKind: evidence?.readbackKind,
            errorCode: status == "error" ? ReceiptPrivacy.errorCode(detail) : nil
        )
        return Self(tool: tool, status: status, detail: redacted.json, evidence: evidence?.receiptSafe())
    }
}

private extension ReceiptTraceDetail {
    var json: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return (try? String(decoding: encoder.encode(self), as: UTF8.self)) ?? "{}"
    }
}

private extension ToolEvidence {
    func receiptSafe() -> Self {
        let safePath: String?
        if let path, (try? SandboxPath(path)) != nil || ["workspace", "config", "state", "logs", "output"].contains(path) {
            safePath = path
        } else {
            safePath = nil
        }
        return Self(
            path: safePath,
            sha256: ReceiptPrivacy.validSHA256(sha256),
            byteCount: byteCount.flatMap { (0...64_000).contains($0) ? $0 : nil },
            readbackKind: ReceiptPrivacy.safeReadbackKind(readbackKind) ?? "source-read",
            contentComplete: contentComplete
        )
    }
}

struct ReceiptEnvironment: Codable {
    let appVersion: String
    let build: String
    let os: String
    let device: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case appVersion, build, os, device
    }

    init(appVersion: String, build: String, os: String, device: String) {
        self.appVersion = appVersion
        self.build = build
        self.os = os
        self.device = device
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        guard Set(dynamic.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw SandboxError.invalid("INVALID_RECEIPT_ENVIRONMENT_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        appVersion = try container.decode(String.self, forKey: .appVersion)
        build = try container.decode(String.self, forKey: .build)
        os = try container.decode(String.self, forKey: .os)
        device = try container.decode(String.self, forKey: .device)
    }
}

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
    let contract: GoalContract?
    let assertions: [AssertionEvidence]
    let provider: String?
    let policyDigest: String?
    let workspaceID: String?
    let environment: ReceiptEnvironment?
    let taskOrigin: ProviderTaskOrigin?
    let routingEvidence: ProviderRoutingEvidence?
    let legacyTraceOnly: Bool

    init(id: String, goal: String, status: RunStatus, origin: String, summary: String, steps: Int,
         failures: Int, durationMs: Double, createdAt: String, trace: [TraceEntry], contract: GoalContract? = nil,
         assertions: [AssertionEvidence] = [], provider: String? = nil, policyDigest: String? = nil,
         workspaceID: String? = nil, environment: ReceiptEnvironment? = nil,
         taskOrigin: ProviderTaskOrigin? = nil, routingEvidence: ProviderRoutingEvidence? = nil,
         legacyTraceOnly: Bool = false) throws {
        self.id = id
        self.goal = origin == "native" || origin == "shortcut" ? ReceiptPrivacy.safeGoal(goal) : goal
        self.status = status
        self.origin = origin
        self.summary = origin == "native" || origin == "shortcut" ? ReceiptPrivacy.safeSummary(status: status) : summary
        self.steps = steps
        self.failures = failures
        self.durationMs = durationMs
        self.createdAt = createdAt
        self.trace = trace.map { $0.receiptSafe() }
        self.contract = try contract?.receiptSafe()
        self.assertions = assertions.map { $0.receiptSafe() }
        self.provider = provider
        self.policyDigest = policyDigest
        self.workspaceID = workspaceID
        self.environment = environment
        self.taskOrigin = taskOrigin
        self.routingEvidence = routingEvidence
        self.legacyTraceOnly = legacyTraceOnly
        try validateQualification()
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case recordType, schemaVersion, id, goal, status, origin, summary, steps, failures, durationMs, createdAt, trace
        case contract, assertions, provider, policyDigest, workspaceID, environment, taskOrigin, routingEvidence, legacyTraceOnly
    }

    init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: ReceiptDynamicCodingKey.self)
        let fields = Set(dynamic.allKeys.map(\.stringValue))
        let currentAllowed = Set(CodingKeys.allCases.map(\.rawValue))
        let legacyAllowed = Set([
            "id", "goal", "status", "origin", "summary", "steps", "failures", "durationMs", "createdAt", "trace",
        ])
        let currentRequired = legacyAllowed.union([
            "recordType", "schemaVersion", "contract", "assertions", "provider", "policyDigest", "workspaceID", "environment", "legacyTraceOnly",
        ])
        let isCurrent = fields.contains(CodingKeys.schemaVersion.rawValue)
        guard isCurrent
            ? fields.isSubset(of: currentAllowed) && currentRequired.isSubset(of: fields)
            : fields == legacyAllowed else {
            throw SandboxError.invalid("INVALID_RUN_RECEIPT_FIELDS")
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version: Int
        if isCurrent {
            version = try container.decode(Int.self, forKey: .schemaVersion)
            guard version == 2 else { throw SandboxError.invalid("UNSUPPORTED_RECEIPT_VERSION") }
            guard try container.decode(String.self, forKey: .recordType) == "run-receipt" else {
                throw SandboxError.invalid("WRONG_RECEIPT_RECORD_TYPE")
            }
        } else {
            version = 0
        }
        let decodedStatus = try container.decode(RunStatus.self, forKey: .status)
        if version == 0, ![RunStatus.verified, .blocked, .cancelled].contains(decodedStatus) {
            throw SandboxError.invalid("INVALID_LEGACY_RECEIPT_STATUS")
        }
        id = try container.decode(String.self, forKey: .id)
        let decodedGoal = try container.decode(String.self, forKey: .goal)
        status = version == 0 && decodedStatus == .verified ? .completed : decodedStatus
        origin = try container.decode(String.self, forKey: .origin)
        goal = origin == "native" || origin == "shortcut" ? ReceiptPrivacy.safeGoal(decodedGoal) : decodedGoal
        let decodedSummary = try container.decode(String.self, forKey: .summary)
        steps = try container.decode(Int.self, forKey: .steps)
        failures = try container.decode(Int.self, forKey: .failures)
        durationMs = try container.decode(Double.self, forKey: .durationMs)
        createdAt = try container.decode(String.self, forKey: .createdAt)
        trace = try container.decode([TraceEntry].self, forKey: .trace).map { $0.receiptSafe() }
        if version == 0 {
            contract = nil
            assertions = []
            provider = nil
            policyDigest = nil
            workspaceID = nil
            environment = nil
            taskOrigin = nil
            routingEvidence = nil
            legacyTraceOnly = true
        } else {
            contract = try container.decodeIfPresent(GoalContract.self, forKey: .contract)?.receiptSafe()
            assertions = try container.decode([AssertionEvidence].self, forKey: .assertions).map { $0.receiptSafe() }
            provider = try container.decodeIfPresent(String.self, forKey: .provider)
            policyDigest = try container.decodeIfPresent(String.self, forKey: .policyDigest)
            workspaceID = try container.decodeIfPresent(String.self, forKey: .workspaceID)
            environment = try container.decodeIfPresent(ReceiptEnvironment.self, forKey: .environment)
            taskOrigin = try container.decodeIfPresent(ProviderTaskOrigin.self, forKey: .taskOrigin)
            routingEvidence = try container.decodeIfPresent(ProviderRoutingEvidence.self, forKey: .routingEvidence)
            legacyTraceOnly = try container.decode(Bool.self, forKey: .legacyTraceOnly)
        }
        summary = origin == "native" || origin == "shortcut" ? ReceiptPrivacy.safeSummary(status: status) : decodedSummary
        try validateQualification()
    }

    private func validateQualification() throws {
        let digestPattern = "^[a-f0-9]{64}$"
        let providerIsValid = provider.map { AppProvider(rawValue: $0) != nil || $0 == "system" } ?? true
        let environmentIsValid = environment.map {
            ReceiptWireContract.scalarCount($0.appVersion) <= 40
                && ReceiptWireContract.scalarCount($0.build) <= 40
                && ReceiptWireContract.scalarCount($0.os) <= 100
                && ReceiptWireContract.scalarCount($0.device) <= 100
        } ?? true
        guard ReceiptWireContract.containsScalarCount(id, in: 1...80),
              ReceiptWireContract.scalarCount(goal) <= 2_000,
              ["cloud-sandbox", "shortcut", "native"].contains(origin),
              ReceiptWireContract.scalarCount(summary) <= 3_000,
              (0...100).contains(steps), (0...min(steps, 100)).contains(failures),
              durationMs.isFinite, (0...86_400_000).contains(durationMs),
              ReceiptWireContract.isValidDateTime(createdAt),
              trace.count <= 100,
              providerIsValid,
              policyDigest == nil || policyDigest!.range(of: digestPattern, options: .regularExpression) != nil,
              workspaceID == nil || ReceiptWireContract.containsScalarCount(workspaceID!, in: 8...80),
              environmentIsValid else {
            throw SandboxError.invalid("INVALID_RUN_RECEIPT")
        }
        if legacyTraceOnly {
            guard status != .verified,
                  contract == nil, assertions.isEmpty,
                  provider == nil, policyDigest == nil, workspaceID == nil,
                  environment == nil, taskOrigin == nil, routingEvidence == nil else {
                throw SandboxError.invalid("INVALID_LEGACY_RECEIPT_QUALIFICATION")
            }
        } else if origin == "native" || origin == "shortcut" {
            guard let provider, provider != "system",
                  policyDigest != nil,
                  workspaceID != nil,
                  environment != nil,
                  taskOrigin != nil,
                  let routingEvidence else {
                throw SandboxError.invalid("LOCAL_RECEIPT_REQUIRES_ROUTE_EVIDENCE")
            }
            guard goal.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil else {
                throw SandboxError.invalid("LOCAL_RECEIPT_GOAL_MUST_BE_REDACTED")
            }
            guard origin != "native" || (provider == AppProvider.apple.rawValue && routingEvidence.provider == .apple),
                  origin != "shortcut" || (provider != AppProvider.apple.rawValue && routingEvidence.provider != .apple) else {
                throw SandboxError.invalid("RECEIPT_ORIGIN_PROVIDER_MISMATCH")
            }
        }
        let mappingValid: Bool
        if let contract {
            mappingValid = assertions.count == contract.assertions.count && zip(assertions, contract.assertions).allSatisfy { $0.matches($1) }
        } else {
            mappingValid = assertions.isEmpty
        }
        guard assertions.isEmpty || mappingValid else { throw SandboxError.invalid("RECEIPT_ASSERTIONS_DO_NOT_MATCH_CONTRACT") }
        if let routingEvidence {
            guard provider == routingEvidence.provider.rawValue else {
                throw SandboxError.invalid("RECEIPT_ROUTING_PROVIDER_MISMATCH")
            }
            if taskOrigin == .appIntent, !routingEvidence.appIntentReturnObserved {
                throw SandboxError.invalid("APP_INTENT_RECEIPT_REQUIRES_OBSERVED_RETURN")
            }
            switch routingEvidence.selection {
            case .saved:
                break
            case .bestLocal:
                guard routingEvidence.provider == .apple || routingEvidence.provider == .local else {
                    throw SandboxError.invalid("RECEIPT_BEST_LOCAL_PROVIDER_MISMATCH")
                }
            case .apple, .local, .chatgpt, .grok, .grokbot, .claude:
                guard routingEvidence.selection.explicitProvider == routingEvidence.provider else {
                    throw SandboxError.invalid("RECEIPT_EXPLICIT_PROVIDER_MISMATCH")
                }
            }
        }
        if status == .verified {
            guard contract != nil, !assertions.isEmpty, mappingValid, assertions.allSatisfy({ $0.passed && $0.errorCode == nil }), !legacyTraceOnly else {
                throw SandboxError.invalid("VERIFIED_RECEIPT_REQUIRES_MATCHING_EVIDENCE")
            }
        }
    }

    static func decodeStrict(from data: Data) throws -> Self {
        let receipt = try StrictJSON.decode(Self.self, from: data, limits: .receipt)
        _ = try receipt.encodedWireData()
        return receipt
    }

    func encodedWireData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        try ReceiptWireContract.validateSerializedByteCount(data.count)
        return data
    }

    func encode(to encoder: Encoder) throws {
        try validateQualification()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("run-receipt", forKey: .recordType)
        try container.encode(2, forKey: .schemaVersion)
        try container.encode(id, forKey: .id)
        try container.encode(goal, forKey: .goal)
        try container.encode(status, forKey: .status)
        try container.encode(origin, forKey: .origin)
        try container.encode(summary, forKey: .summary)
        try container.encode(steps, forKey: .steps)
        try container.encode(failures, forKey: .failures)
        try container.encode(durationMs, forKey: .durationMs)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(trace, forKey: .trace)
        try container.encode(contract, forKey: .contract)
        try container.encode(assertions, forKey: .assertions)
        try container.encode(provider, forKey: .provider)
        try container.encode(policyDigest, forKey: .policyDigest)
        try container.encode(workspaceID, forKey: .workspaceID)
        try container.encode(environment, forKey: .environment)
        try container.encodeIfPresent(taskOrigin, forKey: .taskOrigin)
        try container.encodeIfPresent(routingEvidence, forKey: .routingEvidence)
        try container.encode(legacyTraceOnly, forKey: .legacyTraceOnly)
    }
}

struct RunCheckpoint: Codable {
    let runID: String
    let goal: String
    let nextStep: Int
    let capsule: String
    let lastResult: String
    let phase: String
    let contract: GoalContract?
    let latestResult: ToolResult?
    let policy: ResourcePolicy?
    let authorizationPolicy: ResourcePolicy?
    let taskOrigin: ProviderTaskOrigin?
    let routingEvidence: ProviderRoutingEvidence?
    let trace: [TraceEntry]
    let failures: Int
    let repeated: Int
    let lastFailure: String
    let initialBattery: Int?
    let startedAt: Date?

    init(runID: String, goal: String, nextStep: Int, capsule: String, lastResult: String, phase: String,
         contract: GoalContract? = nil, latestResult: ToolResult? = nil, policy: ResourcePolicy? = nil,
         authorizationPolicy: ResourcePolicy? = nil, taskOrigin: ProviderTaskOrigin? = nil,
         routingEvidence: ProviderRoutingEvidence? = nil,
         trace: [TraceEntry] = [], failures: Int = 0, repeated: Int = 0, lastFailure: String = "",
         initialBattery: Int? = nil, startedAt: Date? = nil) {
        self.runID = runID
        self.goal = goal
        self.nextStep = nextStep
        self.capsule = capsule
        self.lastResult = lastResult
        self.phase = phase
        self.contract = contract
        self.latestResult = latestResult
        self.policy = policy
        self.authorizationPolicy = authorizationPolicy ?? policy
        self.taskOrigin = taskOrigin
        self.routingEvidence = routingEvidence
        self.trace = trace
        self.failures = failures
        self.repeated = repeated
        self.lastFailure = lastFailure
        self.initialBattery = initialBattery
        self.startedAt = startedAt
    }

    private enum CodingKeys: String, CodingKey {
        case recordType, schemaVersion, runID, goal, nextStep, capsule, lastResult, phase, contract, latestResult
        case policy, authorizationPolicy, taskOrigin, routingEvidence, trace, failures, repeated, lastFailure, initialBattery, startedAt
    }
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let version = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0
        guard version <= 4 else { throw SandboxError.invalid("UNSUPPORTED_CHECKPOINT_VERSION") }
        if let recordType = try container.decodeIfPresent(String.self, forKey: .recordType), recordType != "run-checkpoint" {
            throw SandboxError.invalid("WRONG_CHECKPOINT_RECORD_TYPE")
        }
        runID = try container.decode(String.self, forKey: .runID)
        goal = try container.decode(String.self, forKey: .goal)
        nextStep = try container.decode(Int.self, forKey: .nextStep)
        capsule = try container.decode(String.self, forKey: .capsule)
        lastResult = try container.decode(String.self, forKey: .lastResult)
        phase = try container.decode(String.self, forKey: .phase)
        contract = try container.decodeIfPresent(GoalContract.self, forKey: .contract)
        latestResult = try container.decodeIfPresent(ToolResult.self, forKey: .latestResult)
        policy = try container.decodeIfPresent(ResourcePolicy.self, forKey: .policy)
        authorizationPolicy = version >= 3
            ? try container.decodeIfPresent(ResourcePolicy.self, forKey: .authorizationPolicy)
            : policy
        taskOrigin = try container.decodeIfPresent(ProviderTaskOrigin.self, forKey: .taskOrigin)
        routingEvidence = try container.decodeIfPresent(ProviderRoutingEvidence.self, forKey: .routingEvidence)
        trace = try container.decodeIfPresent([TraceEntry].self, forKey: .trace) ?? []
        failures = try container.decodeIfPresent(Int.self, forKey: .failures) ?? 0
        repeated = try container.decodeIfPresent(Int.self, forKey: .repeated) ?? 0
        lastFailure = try container.decodeIfPresent(String.self, forKey: .lastFailure) ?? ""
        initialBattery = try container.decodeIfPresent(Int.self, forKey: .initialBattery)
        startedAt = try container.decodeIfPresent(Date.self, forKey: .startedAt)
        let policyBindingIsValid: Bool
        if let policy, let authorizationPolicy {
            var expectedResolvedPolicy = authorizationPolicy
            expectedResolvedPolicy.provider = routingEvidence?.provider.rawValue ?? authorizationPolicy.provider
            policyBindingIsValid = policy == expectedResolvedPolicy &&
                (routingEvidence?.selection != .saved || policy.provider == authorizationPolicy.provider)
        } else {
            policyBindingIsValid = policy == nil && authorizationPolicy == nil && routingEvidence == nil
        }
        guard !runID.isEmpty, runID.count <= 100,
              !goal.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, goal.count <= 2_000,
              (0...24).contains(nextStep), capsule.count <= 12_000, lastResult.count <= 16_000,
              trace.count <= 24, failures >= 0, repeated >= 0, lastFailure.count <= 1_000,
              policy == nil || authorizationPolicy != nil,
              routingEvidence == nil || (policy != nil && (taskOrigin != nil || version < 4) && routingEvidence!.provider.rawValue == policy!.provider),
              policyBindingIsValid else {
            throw SandboxError.invalid("INVALID_CHECKPOINT")
        }
        if version == 4 { try validateCurrentCheckpoint() }
    }
    func encode(to encoder: Encoder) throws {
        try validateCurrentCheckpoint()
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode("run-checkpoint", forKey: .recordType)
        try container.encode(4, forKey: .schemaVersion)
        try container.encode(runID, forKey: .runID)
        try container.encode(goal, forKey: .goal)
        try container.encode(nextStep, forKey: .nextStep)
        try container.encode(capsule, forKey: .capsule)
        try container.encode(lastResult, forKey: .lastResult)
        try container.encode(phase, forKey: .phase)
        try container.encodeIfPresent(contract, forKey: .contract)
        try container.encodeIfPresent(latestResult, forKey: .latestResult)
        try container.encodeIfPresent(policy, forKey: .policy)
        try container.encodeIfPresent(authorizationPolicy, forKey: .authorizationPolicy)
        try container.encodeIfPresent(taskOrigin, forKey: .taskOrigin)
        try container.encodeIfPresent(routingEvidence, forKey: .routingEvidence)
        try container.encode(trace, forKey: .trace)
        try container.encode(failures, forKey: .failures)
        try container.encode(repeated, forKey: .repeated)
        try container.encode(lastFailure, forKey: .lastFailure)
        try container.encodeIfPresent(initialBattery, forKey: .initialBattery)
        try container.encodeIfPresent(startedAt, forKey: .startedAt)
    }

    private func validateCurrentCheckpoint() throws {
        let allowedPhases = ["planning", "executing", "ready", "verified", "completed", "blocked", "cancelled"]
        guard allowedPhases.contains(phase),
              (repeated == 0) == lastFailure.isEmpty,
              repeated <= failures else {
            throw SandboxError.invalid("INVALID_CHECKPOINT_STATE")
        }
        guard let policy else {
            guard phase == "blocked", authorizationPolicy == nil, taskOrigin == nil, routingEvidence == nil,
                  latestResult == nil, trace.isEmpty, failures == 0, repeated == 0,
                  initialBattery == nil, startedAt == nil else {
                throw SandboxError.invalid("INVALID_CHECKPOINT_REVIEW_RECORD")
            }
            return
        }
        guard let authorizationPolicy,
              taskOrigin != nil,
              let routingEvidence,
              let initialBattery, (0...100).contains(initialBattery),
              let startedAt,
              startedAt.timeIntervalSince1970.isFinite,
              startedAt.timeIntervalSince1970 >= 978_307_200,
              startedAt <= Date().addingTimeInterval(300),
              policy.provider == AppProvider.apple.rawValue,
              routingEvidence.provider == .apple,
              routingEvidence.authorizedProvider.rawValue == authorizationPolicy.provider,
              taskOrigin != .appIntent || routingEvidence.appIntentReturnObserved,
              nextStep <= policy.maxSteps,
              failures <= policy.maxFailures,
              trace.count <= policy.maxSteps else {
            throw SandboxError.invalid("INVALID_CHECKPOINT_CONTINUATION")
        }
        if !lastFailure.isEmpty {
            guard lastResult.hasPrefix("ERROR: ") else { throw SandboxError.invalid("INVALID_CHECKPOINT_FAILURE_STATE") }
        } else if let latestResult {
            let promptLimit = min(policy.contextChars, ProviderQualificationSnapshot.appleMaximumContextCharacters)
            guard lastResult == latestResult.promptJSON(maxCharacters: latestPromptBudget(limit: promptLimit)) else {
                throw SandboxError.invalid("INVALID_CHECKPOINT_LATEST_RESULT")
            }
        }
    }
}

enum RunCheckpointIdentity {
    static func digest(_ checkpoint: RunCheckpoint) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return NativeDigest.sha256(String(decoding: try encoder.encode(checkpoint), as: UTF8.self))
    }

    static func requireUnchanged(expected: RunCheckpoint, current: RunCheckpoint) throws {
        guard try digest(expected) == digest(current) else {
            throw SandboxError.conflict("BACKGROUND_CHECKPOINT_CHANGED")
        }
    }
}

enum CheckpointReviewDisposition {
    case acknowledge(RunCheckpoint)
    case alreadyAcknowledged
}

enum CheckpointReviewCore {
    static func acknowledgedRecord(for checkpoint: RunCheckpoint) throws -> RunCheckpoint {
        let reviewedDigest = try RunCheckpointIdentity.digest(checkpoint)
        return RunCheckpoint(
            runID: checkpoint.runID,
            goal: checkpoint.goal,
            nextStep: checkpoint.nextStep,
            capsule: "User reviewed the interrupted run. No action replayed. Reviewed checkpoint SHA-256: \(reviewedDigest)",
            lastResult: checkpoint.lastResult,
            phase: "blocked"
        )
    }

    static func disposition(expected: RunCheckpoint, current: RunCheckpoint) throws -> CheckpointReviewDisposition {
        let acknowledged = try acknowledgedRecord(for: expected)
        do {
            try RunCheckpointIdentity.requireUnchanged(expected: expected, current: current)
            return .acknowledge(acknowledged)
        } catch {
            do {
                try RunCheckpointIdentity.requireUnchanged(expected: acknowledged, current: current)
                return .alreadyAcknowledged
            } catch {
                throw SandboxError.conflict("BACKGROUND_CHECKPOINT_CHANGED")
            }
        }
    }

    static func reviewPath(for checkpoint: RunCheckpoint) throws -> SandboxPath {
        try SandboxPath("output/reviewed-checkpoint-\(RunCheckpointIdentity.digest(checkpoint)).json")
    }
}

enum ExecutionStateKind: String, CaseIterable, Equatable, Sendable {
    case nativeCheckpoint
    case shortcutSession

    var sourcePath: String {
        switch self {
        case .nativeCheckpoint: return "state/active.json"
        case .shortcutSession: return "state/shortcut-session.json"
        }
    }

    var title: String {
        switch self {
        case .nativeCheckpoint: return "Native run checkpoint"
        case .shortcutSession: return "Shortcut handoff session"
        }
    }

    fileprivate var reviewStem: String {
        switch self {
        case .nativeCheckpoint: return "active"
        case .shortcutSession: return "shortcut-session"
        }
    }
}

struct CorruptExecutionState: Identifiable, Equatable, Sendable {
    static let maximumReviewBytes = 64_000

    let kind: ExecutionStateKind
    let sha256: String?
    let byteCount: Int
    let failureCode: String

    var id: String { kind.rawValue }
    var sourcePath: String { kind.sourcePath }
    var canPreserve: Bool { sha256 != nil && (0...Self.maximumReviewBytes).contains(byteCount) }
    var exportFilename: String { "local-sandbox-corrupt-\(kind.reviewStem)-\(sha256?.prefix(16) ?? "oversized").bin" }

    var reviewPath: SandboxPath? {
        guard let sha256, canPreserve else { return nil }
        return try? SandboxPath("output/reviewed-corrupt-\(kind.reviewStem)-\(sha256).bin")
    }

    static func bounded(kind: ExecutionStateKind, data: Data, failureCode: String) -> Self {
        Self(kind: kind, sha256: NativeDigest.sha256(data), byteCount: data.count, failureCode: failureCode)
    }

    static func oversized(kind: ExecutionStateKind, byteCount: Int) -> Self {
        Self(kind: kind, sha256: nil, byteCount: byteCount, failureCode: "EXECUTION_STATE_REVIEW_BOUND_EXCEEDED")
    }
}

func exactPatch(_ content: String, old: String, replacement: String) throws -> String {
    guard !old.isEmpty, let range = content.range(of: old) else { throw SandboxError.conflict("PATCH_CONTEXT_NOT_FOUND") }
    let nextStart = content.index(after: range.lowerBound)
    guard content.range(of: old, range: nextStart..<content.endIndex) == nil else {
        throw SandboxError.conflict("PATCH_CONTEXT_AMBIGUOUS")
    }
    var result = content
    result.replaceSubrange(range, with: replacement)
    return result
}

func boundedPrompt(goal: String, capsule: String, latest: String, limit: Int) -> String {
    let latestReserve = latestPromptBudget(limit: limit)
    let remaining = max(0, limit - latestReserve - 40)
    let goalBudget = max(100, remaining * 3 / 5)
    let stateBudget = max(100, remaining - goalBudget)
    let header = "Goal: \(goal.prefix(goalBudget))\nState: \(capsule.prefix(stateBudget))\nLatest result:\n"
    return String((header + latest.prefix(max(0, limit - header.count))).prefix(limit))
}

func latestPromptBudget(limit: Int) -> Int {
    min(max(400, limit - 240), max(600, limit * 2 / 3))
}
