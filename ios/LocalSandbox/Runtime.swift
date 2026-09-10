import Foundation
import UIKit
import UserNotifications
import Darwin

struct DeviceSnapshot {
    let battery: Int?
    let memoryBytes: UInt64?
    let physicalMemory: UInt64
    let thermal: ProcessInfo.ThermalState
    @MainActor static func read() -> Self {
        UIDevice.current.isBatteryMonitoringEnabled = true
        let level = UIDevice.current.batteryLevel
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let code = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), rebound, &count)
            }
        }
        return Self(battery: level >= 0 ? Int((level * 100).rounded()) : nil,
                    memoryBytes: code == KERN_SUCCESS ? info.phys_footprint : nil,
                    physicalMemory: ProcessInfo.processInfo.physicalMemory,
                    thermal: ProcessInfo.processInfo.thermalState)
    }
    func stopReason(policy: ResourcePolicy, initialBattery: Int?) -> String? {
        guard let battery, let initialBattery else { return "BATTERY_TELEMETRY_UNAVAILABLE" }
        if battery < policy.batteryReserve { return "BATTERY_RESERVE_REACHED" }
        if initialBattery - battery >= policy.batteryBudget { return "BATTERY_DROP_BUDGET_REACHED" }
        if thermal == .serious || thermal == .critical { return "THERMAL_PRESSURE" }
        guard let memoryBytes else { return "MEMORY_TELEMETRY_UNAVAILABLE" }
        if Double(memoryBytes) / Double(physicalMemory) * 100 > Double(policy.memoryTarget) { return "APP_MEMORY_TARGET_REACHED" }
        return nil
    }
}

@MainActor
final class Dispatcher {
    static let shared = Dispatcher()
    private let store = SandboxStore.shared
    private struct Journal: Codable { let fingerprint: String; let phase: String; let result: ToolResult? }
    func execute(_ raw: ToolCall, callID: String, policy: ResourcePolicy) async throws -> ToolResult {
        let call = try raw.validated()
        let fingerprint = SandboxStore.hash(String(decoding: try JSONEncoder.sorted.encode(call), as: UTF8.self))
        let journalPath = "logs/call-\(SandboxStore.hash(callID)).json"
        if let existing = try? store.load(Journal.self, path: journalPath) {
            guard existing.fingerprint == fingerprint else { throw SandboxError.conflict("CALL_ID_REUSED_WITH_DIFFERENT_ARGUMENTS") }
            if existing.phase == "done", let result = existing.result { return result }
            throw SandboxError.blocked("UNCERTAIN_PRIOR_CALL_REQUIRES_READBACK")
        }
        try store.save(Journal(fingerprint: fingerprint, phase: "pending", result: nil), path: journalPath)
        // Persist pending before side effects. A crash never silently replays a pending call.
        let args = call.arguments
        let result: String
        var hash: String?
        switch call.tool {
        case .read:
            let content = try store.read(SandboxPath(args["path"] ?? ""))
            guard content.count <= 8000 else { throw SandboxError.invalid("READ_TOO_LARGE: Use a smaller source file before editing.") }
            result = content; hash = SandboxStore.hash(content)
        case .list:
            result = try store.list(args["path"] ?? "").joined(separator: "\n")
        case .create, .append, .patch:
            let path = try SandboxPath(args["path"] ?? "")
            guard path.value.hasPrefix("workspace/") || path.value.hasPrefix("output/") else { throw SandboxError.blocked("MODEL_WRITES_REQUIRE_WORKSPACE_OR_OUTPUT") }
            let content: String
            let expected: String?
            if call.tool == .create { content = args["content"] ?? ""; expected = nil }
            else {
                let before = try store.read(path)
                guard args["expectedSHA256"] == SandboxStore.hash(before) else { throw SandboxError.conflict("FILE_CHANGED_REREAD_REQUIRED") }
                expected = SandboxStore.hash(before)
                try store.write(SandboxPath("output/backup-\(SandboxStore.hash(callID)).txt"), content: before, createOnly: true)
                if call.tool == .append { content = before + (args["content"] ?? "") }
                else { content = try exactPatch(before, old: args["old"] ?? "", replacement: args["replacement"] ?? "") }
            }
            try store.write(path, content: content, createOnly: call.tool == .create, expectedSHA256: expected)
            result = "Readback verified: \(path.value). \(content.utf8.count) bytes."; hash = SandboxStore.hash(content)
        case .clipboardGet:
            result = String((UIPasteboard.general.string ?? "").prefix(4000))
        case .clipboardSet:
            UIPasteboard.general.string = args["content"] ?? ""
            result = "Clipboard updated."
        case .notify:
            guard policy.notifications else { throw SandboxError.blocked("NOTIFICATIONS_NOT_AUTHORIZED") }
            let content = UNMutableNotificationContent(); content.title = "Local Sandbox"; content.body = String((args["content"] ?? "").prefix(200))
            try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: callID, content: content, trigger: nil))
            result = "Notification submitted to iOS."
        }
        let value = ToolResult(ok: true, tool: call.tool.rawValue, result: result, sha256: hash, error_code: nil)
        try store.save(Journal(fingerprint: fingerprint, phase: "done", result: value), path: journalPath)
        return value
    }
}
extension JSONEncoder { static var sorted: JSONEncoder { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return e } }

@MainActor
final class AgentRunner {
    static let shared = AgentRunner()
    private(set) var running = false
    private var cancelled = false
    private var generation: Task<String, Error>?
    func cancel() { cancelled = true; generation?.cancel() }
    func run(goal: String, policy rawPolicy: ResourcePolicy, onProgress: @escaping (String) -> Void = { _ in }) async throws -> RunReceipt {
        guard !running else { throw SandboxError.blocked("ANOTHER_RUN_IS_ACTIVE") }
        let policy = try rawPolicy.validated()
        guard !goal.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, goal.count <= 2000 else { throw SandboxError.invalid("GOAL_MUST_BE_1_TO_2000_CHARACTERS") }
        guard SandboxStore.shared.connected else { throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST") }
        running = true; cancelled = false
        defer { running = false; generation = nil }
        let id = UUID().uuidString
        let start = Date()
        let initialBattery = DeviceSnapshot.read().battery
        var trace: [TraceEntry] = []
        var failures = 0, steps = 0
        var lastFailure = "", repeated = 0
        var unresolvedFailure = false
        var latest = "No tools executed."
        var capsule = "Goal accepted. No actions complete."
        var status: RunStatus = .blocked
        var summary = "STEP_BUDGET_EXHAUSTED"
        let provider: any StepProvider
        switch policy.provider {
        case "apple": provider = AppleProvider()
        case "openai": provider = OpenAIProvider()
        default: throw SandboxError.blocked("RUN_LOCAL_PROVIDER_THROUGH_SHORTCUTS")
        }
        for step in 0..<policy.maxSteps {
            steps = step + 1
            if cancelled || Task.isCancelled { status = .cancelled; summary = "Cancelled by user."; break }
            if let reason = DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) { summary = reason; break }
            do {
                try SandboxStore.shared.save(RunCheckpoint(runID: id, goal: goal, nextStep: step, capsule: capsule, lastResult: latest, phase: "planning"), path: "state/active.json")
                onProgress("Planning step \(step + 1) of \(policy.maxSteps)")
                let pending = Task { @MainActor in try await provider.step(goal: goal, capsule: capsule, latest: latest, policy: policy) }
                generation = pending
                let monitor = Task { @MainActor in
                    while !Task.isCancelled {
                        try? await Task.sleep(nanoseconds: 1_000_000_000)
                        if Task.isCancelled { break }
                        if DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) != nil || self.cancelled { pending.cancel(); break }
                    }
                }
                let text: String
                do { text = try await pending.value; monitor.cancel() }
                catch { monitor.cancel(); throw error }
                if let reason = DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) { summary = reason; break }
                if cancelled { status = .cancelled; summary = "Cancelled by user."; break }
                switch try AgentAction.parse(text) {
                case .final(let message):
                    // The model's verified flag is ignored. The receipt reports executed/read-back evidence only.
                    status = trace.contains(where: { $0.status == "ok" }) && !unresolvedFailure ? .verified : .blocked
                    summary = message
                    if status == .blocked { summary = "No clean execution evidence. " + message }
                case .tool(let call):
                    onProgress("Executing \(call.tool.rawValue)")
                    try SandboxStore.shared.save(RunCheckpoint(runID: id, goal: goal, nextStep: step, capsule: capsule, lastResult: latest, phase: "executing"), path: "state/active.json")
                    let value = try await Dispatcher.shared.execute(call, callID: "\(id)-\(step)", policy: policy)
                    unresolvedFailure = false
                    latest = value.json
                    trace.append(TraceEntry(tool: call.tool.rawValue, status: "ok", detail: String(value.result.prefix(900))))
                    capsule = "Goal: \(goal.prefix(700)). Completed \(trace.count) calls. Last: \(call.tool.rawValue). Failures: \(failures). Continue from the last result. Reread before any edit."
                    try SandboxStore.shared.save(RunCheckpoint(runID: id, goal: goal, nextStep: step + 1, capsule: capsule, lastResult: latest, phase: "ready"), path: "state/active.json")
                    continue
                }
                break
            } catch {
                if cancelled || Task.isCancelled { status = .cancelled; summary = "Cancelled by user."; break }
                if let reason = DeviceSnapshot.read().stopReason(policy: policy, initialBattery: initialBattery) { summary = reason; break }
                unresolvedFailure = true
                failures += 1
                let message = error.localizedDescription
                trace.append(TraceEntry(tool: "step", status: "error", detail: String(message.prefix(900))))
                repeated = message == lastFailure ? repeated + 1 : 1
                lastFailure = message
                latest = "ERROR: \(message). Repair invalid JSON once. Reread for patch or hash conflicts. Do not repeat an uncertain mutation."
                summary = message
                if let typed = error as? SandboxError, case .blocked = typed { break }
                if failures >= policy.maxFailures || repeated >= 2 { break }
            }
        }
        let receipt = RunReceipt(id: id, goal: goal, status: status, origin: "native", summary: String(summary.prefix(3000)), steps: steps, failures: failures, durationMs: Date().timeIntervalSince(start) * 1000, createdAt: ISO8601DateFormatter().string(from: Date()), trace: trace)
        try SandboxStore.shared.save(receipt, path: "logs/\(id).json")
        try SandboxStore.shared.save(RunCheckpoint(runID: id, goal: goal, nextStep: steps, capsule: summary, lastResult: latest, phase: status.rawValue), path: "state/active.json")
        if policy.notifications {
            let content = UNMutableNotificationContent(); content.title = "Local Sandbox · \(status.rawValue)"; content.body = String(summary.prefix(180))
            try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
        }
        return receipt
    }
}
