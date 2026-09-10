import AppIntents
import Foundation

struct RunSandboxIntent: AppIntent {
    static let title: LocalizedStringResource = "Run Bounded Task"
    static let description = IntentDescription("Run a task with the saved Local Sandbox policy and return a JSON receipt.")
    static let openAppWhenRun = true
    @Parameter(title: "Goal") var goal: String
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        try SandboxStore.shared.restore()
        guard let data=UserDefaults.standard.data(forKey:"policy") else {throw SandboxError.blocked("Save authorization in Local Sandbox first.")}
        let policy=try JSONDecoder().decode(ResourcePolicy.self,from:data).validated()
        if let checkpoint=try? SandboxStore.shared.load(RunCheckpoint.self,path:"state/active.json"),["planning","executing","ready"].contains(checkpoint.phase){throw SandboxError.blocked("Review the interrupted run in Local Sandbox before continuing.")}
        let receipt=try await AgentRunner.shared.run(goal:goal,policy:policy)
        return .result(value:String(decoding:try JSONEncoder.sorted.encode(receipt),as:UTF8.self))
    }
}
struct PlanOneStepIntent: AppIntent {
    static let title: LocalizedStringResource = "Plan One Step"
    static let description = IntentDescription("Ask Apple Intelligence for one tool proposal. This action does not execute it.")
    static let openAppWhenRun = true
    @Parameter(title: "Goal") var goal:String
    @Parameter(title: "State",default: "No actions executed.") var state:String
    @Parameter(title: "Last result",default: "None") var latest:String
    @MainActor func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let policy:ResourcePolicy
        if let data=UserDefaults.standard.data(forKey:"policy"){policy=try JSONDecoder().decode(ResourcePolicy.self,from:data).validated()}else{throw SandboxError.blocked("Save authorization in the app first.")}
        let snapshot=DeviceSnapshot.read()
        if let reason=snapshot.stopReason(policy:policy,initialBattery:snapshot.battery){throw SandboxError.blocked(reason)}
        let text=try await AppleProvider().step(goal:goal,capsule:state,latest:latest,policy:policy)
        _=try AgentAction.parse(text)
        return .result(value:text)
    }
}
struct OpenSandboxIntent: AppIntent {
    static let title:LocalizedStringResource="Open Local Sandbox"
    static let openAppWhenRun=true
    func perform() async throws -> some IntentResult { .result() }
}
struct LocalSandboxShortcuts: AppShortcutsProvider {
    static var appShortcuts:[AppShortcut] {
        AppShortcut(intent:RunSandboxIntent(),phrases:["Run a task in \(.applicationName)"],shortTitle:"Run bounded task",systemImageName:"square.stack.3d.up")
        AppShortcut(intent:OpenSandboxIntent(),phrases:["Open \(.applicationName)"],shortTitle:"Open sandbox",systemImageName:"folder")
    }
}
