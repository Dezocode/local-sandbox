import Foundation
import UIKit
import FoundationModels
import UserNotifications

enum AppProvider: String, CaseIterable, Codable, Identifiable {
    case local, chatgpt, grok, grokbot, claude, apple
    var id: String { rawValue }
    var title: String { switch self { case .local: return "Locally"; case .chatgpt: return "ChatGPT"; case .grok: return "Grok"; case .grokbot: return "Grokbot"; case .claude: return "Claude"; case .apple: return "Apple Intelligence" } }
    var shortcut: String { self == .local ? "Agent Step - Local" : self == .apple ? "Agent Step - Apple" : "Agent Step - \(title)" }
    var usesCloud: Bool { self != .local && self != .apple }
    @MainActor var unavailableReason: String? {
        if self == .apple {
            switch SystemLanguageModel.default.availability {
            case .available: return nil
            case .unavailable(let reason): return "Apple Intelligence is not available on this device: \(String(describing: reason)). Locally and app Shortcuts remain available."
            @unknown default: return "Apple Intelligence availability could not be determined."
            }
        }
        guard let url=URL(string:"shortcuts://"),UIApplication.shared.canOpenURL(url) else { return "Install Apple Shortcuts to use this provider." }
        return nil
    }
}
struct ShortcutAdapter: Codable {
    var name: String
    var installURL = ""
    var mode = "action"
    var tested = false
}
@MainActor enum AdapterSettings {
    static func deviceReport() -> String {
        let reason=AppProvider.apple.unavailableReason
        let report:[String:Any]=["version":1,"name":UIDevice.current.model,"os":"iOS \(UIDevice.current.systemVersion)","appleAvailable":reason==nil,"appleReason":reason ?? "Available","reportedAt":ISO8601DateFormatter().string(from:Date())]
        return (try? String(decoding:JSONSerialization.data(withJSONObject:report,options:[.sortedKeys]),as:UTF8.self)) ?? "{}"
    }
    static func get(_ provider: AppProvider) -> ShortcutAdapter {
        if let data=UserDefaults.standard.data(forKey:"adapter.\(provider.rawValue)"),let value=try? JSONDecoder().decode(ShortcutAdapter.self,from:data){return value}
        if SandboxStore.shared.connected,let values=try? SandboxStore.shared.load([String:ShortcutAdapter].self,path:"config/app-adapters.json"),var value=values[provider.rawValue]{value.tested=false;return value}
        return ShortcutAdapter(name:provider.shortcut)
    }
    static func save(_ value:ShortcutAdapter,for provider:AppProvider) throws {
        guard !value.name.isEmpty,value.name.count<=80,["action","manual"].contains(value.mode) else {throw SandboxError.invalid("Invalid Shortcut configuration.")}
        if !value.installURL.isEmpty {guard let url=URL(string:value.installURL),url.scheme=="https",url.host=="www.icloud.com",url.path.range(of:"^/shortcuts/[a-fA-F0-9]{32}$",options:.regularExpression) != nil else {throw SandboxError.invalid("Use a shared iCloud Shortcut link.")}}
        if SandboxStore.shared.connected {
            let store=SandboxStore.shared;let path=try SandboxPath("config/app-adapters.json")
            let exists=try store.list("config").contains(path.value)
            let before=exists ? try store.read(path):nil
            var values=try before.map{try JSONDecoder().decode([String:ShortcutAdapter].self,from:Data($0.utf8))} ?? [:]
            values[provider.rawValue]=value
            try store.write(path,content:String(decoding:JSONEncoder.sorted.encode(values),as:UTF8.self),createOnly:!exists,expectedSHA256:before.map{SandboxStore.hash($0)})
        }
        UserDefaults.standard.set(try JSONEncoder().encode(value),forKey:"adapter.\(provider.rawValue)")
    }
    static func runURL(name:String,input:String)->URL? {
        var url=URLComponents();url.scheme="shortcuts";url.host="run-shortcut";url.queryItems=[URLQueryItem(name:"name",value:name),URLQueryItem(name:"input",value:"text"),URLQueryItem(name:"text",value:input)];return url.url
    }
}
struct ShortcutSession: Codable {
    var id:String;var goal:String;var policy:ResourcePolicy;var started:Date;var initialBattery:Int?
    var step=0;var failures=0;var repeated=0;var lastFailure="";var latest="No actions executed."
    var phase="awaiting_response";var trace:[TraceEntry]=[];var lastResponseHash=""
}
@MainActor final class ShortcutCoordinator {
    static let shared=ShortcutCoordinator()
    private let store=SandboxStore.shared
    private var applying=false
    func current()->ShortcutSession? {try? store.load(ShortcutSession.self,path:"state/shortcut-session.json")}
    func begin(goal:String,policy:ResourcePolicy) throws -> String {
        guard !AgentRunner.shared.running,!applying else {throw SandboxError.blocked("Another task is active.")}
        if let prior=current(),["awaiting_response","applying"].contains(prior.phase){throw SandboxError.blocked("Resume or stop the pending app handoff first.")}
        let policy=try policy.validated()
        guard !goal.isEmpty,goal.count<=2000,let provider=AppProvider(rawValue:policy.provider) else {throw SandboxError.invalid("Enter a task up to 2,000 characters.")}
        if let reason=provider.unavailableReason {throw SandboxError.blocked(reason)}
        guard !provider.usesCloud || policy.cloudAllowed else {throw SandboxError.blocked("Authorize cloud app handoffs in Settings first.")}
        guard provider == .apple || AdapterSettings.get(provider).tested else {throw SandboxError.blocked("This provider Shortcut has not passed setup. Save it in Shortcuts and complete the read-only round-trip in Settings first.")}
        let snapshot=DeviceSnapshot.read();if let reason=snapshot.stopReason(policy:policy,initialBattery:snapshot.battery){throw SandboxError.blocked(reason)}
        let session=ShortcutSession(id:UUID().uuidString,goal:goal,policy:policy,started:Date(),initialBattery:snapshot.battery)
        try store.save(session,path:"state/shortcut-session.json")
        return prompt(session)
    }
    func prompt(_ session:ShortcutSession)->String {
        let reserved=max(500,session.policy.contextChars-nativeOraclePolicy.count-180)
        return String((nativeOraclePolicy+"\nRun: \(session.id). Step: \(session.step). Return only one action JSON.\n"+boundedPrompt(goal:session.goal,capsule:"\(session.step) steps, \(session.failures) failures. Latest result is authoritative.",latest:session.latest,limit:reserved)).prefix(session.policy.contextChars))
    }
    func accept(_ response:String) async throws -> String {
        guard !applying,!AgentRunner.shared.running else {throw SandboxError.blocked("Another action is active.")}
        applying=true;defer{applying=false}
        guard var session=current(),session.phase=="awaiting_response" else {throw SandboxError.blocked("No resumable app response is pending. Inspect the checkpoint if interrupted.")}
        if let saved=UserDefaults.standard.data(forKey:"policy"),let current=try? JSONDecoder().decode(ResourcePolicy.self,from:saved),current != session.policy {return try await finish(&session,status:.blocked,summary:"Authorization changed. Begin a new task with the saved policy.")}
        guard session.lastResponseHash != SandboxStore.hash(response) else {return prompt(session)}
        if let reason=DeviceSnapshot.read().stopReason(policy:session.policy,initialBattery:session.initialBattery){return try await finish(&session,status:.blocked,summary:reason)}
        guard session.step<session.policy.maxSteps else {return try await finish(&session,status:.blocked,summary:"Step budget exhausted.")}
        do {
            let action=try AgentAction.parse(response)
            switch action {
            case .final(let summary):
                let verified=session.trace.contains{$0.status=="ok"} && session.lastFailure.isEmpty
                return try await finish(&session,status:verified ? .verified:.blocked,summary:verified ? summary:"No clean execution evidence. "+summary)
            case .tool(let call):
                session.phase="applying";try store.save(session,path:"state/shortcut-session.json")
                let result=try await Dispatcher.shared.execute(call,callID:"\(session.id)-app-\(session.step)",policy:session.policy)
                session.latest=result.json;session.trace.append(TraceEntry(tool:call.tool.rawValue,status:"ok",detail:String(result.result.prefix(1000))))
                session.lastFailure="";session.repeated=0
            }
        } catch {
            let message=error.localizedDescription;session.failures+=1;session.repeated=message==session.lastFailure ? session.repeated+1:1;session.lastFailure=message;session.latest="Action failed: \(message). Read current state before proposing a repair."
            session.trace.append(TraceEntry(tool:"app.response",status:"error",detail:String(message.prefix(1000))))
            if message.contains("UNCERTAIN") || session.failures>=session.policy.maxFailures || session.repeated>=2 {return try await finish(&session,status:.blocked,summary:message)}
        }
        session.step+=1;session.lastResponseHash=SandboxStore.hash(response);session.phase="awaiting_response"
        if session.step>=session.policy.maxSteps{return try await finish(&session,status:.blocked,summary:"Step budget exhausted. Review the recorded results.")}
        try store.save(session,path:"state/shortcut-session.json");return prompt(session)
    }
    func stop() async throws {guard !applying else{throw SandboxError.blocked("Wait for the current action to finish before stopping.")};guard var session=current() else{return};_ = try await finish(&session,status:.cancelled,summary:"Stopped by user. No pending action replayed.")}
    private func finish(_ session:inout ShortcutSession,status:RunStatus,summary:String) async throws -> String {
        session.phase=status.rawValue;try store.save(session,path:"state/shortcut-session.json")
        let receipt=RunReceipt(id:session.id,goal:session.goal,status:status,origin:"native",summary:summary,steps:session.step,failures:session.failures,durationMs:Date().timeIntervalSince(session.started)*1000,createdAt:ISO8601DateFormatter().string(from:Date()),trace:session.trace)
        try store.save(receipt,path:"logs/\(session.id).json")
        if session.policy.notifications {let note=UNMutableNotificationContent();note.title="Local Sandbox · \(status.rawValue)";note.body=String(summary.prefix(200));try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier:session.id,content:note,trigger:nil))}
        return String(decoding:try JSONEncoder.sorted.encode(receipt),as:UTF8.self)
    }
}
