import XCTest
import UIKit
import SwiftUI
import CryptoKit
@testable import LocalSandbox

@MainActor
private final class SharingFixture {
    let priorVault = ProviderSharingConsent.vault
    var records: [AppProvider: String] = [:]
    var denied = Set<AppProvider>()
    var failDelete = false
    let user = "provider-sharing-test-" + UUID().uuidString
    private var keys: [String: String] = [:]
    private var defaults: [String: Any] = [:]
    let policy: ResourcePolicy
    let adapter = ShortcutAdapter(name: "Reviewed local test")
    init() throws {
        for name in ["appleUser", "appleLocalWorkspaceBinding.v1"] { if let value = try Keychain.getChecked(name) { keys[name] = value } }
        for name in ["policy", "adapter.local", "sandboxBookmark"] { defaults[name] = UserDefaults.standard.object(forKey: name) }
        var policy = ResourcePolicy(); policy.notifications = false; policy.memoryTarget = 80; policy.batteryReserve = 5
        self.policy = policy
        try Keychain.set(user, for: "appleUser")
        try Keychain.deleteChecked("appleLocalWorkspaceBinding.v1")
        UserDefaults.standard.set(try JSONEncoder().encode(policy), forKey: "policy")
        UserDefaults.standard.set(try JSONEncoder().encode(adapter), forKey: "adapter.local")
        try SandboxStore.shared.useLocal()
        ProviderSharingConsent.vault = ProviderSharingConsentVault(operations: .init(
            read: { self.records[$0] }, write: { self.records[$0] = $1 },
            delete: { if self.failDelete { throw SandboxError.blocked("CONSENT_DELETE_INJECTED") }; self.records[$0] = nil },
            isDenied: { self.denied.contains($0) }, deny: { self.denied.insert($0) }, clearDenial: { self.denied.remove($0) }
        ))
        try ProviderSharingConsent.vault.approve(ProviderSharingConsent.configuration(.local), owner: user)
    }
    func cleanup() {
        SandboxStore.shared.disconnect()
        if let base = try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: false) {
            try? FileManager.default.removeItem(at: base.appendingPathComponent("LocalSandbox").appendingPathComponent(NativeDigest.sha256(user)))
        }
        for name in ["appleUser", "appleLocalWorkspaceBinding.v1"] {
            if let value = keys[name] { try? Keychain.set(value, for: name) } else { try? Keychain.deleteChecked(name) }
        }
        for name in ["policy", "adapter.local", "sandboxBookmark"] {
            if let value = defaults[name] { UserDefaults.standard.set(value, forKey: name) } else { UserDefaults.standard.removeObject(forKey: name) }
        }
        ProviderSharingConsent.vault = priorVault
    }
    func session(origin: ProviderTaskOrigin = .app) throws -> ShortcutSession {
        let snapshot = ProviderQualificationSnapshot(provider: .local, epochSHA256: String(repeating: "a", count: 64), adapterSHA256: String(repeating: "b", count: 64), sampleCount: 5, distinctProbeCount: 5, verifiedCount: 5, schemaPassCount: 5, assertionPassCount: 5, assertionCount: 5, toolProbePassCount: 3, maximumContextCharacters: 6000, medianDurationBucketMilliseconds: 500, integrityFaultCount: 0, appIntentReturnObserved: true, lastSuccessfulAt: "2026-09-17T00:00:00Z")
        let evidence = ProviderRoutingEvidence(selection: .local, provider: .local, authorizedProvider: .local, strategy: .explicitPinned, activity: .workspaceIdle, accessEvidence: .recentLocallyValidatedResponse, deviceProfileSHA256: String(repeating: "a", count: 64), configurationSHA256: String(repeating: "b", count: 64), qualification: snapshot)
        return ShortcutSession(id: UUID().uuidString, goal: "Read workspace/test.txt", policy: policy, authorizationPolicy: policy, started: Date(), initialBattery: 100, providerSelection: .local, taskOrigin: origin, shortcutAdapterName: adapter.name, routingEvidence: evidence)
    }
    func save(_ session: ShortcutSession) throws {
        try SandboxStore.shared.save(session, path: "state/shortcut-session.json")
        try ProviderSharingConsent.bindSession(session)
    }
}

@MainActor
private final class HeldSharingAction {
    var continuation: CheckedContinuation<ToolResult, Error>?
    var waiters: [CheckedContinuation<Void, Never>] = []
    var calls = 0
    func invoke() async throws -> ToolResult {
        calls += 1
        return try await withCheckedThrowingContinuation { value in
            continuation = value
            waiters.forEach { $0.resume() }; waiters.removeAll()
        }
    }
    func ready() async {
        if continuation != nil { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func fail() { continuation?.resume(throwing: SandboxError.blocked("TOOL_ERROR")); continuation = nil }
}

final class ProviderSharingTests: XCTestCase {
    @MainActor
    func testActualCoordinatorRejectsRevokedAndEditedPendingState() async throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        let session = try fixture.session(); try fixture.save(session)
        var executions = 0
        let coordinator = ShortcutCoordinator(validateRoute: { _ in }, executeAction: { _, _, _, _, before in
            try before(); executions += 1
            return ToolResult(ok: true, tool: "file.read", result: "unexpected", sha256: nil, error_code: nil)
        })
        let prompt = try coordinator.currentPrompt()
        XCTAssertTrue(prompt.contains(session.goal))
        var edited = session; edited.latest = "imported secret payload"
        try SandboxStore.shared.save(edited, path: "state/shortcut-session.json")
        XCTAssertThrowsError(try coordinator.currentPrompt())
        try SandboxStore.shared.save(session, path: "state/shortcut-session.json")
        try ProviderSharingConsent.vault.withdraw(.local)
        XCTAssertThrowsError(try coordinator.currentPrompt())
        XCTAssertThrowsError(try coordinator.currentRunURL())
        do { _ = try await coordinator.accept("{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}"); XCTFail("revoked response admitted") } catch {}
        XCTAssertEqual(executions, 0)
        XCTAssertEqual(coordinator.current()?.phase, "awaiting_response")
        try ProviderSharingConsent.vault.approve(ProviderSharingConsent.configuration(.local), owner: fixture.user)
        XCTAssertThrowsError(try coordinator.currentPrompt(), "reconsent adopted old task")
    }

    @MainActor
    func testRecipientAndAppIntentEnvelopeUseOneCheckedSnapshot() throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        let session = try fixture.session(origin: .appIntent); try fixture.save(session)
        var attacker = session; attacker.shortcutAdapterName = "Unreviewed recipient"
        var reads = 0
        let coordinator = ShortcutCoordinator(validateRoute: { _ in }, readSession: { reads += 1; return reads == 1 ? session : attacker })
        let url = try coordinator.currentRunURL()
        XCTAssertEqual(reads, 1)
        XCTAssertEqual(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "name" })?.value, fixture.adapter.name)
        reads = 0
        let payload = try coordinator.currentPrompt()
        reads = 0
        let output = try coordinator.appIntentOutput(payload: payload, executionGeneration: ExecutionContinuationGate.shared.capture())
        XCTAssertEqual(reads, 1)
        let decoded = try JSONDecoder().decode(AppIntentTaskOutput.self, from: Data(output.utf8))
        XCTAssertEqual(decoded.adapterName, fixture.adapter.name)
        XCTAssertEqual(decoded.payload, payload)
    }

    @MainActor
    func testWithdrawnHeldEffectPreservesApplyingStateAndFailureCounters() async throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        var session = try fixture.session(); session.step = 2; session.failures = 2; session.repeated = 1; session.lastFailure = "TOOL_ERROR"
        try fixture.save(session)
        let held = HeldSharingAction()
        let started = expectation(description: "tool submitted")
        let coordinator = ShortcutCoordinator(validateRoute: { _ in }, readSnapshot: { DeviceSnapshot(battery: 100, memoryBytes: 1, physicalMemory: 100, thermal: .nominal) }, executeAction: { _, _, _, _, before in try before(); started.fulfill(); return try await held.invoke() })
        let task = Task { @MainActor in try await coordinator.accept("{\"kind\":\"tool\",\"tool\":\"file.read\",\"arguments\":{\"path\":\"workspace/test.txt\"}}") }
        await fulfillment(of: [started], timeout: 5)
        guard held.continuation != nil else { task.cancel(); let result = await task.result; XCTFail("action never submitted: \(result)"); return }
        let submitted = try SandboxStore.shared.read(SandboxPath("state/shortcut-session.json"))
        try ProviderSharingConsent.vault.withdraw(.local)
        held.fail()
        do { _ = try await task.value; XCTFail("retired effect continued") } catch {}
        XCTAssertEqual(held.calls, 1)
        XCTAssertEqual(try SandboxStore.shared.read(SandboxPath("state/shortcut-session.json")), submitted)
        XCTAssertEqual(coordinator.current()?.phase, "applying")
        XCTAssertEqual(coordinator.current()?.failures, 2)
    }

    @MainActor
    func testLazyExportSuppliesNoBytesAfterChangeWithdrawalOrLock() throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        let session = try fixture.session(); try fixture.save(session)
        let coordinator = ShortcutCoordinator(validateRoute: { _ in })
        let expected = try coordinator.currentPrompt()
        let source = CheckedPromptActivityItemSource(reviewed: expected, generation: ExecutionContinuationGate.shared.capture(), readPrompt: { try coordinator.currentPrompt() })
        let controller = UIActivityViewController(activityItems: [source], applicationActivities: nil)
        XCTAssertEqual(source.activityViewControllerPlaceholderItem(controller) as? String, "")
        XCTAssertEqual(source.activityViewController(controller, itemForActivityType: .copyToPasteboard) as? String, expected)
        var edited = session; edited.goal = "replacement task"
        try SandboxStore.shared.save(edited, path: "state/shortcut-session.json")
        XCTAssertNil(source.activityViewController(controller, itemForActivityType: .copyToPasteboard))
        try SandboxStore.shared.save(session, path: "state/shortcut-session.json")
        try ProviderSharingConsent.vault.withdraw(.local)
        XCTAssertNil(source.activityViewController(controller, itemForActivityType: .copyToPasteboard))
        let lockOnly = CheckedPromptActivityItemSource(reviewed: expected, generation: ExecutionContinuationGate.shared.capture(), readPrompt: { expected })
        XCTAssertEqual(lockOnly.activityViewController(controller, itemForActivityType: .copyToPasteboard) as? String, expected)
        ExecutionContinuationGate.shared.invalidate()
        XCTAssertNil(lockOnly.activityViewController(controller, itemForActivityType: .copyToPasteboard))
    }

    @MainActor
    func testMalformedEffectiveWorkspaceAdapterCannotReviveOldPermission() throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        UserDefaults.standard.removeObject(forKey: "adapter.local")
        try SandboxStore.shared.save(["local": fixture.adapter], path: "config/app-adapters.json")
        _ = try ProviderSharingConsent.require(.local)
        try SandboxStore.shared.save(["local": ShortcutAdapter(name: fixture.adapter.name, mode: "malformed")], path: "config/app-adapters.json")
        _ = AdapterSettings.get(.local)
        try SandboxStore.shared.save(["local": fixture.adapter], path: "config/app-adapters.json")
        XCTAssertThrowsError(try ProviderSharingConsent.require(.local))
    }

    @MainActor
    func testPromptShareSheetPresentsAndDismissesOnAttachedWindow() async throws {
        try await checkPromptSharePresentation(rotate: false)
    }

    @MainActor
    func testPromptShareSheetSurvivesSupportedSceneRotation() async throws {
        guard UIDevice.current.userInterfaceIdiom == .pad else { throw XCTSkip("iPad scene rotation coverage runs on iPad.") }
        try await checkPromptSharePresentation(rotate: true)
    }

    @MainActor
    private func checkPromptSharePresentation(rotate: Bool) async throws {
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first else { return XCTFail("No attached scene") }
        let previousWindow = scene.windows.first(where: \.isKeyWindow)
        let state = SharingPresentationState()
        let source = CheckedPromptActivityItemSource(reviewed: "Synthetic export check", generation: ExecutionContinuationGate.shared.capture(), readPrompt: { "Synthetic export check" })
        let host = UIHostingController(rootView: SharingPresentationHarness(state: state, source: source))
        let window = UIWindow(windowScene: scene); window.rootViewController = host; window.makeKeyAndVisible()
        defer { state.presented = false; window.isHidden = true; previousWindow?.makeKeyAndVisible() }
        state.presented = true
        func activity(in controller: UIViewController?) -> UIActivityViewController? {
            guard let controller else { return nil }
            if let value = controller as? UIActivityViewController { return value }
            if let value = activity(in: controller.presentedViewController) { return value }
            return controller.children.lazy.compactMap { activity(in: $0) }.first
        }
        for _ in 0..<40 where activity(in: host)?.viewIfLoaded?.window == nil { try await Task.sleep(for: .milliseconds(50)) }
        guard let presented = activity(in: host) else { return XCTFail("Share controller was not presented") }
        XCTAssertNotNil(presented.view.window)
        XCTAssertNotNil(host.presentedViewController)
        if rotate {
            var geometryError: Error?
            scene.requestGeometryUpdate(.iOS(interfaceOrientations: .landscapeLeft)) { geometryError = $0 }
            host.setNeedsUpdateOfSupportedInterfaceOrientations()
            for _ in 0..<40 where !scene.effectiveGeometry.interfaceOrientation.isLandscape { try await Task.sleep(for: .milliseconds(50)) }
            if let error = geometryError as NSError?, error.domain == "UISceneErrorDomain", error.code == 101 {
                throw XCTSkip("iPad windowing mode rejects app-requested orientation changes; rotation remains unverified in this environment.")
            }
            XCTAssertNil(geometryError)
            XCTAssertTrue(scene.effectiveGeometry.interfaceOrientation.isLandscape)
            XCTAssertNotNil(presented.view.window)
            XCTAssertGreaterThan(presented.view.bounds.width, 0)
            scene.requestGeometryUpdate(.iOS(interfaceOrientations: .portrait)) { geometryError = $0 }
            host.setNeedsUpdateOfSupportedInterfaceOrientations()
            for _ in 0..<40 where scene.effectiveGeometry.interfaceOrientation != .portrait { try await Task.sleep(for: .milliseconds(50)) }
            XCTAssertEqual(scene.effectiveGeometry.interfaceOrientation, .portrait)
        }
        state.presented = false
        for _ in 0..<40 where host.presentedViewController != nil { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertNil(host.presentedViewController)
    }

    @MainActor
    func testActualQualificationTerminalRetryPreservesConsentAndCounters() throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("qualification-consent-" + UUID().uuidString)
        let priorDirectory = ProviderQualificationStore.ledgerDirectory
        let priorKey = try Keychain.getChecked("providerQualificationLedgerHMAC")
        ProviderQualificationStore.ledgerDirectory = { directory }
        defer {
            ProviderQualificationStore.ledgerDirectory = priorDirectory
            if let priorKey { try? Keychain.set(priorKey, for: "providerQualificationLedgerHMAC") } else { try? Keychain.deleteChecked("providerQualificationLedgerHMAC") }
            try? FileManager.default.removeItem(at: directory)
        }
        let bytes = Data(repeating: 0x42, count: 32); let key = SymmetricKey(data: bytes)
        try Keychain.set(bytes.base64EncodedString(), for: "providerQualificationLedgerHMAC")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let epoch = ProviderQualificationStore.epochSHA256(provider: .local, adapter: fixture.adapter)
        let id = UUID().uuidString
        let message = "suite=\(ProviderQualificationStore.suiteVersion)|epoch=\(epoch)|provider=local|probe=strict-json|attempt=\(id)"
        let token = Data(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: key)).map { String(format: "%02x", $0) }.joined().prefix(24).description
        let prompt = ProviderQualificationVerifier.prompt(probe: .strictJSON, token: token, contextCharacters: 6000)
        let challenge = ProviderQualificationChallenge(attemptID: id, provider: .local, probe: .strictJSON, adapterName: fixture.adapter.name, prompt: prompt)
        try ProviderSharingConsent.bindQualification(challenge)
        let now = Date()
        let attempt = ProviderQualificationAttempt(attemptID: id, provider: .local, epochSHA256: epoch, adapterSHA256: ProviderQualificationStore.adapterSHA256(fixture.adapter), probe: .strictJSON, outcome: .verified, schemaPassCount: 1, assertionPassCount: 1, assertionCount: 1, promptCharacterCount: prompt.count, durationBucketMilliseconds: 500, appIntentReturnObserved: true, adapterStateReconciled: false, startedAt: now, finishedAt: now)
        let ledger = ProviderQualificationLedgerPayload(recordType: "provider-qualification-ledger", schemaVersion: ProviderQualificationLedgerPayload.currentSchemaVersion, suiteVersion: ProviderQualificationStore.suiteVersion, attempts: [attempt], recommendation: nil)
        let mac = Data(HMAC<SHA256>.authenticationCode(for: try JSONEncoder.sorted.encode(ledger), using: key)).map { String(format: "%02x", $0) }.joined()
        try JSONEncoder.sorted.encode(SignedProviderQualificationLedger(payload: ledger, hmacSHA256: mac)).write(to: directory.appendingPathComponent("provider-qualification-ledger.json"))
        try SandboxStore.shared.write(SandboxPath("config/app-adapters.json"), content: "malformed")
        let response = "{\"kind\":\"final\",\"summary\":\"\(token)\"}"
        XCTAssertThrowsError(try ProviderQualificationStore.complete(attemptID: id, provider: .local, response: response))
        try SandboxStore.shared.save(["local": fixture.adapter], path: "config/app-adapters.json")
        let repaired = try ProviderQualificationStore.complete(attemptID: id, provider: .local, response: response)
        XCTAssertEqual(repaired.outcome, .verified)
        XCTAssertEqual(repaired.adapterStateReconciled, true)
        XCTAssertEqual(try ProviderQualificationStore.complete(attemptID: id, provider: .local, response: response), repaired)
        XCTAssertEqual(try ProviderQualificationStore.snapshots()[.local]?.sampleCount, 1)
        try ProviderSharingConsent.vault.withdraw(.local)
        try ProviderSharingConsent.vault.approve(ProviderSharingConsent.configuration(.local), owner: fixture.user)
        XCTAssertThrowsError(try ProviderQualificationStore.complete(attemptID: id, provider: .local, response: response))
    }

    @MainActor
    func testProfileDeletionRetainsIdentityWhenConsentCleanupFails() async throws {
        let fixture = try SharingFixture(); defer { fixture.cleanup() }
        fixture.failDelete = true
        let auth = NativeAppleAuthController(api: NativeAppleAuthAPI(endpoints: try NativeServiceEndpoints(origin: URL(string: "https://example.com")!), transport: SharingUnexpectedTransport()), vault: NativeBearerVault(read: { nil }, write: { _ in }, delete: {}))
        let model = AppModel(nativeAuth: auth)
        model.userID = fixture.user; model.unlocked = true
        await model.deleteProfile()
        XCTAssertEqual(try Keychain.getChecked("appleUser"), fixture.user)
        XCTAssertTrue(model.error.contains("CONSENT_DELETE_INJECTED"), model.error)
    }
}

private struct SharingUnexpectedTransport: NativeHTTPPerforming {
    func perform(_ request: URLRequest, maximumResponseBytes: Int) async throws -> NativeHTTPResult { throw SandboxError.blocked("UNEXPECTED_NETWORK") }
}

@MainActor
private final class SharingPresentationState: ObservableObject { @Published var presented = false }
private struct SharingPresentationHarness: View {
    @ObservedObject var state: SharingPresentationState
    let source: CheckedPromptActivityItemSource
    var body: some View { Text("Share test").sheet(isPresented: $state.presented) { CheckedPromptShareSheet(source: source) } }
}
