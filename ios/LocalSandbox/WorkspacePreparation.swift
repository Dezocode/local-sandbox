import Foundation

struct WorkspacePreparationResult: Equatable {
    let policy: ResourcePolicy
    let status: String?
    let createdPaths: [String]
}

@MainActor
struct WorkspacePreparationOperations {
    let workspaceConnected: () -> Bool
    let prepareProviderQualification: () throws -> Void
    let exists: (SandboxPath) throws -> Bool
    let writeText: (SandboxPath, String, Bool) throws -> Void
    let loadWorkspacePolicy: () throws -> ResourcePolicy
    let deviceAuthorizationData: () -> Data?
    let updateAppShortcutParameters: () -> Void
}

@MainActor
struct WorkspacePreparationService {
    private let operations: WorkspacePreparationOperations
    private let oraclePolicy: String

    init(operations: WorkspacePreparationOperations, oraclePolicy: String) {
        self.operations = operations
        self.oraclePolicy = oraclePolicy
    }

    static var live: Self {
        let store = SandboxStore.shared
        return Self(
            operations: WorkspacePreparationOperations(
                workspaceConnected: { store.connected },
                prepareProviderQualification: { try ProviderQualificationStore.prepare() },
                exists: { try store.exists($0) },
                writeText: { path, content, createOnly in
                    try store.write(path, content: content, createOnly: createOnly)
                },
                loadWorkspacePolicy: { try store.load(ResourcePolicy.self, path: "config/policy.json") },
                deviceAuthorizationData: { UserDefaults.standard.data(forKey: "policy") },
                updateAppShortcutParameters: { LocalSandboxShortcuts.updateAppShortcutParameters() }
            ),
            oraclePolicy: nativeOraclePolicy
        )
    }

    func prepare(defaultPolicy: ResourcePolicy) throws -> WorkspacePreparationResult {
        guard operations.workspaceConnected() else {
            throw SandboxError.blocked("CONNECT_SANDBOX_FOLDER_FIRST")
        }
        try operations.prepareProviderQualification()

        var createdPaths: [String] = []
        let oraclePath = try SandboxPath("config/oracle.md")
        if try !operations.exists(oraclePath) {
            try operations.writeText(oraclePath, oraclePolicy, true)
            createdPaths.append(oraclePath.value)
        }

        let baselinePolicy = try defaultPolicy.validated()
        let deviceAuthorization = decodeDeviceAuthorization(operations.deviceAuthorizationData())
        let resolvedPolicy = deviceAuthorization ?? baselinePolicy
        let policyPath = try SandboxPath("config/policy.json")
        var status: String?
        if try operations.exists(policyPath) {
            do {
                var workspacePolicy = try operations.loadWorkspacePolicy()
                if workspacePolicy.provider == "openai" { workspacePolicy.provider = "chatgpt" }
                workspacePolicy = try workspacePolicy.validated()
                if deviceAuthorization == nil {
                    status = "Workspace policy is configuration only. Review it in Settings and tap Save authorization before running."
                } else if workspacePolicy != deviceAuthorization {
                    status = "Workspace policy differs from this iPhone's saved authorization. Review Settings and tap Save authorization to replace the workspace copy."
                }
            } catch {
                status = "Workspace policy needs review and was not granted as authorization: \(error.localizedDescription)"
            }
        } else {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let encodedPolicy = String(decoding: try encoder.encode(resolvedPolicy), as: UTF8.self)
            try operations.writeText(policyPath, encodedPolicy, true)
            createdPaths.append(policyPath.value)
            if deviceAuthorization == nil {
                status = "Review the default resource policy and tap Save authorization before running."
            }
        }

        let testPath = try SandboxPath("workspace/test.txt")
        if try !operations.exists(testPath) {
            try operations.writeText(testPath, "Status: pending", true)
            createdPaths.append(testPath.value)
        }
        operations.updateAppShortcutParameters()
        return WorkspacePreparationResult(policy: resolvedPolicy, status: status, createdPaths: createdPaths)
    }

    private func decodeDeviceAuthorization(_ data: Data?) -> ResourcePolicy? {
        guard let data, var policy = try? JSONDecoder().decode(ResourcePolicy.self, from: data) else { return nil }
        if policy.provider == "openai" { policy.provider = "chatgpt" }
        return try? policy.validated()
    }
}
