import Foundation

@main
enum WorkspacePreparationContracts {
    @MainActor
    final class Fixture {
        var files: [String: String]
        var writes: [(path: String, createOnly: Bool)] = []
        var qualificationPreparations = 0
        var shortcutUpdates = 0
        let deviceAuthorizationData: Data?
        let interveningCreate: (path: String, content: String)?

        init(
            files: [String: String] = [:],
            deviceAuthorizationData: Data? = nil,
            interveningCreate: (path: String, content: String)? = nil
        ) {
            self.files = files
            self.deviceAuthorizationData = deviceAuthorizationData
            self.interveningCreate = interveningCreate
        }

        func operations() -> WorkspacePreparationOperations {
            WorkspacePreparationOperations(
                workspaceConnected: { true },
                prepareProviderQualification: { self.qualificationPreparations += 1 },
                exists: { self.files[$0.value] != nil },
                writeText: { path, content, createOnly in
                    if createOnly, self.interveningCreate?.path == path.value,
                       let interveningContent = self.interveningCreate?.content {
                        self.files[path.value] = interveningContent
                    }
                    if createOnly && self.files[path.value] != nil {
                        throw SandboxError.conflict("FILE_EXISTS")
                    }
                    self.files[path.value] = content
                    self.writes.append((path.value, createOnly))
                },
                loadWorkspacePolicy: {
                    guard let text = self.files["config/policy.json"], let data = text.data(using: .utf8) else {
                        throw SandboxError.blocked("MISSING_POLICY")
                    }
                    return try JSONDecoder().decode(ResourcePolicy.self, from: data)
                },
                deviceAuthorizationData: { self.deviceAuthorizationData },
                updateAppShortcutParameters: { self.shortcutUpdates += 1 }
            )
        }
    }

    static func check(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() {
            throw NSError(domain: "WorkspacePreparationContracts", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
        }
    }

    static func encoded(_ policy: ResourcePolicy) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(policy)
    }

    @MainActor
    static func main() throws {
        var authorized = ResourcePolicy()
        authorized.provider = "local"
        authorized.contextChars = 4_000
        authorized = try authorized.validated()
        let policyText = String(decoding: try encoded(authorized), as: UTF8.self) + "\n"
        let originalFiles = [
            "config/oracle.md": "user-owned oracle bytes\n",
            "config/policy.json": policyText,
            "workspace/test.txt": "user-owned test bytes\n",
        ]
        let existing = Fixture(files: originalFiles, deviceAuthorizationData: try encoded(authorized))
        let existingResult = try WorkspacePreparationService(
            operations: existing.operations(),
            oraclePolicy: "replacement must not be written"
        ).prepare(defaultPolicy: ResourcePolicy())
        try check(existing.files == originalFiles, "preparation changed existing workspace bytes")
        try check(existing.writes.isEmpty, "preparation attempted a write for an existing default")
        try check(existingResult.createdPaths.isEmpty, "existing files were reported as newly created")
        try check(existingResult.policy == authorized, "device authorization was not returned to AppModel")
        try check(existing.qualificationPreparations == 1 && existing.shortcutUpdates == 1, "preparation hooks did not run exactly once")

        let missing = Fixture()
        let missingResult = try WorkspacePreparationService(
            operations: missing.operations(),
            oraclePolicy: "default oracle"
        ).prepare(defaultPolicy: authorized)
        try check(Set(missingResult.createdPaths) == Set(["config/oracle.md", "config/policy.json", "workspace/test.txt"]), "missing defaults were not created exactly once")
        try check(missing.files["config/oracle.md"] == "default oracle", "default oracle content was not created")
        try check(missing.files["workspace/test.txt"] == "Status: pending", "default workspace probe was not created")
        try check(missing.writes.allSatisfy { $0.createOnly }, "a default write was not create-only")
        try check(missingResult.status == "Review the default resource policy and tap Save authorization before running.", "missing device authorization did not remain review-only")

        let racedPolicy = "user-created-between-check-and-write\n"
        let raced = Fixture(interveningCreate: ("config/policy.json", racedPolicy))
        do {
            _ = try WorkspacePreparationService(
                operations: raced.operations(),
                oraclePolicy: "default oracle"
            ).prepare(defaultPolicy: authorized)
            throw NSError(domain: "WorkspacePreparationContracts", code: 2, userInfo: [NSLocalizedDescriptionKey: "intervening policy create was overwritten"])
        } catch let error as SandboxError {
            try check(error.localizedDescription == "FILE_EXISTS", "intervening policy create returned the wrong conflict")
        }
        try check(raced.files["config/policy.json"] == racedPolicy, "intervening policy bytes were overwritten")

        let invalidBytes = "{\"provider\":\"untrusted\"}\n"
        let invalid = Fixture(files: [
            "config/oracle.md": "keep",
            "config/policy.json": invalidBytes,
            "workspace/test.txt": "keep",
        ])
        let invalidResult = try WorkspacePreparationService(
            operations: invalid.operations(),
            oraclePolicy: "unused"
        ).prepare(defaultPolicy: authorized)
        try check(invalid.files["config/policy.json"] == invalidBytes, "invalid existing policy bytes were rewritten")
        try check(invalid.writes.isEmpty, "invalid existing policy triggered a replacement write")
        try check(invalidResult.status?.hasPrefix("Workspace policy needs review and was not granted as authorization:") == true, "invalid workspace policy did not remain review-only")

        print("Workspace preparation contracts passed: focused service, create-only defaults, exact-byte preservation, and review-only workspace configuration.")
    }
}
