import Foundation
import LocalAuthentication

@MainActor
struct LocalAccessLease {
    let executionGeneration: ExecutionContinuationGate.Generation
    private let continuationValidator: ExecutionContinuationValidator

    init(
        executionGeneration: ExecutionContinuationGate.Generation,
        gate: ExecutionContinuationGate = .shared
    ) {
        self.executionGeneration = executionGeneration
        continuationValidator = gate.validator(for: executionGeneration)
    }

    func requireCurrent() throws {
        try continuationValidator.requireCurrent()
    }
}

@MainActor enum LocalAccess {
    static func authenticate(
        executionGeneration providedExecutionGeneration: ExecutionContinuationGate.Generation? = nil
    ) async throws -> LocalAccessLease {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        return try await authenticate(
            executionGeneration: providedExecutionGeneration,
            hasLocalAccount: { Keychain.get("appleUser") != nil },
            evaluatePolicy: {
                try await context.evaluatePolicy(
                    .deviceOwnerAuthentication,
                    localizedReason: "Unlock your Local Sandbox files and actions."
                )
            }
        )
    }

    static func authenticate(
        executionGeneration providedExecutionGeneration: ExecutionContinuationGate.Generation? = nil,
        gate: ExecutionContinuationGate = .shared,
        hasLocalAccount: @MainActor () -> Bool,
        evaluatePolicy: @MainActor () async throws -> Bool
    ) async throws -> LocalAccessLease {
        let executionGeneration = providedExecutionGeneration ?? gate.capture()
        let lease = LocalAccessLease(executionGeneration: executionGeneration, gate: gate)
        try lease.requireCurrent()
        guard hasLocalAccount() else {
            throw SandboxError.blocked("Sign in with Apple in Local Sandbox first.")
        }
        let accepted = try await gate.validator(for: executionGeneration).validatedAwait {
            try await evaluatePolicy()
        }
        guard accepted else { throw SandboxError.blocked("Device authentication required.") }
        try lease.requireCurrent()
        return lease
    }
}
