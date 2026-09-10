import Foundation
import LocalAuthentication

@MainActor enum LocalAccess {
    static func authenticate() async throws {
        guard Keychain.get("appleUser") != nil else { throw SandboxError.blocked("Sign in with Apple in Local Sandbox first.") }
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        let accepted = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your Local Sandbox files and actions.")
        guard accepted else { throw SandboxError.blocked("Device authentication required.") }
    }
}
