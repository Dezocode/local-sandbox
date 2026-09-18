import SwiftUI
import UIKit

struct ProviderSharingSettingsView: View {
    let provider: AppProvider
    @EnvironmentObject private var model: AppModel
    @State private var configuration: ProviderSharingConfiguration?
    @State private var status = "Sharing is blocked until permission is checked."
    @State private var error = ""
    @State private var resetConfirmation = false

    var body: some View {
        Form {
            Section("Recipient and Shortcut") {
                Text(provider.title).font(.headline)
                if let configuration {
                    LabeledContent("Saved Shortcut", value: configuration.name)
                    LabeledContent("Return mode", value: configuration.mode)
                    if !configuration.installURL.isEmpty { Text(configuration.installURL).font(.footnote) }
                }
                Text("This permission applies to the saved configuration on this iPhone. Review and save the actual Shortcut in Apple’s Shortcuts app. A custom Shortcut can be edited outside Local Sandbox; this app cannot verify its eventual destination, account, model, or local-only behavior.")
            }
            ProviderSharingDisclosureSection()
            Section("Permission on this iPhone") {
                Text(status)
                Button("Allow these handoffs on this iPhone") { approve() }.disabled(configuration == nil)
                Button("Withdraw sharing permission", role: .destructive) {
                    do { try ProviderSharingConsent.vault.withdraw(provider); refresh() }
                    catch { self.error = "Sharing is blocked here. Withdrawal could not be fully saved; retry before relying on it after restart. \(error.localizedDescription)" }
                }
                Text("Once allowed, app and Siri tasks use this permission without asking at each step. Saved resource and clipboard permissions, cloud authorization, local authentication and measured provider checks still apply. Withdrawal stops future app-controlled handoffs and returned actions. It cannot recall data already sent or stop a Shortcut already running in another app.")
                Button("Reset blocked permission record", role: .destructive) { resetConfirmation = true }
            }
            if !error.isEmpty { Section("Needs attention") { Text(error).foregroundStyle(.red) } }
        }
        .navigationTitle("Provider sharing")
        .onAppear { refresh() }
        .alert("Reset this provider’s permission?", isPresented: $resetConfirmation) {
            Button("Reset permission", role: .destructive) {
                do { try ProviderSharingConsent.vault.reset(provider); refresh() } catch { self.error = error.localizedDescription }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text("This removes only this provider’s permission and pending task bindings on this iPhone. Sharing stays blocked until you review and allow it again. Existing provider accounts and measured check history remain.") }
    }
    private func refresh() {
        do {
            let current = try ProviderSharingConsent.configuration(provider)
            try ProviderSharingConsent.vault.reconcile(current)
            configuration = current
            let record = try ProviderSharingConsent.vault.load(provider)
            if record?.state == .withdrawalPending { status = "Withdrawal pending. Handoffs are blocked; retry withdrawal." }
            else if let record, record.state == .active, (try? ProviderSharingConsent.require(provider)) != nil { status = "Allowed for this saved Shortcut on this iPhone." }
            else { status = "Not allowed. Review the disclosure before enabling handoffs." }
            error = ""
        } catch { configuration = nil; self.error = error.localizedDescription; status = "Permission could not be verified. Handoffs are blocked." }
    }
    private func approve() {
        do {
            guard let reviewed = configuration, try ProviderSharingConsent.configuration(provider) == reviewed else { throw SandboxError.blocked("The saved Shortcut changed. Review its configuration again.") }
            let policy = try SavedExecutionAuthorization.load()
            guard !provider.usesCloud || policy.cloudAllowed else { throw SandboxError.blocked("Save cloud authorization in Settings before allowing this cloud provider.") }
            try ProviderSharingConsent.vault.approve(reviewed, owner: ProviderSharingConsent.owner())
            refresh()
        } catch { self.error = error.localizedDescription }
    }
}

struct ProviderSharingDisclosureSection: View {
    var body: some View {
        Section("What is sent") {
            Text("Task text and verification instructions, including paths and expected text you provide.")
            Text("Run context and action instructions, including run ID, step and failure counters.")
            Text("The latest tool result, which may contain workspace file names and content. Clipboard content can be included only if you separately save permission for clipboard reads.")
            Text("Synthetic provider-check prompts and their returned responses. These checks do not read your workspace contents.")
            Text("The receiving Shortcut and app use their own settings and policies for storage and further sharing. Local Sandbox cannot control or promise their retention or deletion. Review the receiving app’s privacy information before allowing handoffs.")
        }
    }
}

private struct PromptSharePresentation: Identifiable {
    let id = UUID()
    let source: CheckedPromptActivityItemSource
}

@MainActor
final class CheckedPromptActivityItemSource: NSObject, @MainActor UIActivityItemSource {
    let reviewed: String
    let generation: ExecutionContinuationGate.Generation
    let readPrompt: @MainActor () throws -> String
    init(reviewed: String, generation: ExecutionContinuationGate.Generation, readPrompt: @escaping @MainActor () throws -> String = { try ShortcutCoordinator.shared.currentPrompt() }) { self.reviewed = reviewed; self.generation = generation; self.readPrompt = readPrompt }
    func activityViewControllerPlaceholderItem(_ activityViewController: UIActivityViewController) -> Any { "" }
    func activityViewController(_ activityViewController: UIActivityViewController, itemForActivityType activityType: UIActivity.ActivityType?) -> Any? {
        do {
            try ExecutionContinuationGate.shared.requireCurrent(generation)
            guard try readPrompt() == reviewed else { return nil }
            return reviewed
        } catch { return nil }
    }
}

struct CheckedPromptShareSheet: UIViewControllerRepresentable {
    let source: CheckedPromptActivityItemSource
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [source], applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

struct PromptExportReview: Identifiable {
    let id = UUID()
    let prompt: String
    let generation: ExecutionContinuationGate.Generation
}

struct PromptExportReviewView: View {
    let review: PromptExportReview
    @Environment(\.dismiss) private var dismiss
    @State private var presentation: PromptSharePresentation?
    @State private var error = ""
    var body: some View {
        NavigationStack {
            Form {
                Section("Choose a separate recipient") {
                    Text("This is a one-time export of the exact prompt below. It may include task text, verification paths and expected values, run context, and the latest authorized file or clipboard result. The share sheet recipient may differ from your configured provider. Choose only a recipient you intend to receive this data. Their storage and further sharing are outside Local Sandbox’s control.")
                    Text("This export does not create or renew a provider permission. Once delivered, the copy cannot be recalled.")
                }
                Section("Exact prompt") { Text(review.prompt).font(.system(.footnote, design: .monospaced)) }
                Section {
                    Button("Allow this export and choose recipient") {
                        do {
                            try ExecutionContinuationGate.shared.requireCurrent(review.generation)
                            guard try ShortcutCoordinator.shared.currentPrompt() == review.prompt else { throw SandboxError.blocked("The prompt or permission changed. Start a new export review.") }
                            presentation = PromptSharePresentation(source: CheckedPromptActivityItemSource(reviewed: review.prompt, generation: review.generation))
                        } catch { self.error = error.localizedDescription }
                    }
                    Button("Cancel", role: .cancel) { dismiss() }
                }
                if !error.isEmpty { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("Review prompt export")
            .sheet(item: $presentation, onDismiss: { dismiss() }) { item in CheckedPromptShareSheet(source: item.source) }
        }
    }
}
