import SwiftUI

@MainActor
extension NativeAutosaveJournal {
    static let live = NativeAutosaveJournal(
        load: { rawPath in
            let path = try journalPath(for: rawPath)
            guard let data = try SandboxStore.shared.readAutosaveJournal(path) else { return nil }
            let draft = try JSONDecoder().decode(NativeAutosaveDraft.self, from: data)
            try draft.validate()
            return draft
        },
        save: { draft in
            try draft.validate()
            let encoder = JSONEncoder();encoder.outputFormatting = [.sortedKeys]
            try SandboxStore.shared.writeAutosaveJournal(try journalPath(for: draft.path), data: encoder.encode(draft))
        },
        removeIf: { rawPath, generation in
            let path = try journalPath(for: rawPath)
            guard let data = try SandboxStore.shared.readAutosaveJournal(path) else { return true }
            let current = try JSONDecoder().decode(NativeAutosaveDraft.self, from: data)
            guard current.path == rawPath, current.generation == generation else { return false }
            try SandboxStore.shared.deleteAutosaveJournal(path)
            return true
        },
        remove: { rawPath in try SandboxStore.shared.deleteAutosaveJournal(try journalPath(for: rawPath)) }
    )

    private static func journalPath(for rawPath: String) throws -> SandboxPath {
        _ = try SandboxPath(rawPath)
        return try SandboxPath("state/autosave/\(SandboxStore.hash(rawPath)).json")
    }
}

@MainActor
extension NativeAutosaveRepository {
    static let live = NativeAutosaveRepository(
        read: { rawPath in
            let path = try SandboxPath(rawPath)
            guard try SandboxStore.shared.exists(path) else { return nil }
            return try SandboxStore.shared.read(path)
        },
        write: { rawPath, content, expectedSHA256 in
            let path = try SandboxPath(rawPath)
            if let expectedSHA256 {
                try SandboxStore.shared.write(path, content: content, expectedSHA256: expectedSHA256)
            } else {
                try SandboxStore.shared.write(path, content: content, createOnly: true)
            }
            return try SandboxStore.shared.read(path)
        }
    )
}

struct NativeFileEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var editor: NativeAutosaveCoordinator
    @State private var confirmDiscard = false
    let onClose: () -> Void

    init(path: String, onClose: @escaping () -> Void) {
        _editor = StateObject(wrappedValue: NativeAutosaveCoordinator(path: path, journal: .live, repository: .live))
        self.onClose = onClose
    }

    var body: some View {
        VStack(spacing: 0) {
            TextEditor(text: Binding(get: { editor.content }, set: { editor.edit($0) }))
                .font(.system(.body, design: .monospaced))
                .padding()
                .disabled(!editor.acceptsEdits)
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                Label(editor.state.message, systemImage: statusIcon)
                    .foregroundStyle(statusColor)
                    .font(.footnote)
                if editor.state.phase == .offlineOrFailed {
                    Button("Retry journal and save") { Task { await editor.retry() } }
                    if !editor.acceptsEdits {
                        Button("Discard unreadable recovery journal", role: .destructive) { confirmDiscard = true }
                    }
                }
                if editor.state.phase == .conflict {
                    GroupBox("Review conflict") {
                        VStack(alignment: .leading, spacing: 8) {
                            LabeledContent("Draft", value: preview(editor.content))
                            LabeledContent("Current file", value: preview(editor.state.remoteContent))
                            HStack {
                                Button("Use current file") { Task { await editor.useCurrentFile() } }
                                Button("Keep draft") { Task { await editor.keepDraft() } }
                            }
                        }
                    }
                }
            }.padding()
        }
        .navigationTitle(editor.path)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Close") {
                    Task {
                        await editor.flush()
                        if editor.canCloseWithoutDiscard { finish() } else { confirmDiscard = true }
                    }
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save now") { Task { await editor.flush() } }
                    .disabled(!editor.hasPendingChanges || editor.state.phase == .conflict)
            }
        }
        .task { await editor.load() }
        .onChange(of: scenePhase) { _, phase in if phase != .active { Task { await editor.flush() } } }
        .onDisappear { editor.stopScheduling() }
        .interactiveDismissDisabled(editor.hasPendingChanges)
        .confirmationDialog("Discard the journaled draft?", isPresented: $confirmDiscard) {
            Button("Discard draft", role: .destructive) {
                Task { await editor.discardDraft();if editor.canCloseWithoutDiscard { finish() } }
            }
            Button("Keep editing", role: .cancel) {}
        } message: {
            Text("Changes remain in this editor and, when journaling succeeded, in its recovery journal. Retry or resolve the conflict unless you intend to discard them.")
        }
    }

    private var statusIcon: String {
        switch editor.state.phase {
        case .loading: return "hourglass"
        case .clean, .saved: return "checkmark.circle"
        case .dirty, .recovered: return "pencil.circle"
        case .saving: return "arrow.triangle.2.circlepath"
        case .offlineOrFailed: return "exclamationmark.triangle"
        case .conflict: return "arrow.triangle.branch"
        }
    }

    private var statusColor: Color {
        switch editor.state.phase {
        case .clean, .saved: return .green
        case .offlineOrFailed, .conflict: return .orange
        default: return .secondary
        }
    }

    private func preview(_ value: String?) -> String {
        guard let value else { return "Missing" }
        return value.count <= 180 ? (value.isEmpty ? "Empty" : value) : String(value.prefix(180)) + "…"
    }

    private func finish() { onClose();dismiss() }
}
