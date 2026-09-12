import SwiftUI
import UniformTypeIdentifiers

@MainActor
enum ShortcutDistributionApprovalStore {
    static let storageKey = "shortcutDistributionOrigin.v1"

    static func approvedOrigin() -> String? {
        try? approvedOriginChecked()
    }

    static func approvedOriginChecked(
        readChecked: () throws -> String? = { try Keychain.getChecked(storageKey) }
    ) throws -> String? {
        guard let raw = try readChecked() else { return nil }
        guard raw != ShortcutPackageContract.canonicalOrigin,
              (try? ShortcutPackageContract.validatedDistributionOrigin(raw)) == raw else {
            throw SandboxError.blocked("SHORTCUT_DISTRIBUTION_APPROVAL_INVALID")
        }
        return raw
    }

    static func isApproved(_ origin: String) -> Bool {
        origin == ShortcutPackageContract.canonicalOrigin || approvedOrigin() == origin
    }

    static func approve(_ origin: String) throws {
        let normalized = try ShortcutPackageContract.validatedDistributionOrigin(origin)
        guard normalized != ShortcutPackageContract.canonicalOrigin else { return }
        try Keychain.set(origin, for: storageKey)
    }

    static func clear(
        deleteChecked: () throws -> Void = { try Keychain.deleteChecked(storageKey) },
        readChecked: () throws -> String? = { try Keychain.getChecked(storageKey) }
    ) throws {
        try deleteChecked()
        guard try readChecked() == nil else {
            throw SandboxError.blocked("KEYCHAIN_DELETE_FAILED")
        }
    }
}

private struct PendingShortcutCatalog {
    let catalog: ShortcutCatalog
    let distributionOrigin: String
    let sha256: String
}

struct ShortcutPackagesView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL
    @State private var importing = false
    @State private var packages: [ShortcutPackage] = []
    @State private var selected: ShortcutPackage?
    @State private var installGate = ShortcutPackageInstallGate()
    @State private var openOutcome: ShortcutPackageOpenOutcome?
    @State private var pendingCatalog: PendingShortcutCatalog?

    var body: some View {
        List {
            Section {
                Text("Import a canonical Local Sandbox 0.3.0 catalog. The published origin is pretrusted. A self-hosted catalog requires one explicit approval for its exact normalized HTTPS origin on this iPhone.")
                Button("Import package catalog") { importing = true }
                    .disabled(installGate.isBusy)
                Link("Open published package installer", destination: URL(string: "https://local-sandbox.ctyy4wd4c2.chatgpt.site/local/install.html")!)
                if let approvedOrigin=ShortcutDistributionApprovalStore.approvedOrigin() {
                    LabeledContent("Approved self-host origin",value:approvedOrigin)
                    Button("Forget self-host origin",role:.destructive) {
                        do {
                            try ShortcutDistributionApprovalStore.clear()
                            packages=[]
                            openOutcome=nil
                            model.progress="Self-host Shortcut origin approval removed. Import its catalog again to approve it."
                        } catch {model.error=error.localizedDescription}
                    }
                }
            }
            if packages.isEmpty {
                Section {
                    Text("No signed 0.3.0 package is available. No Shortcut has been installed.")
                        .foregroundStyle(.secondary)
                }
            }
            ForEach(packages) { package in
                ShortcutPackageRow(
                    package: package,
                    isVerifying: installGate.activePackageID == package.id,
                    installsDisabled: installGate.isBusy
                ) {
                    selected = package
                }
            }
            if let openOutcome {
                Section {
                    Text(openOutcome.message)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            Section {
                Text("After Apple presents Add Shortcut and permissions, complete the provider's harmless text test in Apps & Shortcuts. A verified download does not prove installation or successful execution.")
                    .font(.footnote)
            }
        }
        .navigationTitle("Shortcut packages")
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            importCatalog(result)
        }
        .confirmationDialog(
            "Verify signed Shortcut package?",
            isPresented: Binding(
                get: { selected != nil },
                set: { if !$0 { selected = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let package = selected {
                Button("Verify and open \(package.name)") { beginInstall(package) }
                    .disabled(installGate.isBusy)
            }
            Button("Cancel", role: .cancel) { selected = nil }
        } message: {
            Text("Local Sandbox downloads without redirects, verifies the exact byte count and SHA-256, writes a bounded local .shortcut file, and only then asks Apple to open that local file.")
        }
        .alert("Trust exact self-host origin?",isPresented:Binding(
            get:{pendingCatalog != nil},
            set:{if !$0{pendingCatalog=nil}}
        )) {
            Button("Trust exact self-host origin") {approvePendingCatalog()}
            Button("Cancel",role:.cancel){pendingCatalog=nil}
        } message: {
            if let pendingCatalog {
                Text("Origin: \(pendingCatalog.distributionOrigin)\nRelease: \(pendingCatalog.catalog.release)\nPackages: \(pendingCatalog.catalog.packages.count)\nCatalog SHA-256: \(pendingCatalog.sha256)\n\nOnly this exact scheme, host, and nondefault port will be saved in this iPhone's Keychain. A different origin requires a new approval.")
            }
        }
    }

    private func importCatalog(_ result: Result<URL, Error>) {
        do {
            let url = try result.get()
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard (1...100_000).contains(size) else {
                throw ShortcutPackageValidationError.invalidCatalog
            }
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            guard data.count <= 100_000 else { throw ShortcutPackageValidationError.invalidCatalog }
            let catalog = try JSONDecoder().decode(ShortcutCatalog.self, from: data)
            let distributionOrigin=try catalog.candidateDistributionOrigin()
            let catalogSHA256=ShortcutPackageContract.sha256(data)
            let pending=PendingShortcutCatalog(catalog:catalog,distributionOrigin:distributionOrigin,sha256:catalogSHA256)
            if ShortcutDistributionApprovalStore.isApproved(distributionOrigin) {
                try acceptCatalog(pending)
            } else {
                pendingCatalog=pending
                selected=nil
                openOutcome=nil
            }
        } catch {
            model.error = error.localizedDescription
        }
    }

    private func approvePendingCatalog() {
        guard let pendingCatalog else { return }
        do {
            try ShortcutDistributionApprovalStore.approve(pendingCatalog.distributionOrigin)
            try acceptCatalog(pendingCatalog)
            model.progress="Approved exact Shortcut origin \(pendingCatalog.distributionOrigin) and imported catalog \(pendingCatalog.sha256.prefix(12))."
        } catch {model.error=error.localizedDescription}
        self.pendingCatalog=nil
    }

    private func acceptCatalog(_ pending: PendingShortcutCatalog) throws {
        packages=try pending.catalog.validated(distributionOrigin:pending.distributionOrigin)
        selected=nil
        openOutcome=nil
    }

    private func beginInstall(_ package: ShortcutPackage) {
        guard installGate.begin(package.id) else { return }
        selected = nil
        Task { @MainActor in
            defer { installGate.finish(package.id) }
            do {
                let verified = try await ShortcutPackageInstaller.downloadVerifiedPackage(package)
                openOutcome = .verified(package.name)
                model.progress = "Verified \(package.name). Asking iOS to open the local Shortcut import flow. Installation remains unconfirmed."
                openURL(verified.fileURL) { accepted in
                    Task { @MainActor in
                        openOutcome = accepted ? .accepted(package.name) : .rejected(package.name)
                        if accepted {
                            model.progress = "iOS accepted the request to open \(package.name). Installation remains unconfirmed until you accept it in Shortcuts."
                        } else {
                            model.error = "iOS rejected the request to open the verified local copy of \(package.name). No installation was claimed."
                        }
                    }
                }
            } catch {
                model.error = error.localizedDescription
            }
        }
    }
}

private struct ShortcutPackageRow: View {
    let package: ShortcutPackage
    let isVerifying: Bool
    let installsDisabled: Bool
    let select: () -> Void

    var body: some View {
        Section(package.name) {
            Text(package.url.absoluteString)
                .font(.footnote)
                .textSelection(.enabled)
            Text("SHA-256: \(package.sha256)")
                .font(.caption.monospaced())
                .textSelection(.enabled)
            if !package.requires.isEmpty {
                Text("Install first: \(package.requires.joined(separator: ", "))")
            }
            Button(action: select) {
                if isVerifying {
                    Label("Verifying package", systemImage: "checkmark.shield")
                } else {
                    Text("Add Shortcut")
                }
            }
            .disabled(installsDisabled)
        }
    }
}
