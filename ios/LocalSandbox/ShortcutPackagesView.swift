import SwiftUI
import UniformTypeIdentifiers

struct ShortcutPackage: Decodable, Identifiable {
    let id:String; let name:String; let url:URL; let sha256:String; let bytes:Int; let requires:[String]
}
struct ShortcutCatalog: Decodable {
    let version:Int; let release:String; let packages:[ShortcutPackage]
    func validated() throws -> [ShortcutPackage] {
        guard version == 1, packages.count <= 30, Set(packages.map(\.id)).count == packages.count else {throw SandboxError.invalid("Invalid package catalog.")}
        for p in packages {
            guard !p.name.isEmpty,p.name.count<=80,p.url.scheme=="https",p.url.host != nil,p.url.user==nil,p.url.password==nil,p.url.query==nil,p.url.fragment==nil,p.url.path.hasSuffix(".shortcut"),p.bytes>0,p.bytes<=5_000_000,p.sha256.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil else {throw SandboxError.invalid("Invalid HTTPS Shortcut package.")}
        }
        var result:[ShortcutPackage]=[];var active=Set<String>();var visited=Set<String>()
        func visit(_ id:String) throws {
            if visited.contains(id){return}
            guard !active.contains(id),let item=packages.first(where:{$0.id==id}) else {throw SandboxError.invalid("Missing or circular Shortcut dependency.")}
            active.insert(id);for dep in item.requires{try visit(dep)};active.remove(id);visited.insert(id);result.append(item)
        }
        for p in packages {try visit(p.id)}
        return result
    }
}
struct ShortcutPackagesView:View {
    @EnvironmentObject private var model:AppModel
    @Environment(\.openURL) private var openURL
    @State private var importing=false
    @State private var packages:[ShortcutPackage]=[]
    @State private var selected:ShortcutPackage?
    var body:some View {
        List {
            Section {Text("Import the catalog produced by your Mac package publisher. It contains real signed workflow links, ordered by dependency. Apple reviews the package when you add it.");Button("Import package catalog"){importing=true};Link("Open published package installer",destination:URL(string:"https://local-sandbox.ctyy4wd4c2.chatgpt.site/local/install.html")!)}
            if packages.isEmpty {Section {Text("No package catalog loaded. No Shortcut has been installed.").foregroundStyle(.secondary)}}
            ForEach(packages){p in Section(p.name){Text(p.url.host ?? "").font(.footnote);Text("SHA-256: \(p.sha256)").font(.caption.monospaced()).textSelection(.enabled);if !p.requires.isEmpty{Text("Install first: \(p.requires.joined(separator:", "))")};Button("Add Shortcut"){selected=p}}}
            Section {Text("After adding the workflow, complete the provider's harmless text test in Apps & Shortcuts. Opening a link does not prove installation or successful execution.").font(.footnote)}
        }.navigationTitle("Shortcut packages")
        .fileImporter(isPresented:$importing,allowedContentTypes:[.json]){result in
            do {let url=try result.get();let accessed=url.startAccessingSecurityScopedResource();defer{if accessed{url.stopAccessingSecurityScopedResource()}};let size=try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? 0;guard size<=100000 else{throw SandboxError.invalid("Catalog too large.")};let catalog=try JSONDecoder().decode(ShortcutCatalog.self,from:Data(contentsOf:url));packages=try catalog.validated()}catch{model.error=error.localizedDescription}
        }.confirmationDialog("Open signed Shortcut package?",isPresented:Binding(get:{selected != nil},set:{if !$0{selected=nil}}),titleVisibility:.visible){if let p=selected{Button("Open from \(p.url.host ?? "package host")"){openURL(p.url);selected=nil}};Button("Cancel",role:.cancel){selected=nil}}message:{Text("Apple presents the installation and permission controls. The catalog hash is release metadata, not proof of device execution.")}
    }
}
