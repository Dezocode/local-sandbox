import SwiftUI

struct GitHubFineGrainedCredential: Equatable {
    let rawValue: String
    init(_ rawValue: String) throws {
        guard rawValue.range(of: "^github_pat_[A-Za-z0-9_]{20,480}$", options: .regularExpression) != nil else {
            throw SandboxError.invalid("Enter a fine-grained personal access token beginning with github_pat_.")
        }
        self.rawValue = rawValue
    }
}

struct GitHubTarget: Codable, Equatable {
    var repository="";var branch="local-sandbox/phone";var path="notes.md"
    func validated() throws -> Self {
        guard repository.range(of:"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",options:.regularExpression) != nil,
              branch.range(of:"^[A-Za-z0-9][A-Za-z0-9._/-]*$",options:.regularExpression) != nil,
              !branch.contains(".."),!branch.contains("//"),!branch.hasSuffix("/"),!branch.hasSuffix(".lock"),
              path.range(of:"^[A-Za-z0-9][A-Za-z0-9._/-]*$",options:.regularExpression) != nil,
              !path.hasPrefix(".github/"),path.split(separator:"/",omittingEmptySubsequences:false).allSatisfy({!$0.isEmpty && $0 != "." && $0 != ".." && $0 != ".git"}),
              repository.count<=160,branch.count<=160,path.count<=180 else {throw SandboxError.invalid("Check the repository, branch, and file path.")}
        return self
    }
}
struct GitHubSnapshot {let commit:String;let sha:String?;let content:String?}
@MainActor struct GitHubClient {
    private let credential:GitHubFineGrainedCredential
    private let transport:any GitHubHTTPPerforming
    init(token:String,transport:any GitHubHTTPPerforming=GitHubURLSessionTransport()) throws {credential=try GitHubFineGrainedCredential(token);self.transport=transport}
    init(credential:GitHubFineGrainedCredential,transport:any GitHubHTTPPerforming=GitHubURLSessionTransport()){self.credential=credential;self.transport=transport}
    func request(_ path:String,method:String="GET",body:[String:Any]?=nil) async throws -> [String:Any] {
        guard let url=URL(string:"https://api.github.com"+path),url.host=="api.github.com" else {throw SandboxError.invalid("Invalid GitHub URL.")}
        var request=URLRequest(url:url);request.httpMethod=method;request.timeoutInterval=25
        request.setValue("Bearer \(credential.rawValue)",forHTTPHeaderField:"Authorization");request.setValue("application/vnd.github+json",forHTTPHeaderField:"Accept");request.setValue("2022-11-28",forHTTPHeaderField:"X-GitHub-Api-Version");request.setValue("Local-Sandbox",forHTTPHeaderField:"User-Agent")
        if let body{request.setValue("application/json",forHTTPHeaderField:"Content-Type");request.httpBody=try JSONSerialization.data(withJSONObject:body)}
        let result:GitHubHTTPResult
        do {result=try await transport.perform(request,maximumResponseBytes:GitHubTransportLimits.responseBytes)}
        catch is CancellationError {throw CancellationError()}
        catch {throw SandboxError.blocked("GitHub could not complete this operation. Check access or compare again. No force push is used.")}
        guard let object=try JSONSerialization.jsonObject(with:result.data) as? [String:Any] else {throw SandboxError.blocked("GitHub could not complete this operation. Check access or compare again. No force push is used.")}
        return object
    }
    func login() async throws -> String {let user=try await request("/user");guard let name=user["login"] as? String else{throw SandboxError.invalid("GitHub did not return an account.")};return name}
    func createBranch(_ raw:GitHubTarget) async throws {
        let t=try raw.validated();let repo=try await request(root(t))
        guard let defaultBranch=repo["default_branch"] as? String else{throw SandboxError.invalid("Missing repository default branch.")}
        var source=t;source.branch=defaultBranch
        let sha=try await head(source)
        _ = try await request(root(t)+"/git/refs",method:"POST",body:["ref":"refs/heads/"+t.branch,"sha":sha])
    }
    private func root(_ t:GitHubTarget)->String {"/repos/"+t.repository}
    private func branchPath(_ t:GitHubTarget)->String {t.branch.addingPercentEncoding(withAllowedCharacters:.urlPathAllowed) ?? ""}
    private func head(_ t:GitHubTarget) async throws -> String {
        let ref=try await request(root(t)+"/git/ref/heads/"+branchPath(t));guard let object=ref["object"] as? [String:Any],let sha=object["sha"] as? String else {throw SandboxError.invalid("Invalid GitHub reference.")};return sha
    }
    func inspect(_ raw:GitHubTarget) async throws -> GitHubSnapshot {
        let t=try raw.validated();let commit=try await head(t)
        let tree=try await request(root(t)+"/git/trees/\(commit)?recursive=1")
        guard tree["truncated"] as? Bool == false,let files=tree["tree"] as? [[String:Any]] else {throw SandboxError.blocked("Repository tree exceeds this bounded sync. Use the worktree bridge.")}
        guard let file=files.first(where:{$0["path"] as? String==t.path}) else {return GitHubSnapshot(commit:commit,sha:nil,content:nil)}
        guard file["type"] as? String=="blob",file["mode"] as? String != "120000",let sha=file["sha"] as? String,(file["size"] as? Int ?? 64001)<=64000 else {throw SandboxError.blocked("Only regular text files up to 64 KB can be synced.")}
        let blob=try await request(root(t)+"/git/blobs/"+sha)
        guard let encoded=blob["content"] as? String,let bytes=Data(base64Encoded:encoded,options:.ignoreUnknownCharacters),bytes.count<=64000,let text=String(data:bytes,encoding:.utf8),!text.contains("\0") else {throw SandboxError.invalid("File is not supported UTF-8 text.")}
        return GitHubSnapshot(commit:commit,sha:sha,content:text)
    }
    func push(_ raw:GitHubTarget,expected:String,content:String) async throws -> String {
        let t=try raw.validated();guard content.utf8.count<=64000 else{throw SandboxError.invalid("File exceeds 64 KB.")}
        guard try await head(t)==expected else {throw SandboxError.conflict("Branch changed. Compare again before publishing.")}
        let previous=try await request(root(t)+"/git/commits/"+expected)
        guard let oldTree=previous["tree"] as? [String:Any],let baseTree=oldTree["sha"] as? String else{throw SandboxError.invalid("Missing base tree.")}
        let blob=try await request(root(t)+"/git/blobs",method:"POST",body:["content":content,"encoding":"utf-8"])
        guard let blobSHA=blob["sha"] as? String else{throw SandboxError.invalid("Missing blob.")}
        let tree=try await request(root(t)+"/git/trees",method:"POST",body:["base_tree":baseTree,"tree":[["path":t.path,"mode":"100644","type":"blob","sha":blobSHA]]])
        guard let treeSHA=tree["sha"] as? String else{throw SandboxError.invalid("Missing tree.")}
        let commit=try await request(root(t)+"/git/commits",method:"POST",body:["message":"Local Sandbox: update \(t.path)","tree":treeSHA,"parents":[expected]])
        guard let commitSHA=commit["sha"] as? String else{throw SandboxError.invalid("Missing commit.")}
        let updated=try await request(root(t)+"/git/refs/heads/"+branchPath(t),method:"PATCH",body:["sha":commitSHA,"force":false])
        guard let object=updated["object"] as? [String:Any],object["sha"] as? String==commitSHA else{throw SandboxError.blocked("Compare again to confirm the remote result.")}
        return commitSHA
    }
}
struct GitHubSettingsView:View {
    @EnvironmentObject private var model:AppModel
    @State private var token="";@State private var login="";@State private var target=GitHubTarget()
    @State private var localPath="workspace/test.txt";@State private var snapshot:GitHubSnapshot?;@State private var compared:GitHubTarget?
    @State private var localContent="";@State private var localHash="";@State private var busy=false
    var body:some View {
        Form {
            Section("GitHub account") {
                if login.isEmpty {SecureField("Fine-grained token",text:$token).textInputAutocapitalization(.never).autocorrectionDisabled();Button("Connect GitHub"){perform{let credential=try GitHubFineGrainedCredential(token);let name=try await GitHubClient(credential:credential).login();try Keychain.set(credential.rawValue,for:"githubToken");login=name;token=""}};Link("Create 30-day repository-scoped token",destination:URL(string:"https://github.com/settings/personal-access-tokens/new?name=Local%20Sandbox&description=Repository-scoped%20file%20sync&expires_in=30&contents=write")!)}
                else {Label(login,systemImage:"person.crop.circle.badge.checkmark");Button("Disconnect",role:.destructive){perform{try GitHubCredentialDisconnect(deleteChecked:{try Keychain.deleteChecked("githubToken")},readChecked:{try Keychain.getChecked("githubToken")}).perform();login="";snapshot=nil}}}
                Text("Select only the repository you will sync. Contents write includes read access. This token stays in this device’s Keychain. Model subscriptions stay in their own apps.").font(.footnote).foregroundStyle(.secondary)
            }
            Section("Worktree target") {TextField("owner/repository",text:$target.repository);TextField("Existing branch",text:$target.branch);TextField("Repository file path",text:$target.path);TextField("Local sandbox path",text:$localPath);Button("Save target"){do{let value=try target.validated();UserDefaults.standard.set(try JSONEncoder().encode(value),forKey:"githubTarget")}catch{model.error=error.localizedDescription}}}.textInputAutocapitalization(.never).autocorrectionDisabled()
            Section("Compare before publishing") {
                Button("Create branch from repository default"){perform{guard let key=Keychain.get("githubToken") else{throw SandboxError.blocked("Connect GitHub first.")};try await GitHubClient(token:key).createBranch(target);snapshot=nil;model.progress="Branch created. Existing branches are never overwritten."}}
                Button("Compare with GitHub"){perform{guard let key=Keychain.get("githubToken") else{throw SandboxError.blocked("Connect GitHub first.")};localContent=try SandboxStore.shared.read(SandboxPath(localPath));localHash=SandboxStore.hash(localContent);snapshot=try await GitHubClient(token:key).inspect(target);compared=target}}
                if let snapshot,compared==target {Text("Base: \(snapshot.commit.prefix(10))").font(.caption.monospaced());DisclosureGroup("GitHub version"){Text(snapshot.content ?? "New file").font(.system(.footnote,design:.monospaced)).textSelection(.enabled)};DisclosureGroup("Sandbox version"){Text(localContent).font(.system(.footnote,design:.monospaced)).textSelection(.enabled)}
                    Button("Commit sandbox → GitHub"){perform{guard let key=Keychain.get("githubToken") else{throw SandboxError.blocked("Connect GitHub first.")};guard SandboxStore.hash(try SandboxStore.shared.read(SandboxPath(localPath)))==localHash else{throw SandboxError.conflict("Local file changed. Compare again.")};let commit=try await GitHubClient(token:key).push(target,expected:snapshot.commit,content:localContent);self.snapshot=nil;model.progress="GitHub commit \(commit.prefix(10)) confirmed."}}.disabled(snapshot.content==localContent)
                    if let content=snapshot.content {Button("Import GitHub version"){perform{try SandboxStore.shared.write(SandboxPath(localPath),content:content,expectedSHA256:localHash);model.refresh();self.snapshot=nil}}}
                }
                Text("Sync commits to the worktree’s branch. Pull that branch on the computer hosting the Git worktree. Concurrent branch changes block publishing.").font(.footnote).foregroundStyle(.secondary)
            }
        }.navigationTitle("GitHub worktrees").onChange(of:localPath){_,_ in snapshot=nil}.disabled(busy).task{if let saved=UserDefaults.standard.data(forKey:"githubTarget"),let value=try? JSONDecoder().decode(GitHubTarget.self,from:saved){target=value};if let key=Keychain.get("githubToken"){do{login=try await GitHubClient(token:key).login()}catch{model.error=error.localizedDescription}}}
    }
    private func perform(_ work:@escaping @MainActor () async throws -> Void){guard !busy else{return};busy=true;Task{@MainActor in defer{busy=false};do{try await work()}catch{model.error=error.localizedDescription}}}
}
