import SwiftUI
import Combine
import AuthenticationServices
import UniformTypeIdentifiers
import UserNotifications
import SafariServices

@MainActor
final class AppModel: ObservableObject {
    @Published var unlocked = false
    @Published var policy = ResourcePolicy()
    @Published var connected = false
    @Published var folderName = "No folder selected"
    @Published var userID = ""
    @Published var running = false
    @Published var progress = "Ready to plan"
    @Published var error = ""
    @Published var files: [String] = []
    @Published var receipts: [RunReceipt] = []
    @Published var checkpoint: RunCheckpoint?
    init() {
        if let saved=UserDefaults.standard.data(forKey:"policy"),var parsed=try? JSONDecoder().decode(ResourcePolicy.self,from:saved){if parsed.provider=="openai"{parsed.provider="chatgpt"};if let valid=try? parsed.validated(){policy=valid}}
        Keychain.delete("openaiKey");Keychain.delete("openaiModel")
        userID=Keychain.get("appleUser") ?? ""
        do {try SandboxStore.shared.restore();refresh()} catch {self.error=error.localizedDescription}
        if !userID.isEmpty {
            ASAuthorizationAppleIDProvider().getCredentialState(forUserID:userID){state,error in
                Task { @MainActor in if error == nil && (state == .revoked || state == .notFound) {self.deleteProfile()} }
            }
        }
    }
    func unlock() async {do {try await LocalAccess.authenticate();unlocked=true;try SandboxStore.shared.restore();try prepare();refresh()}catch{self.error=error.localizedDescription}}
    func connect(_ url:URL) {do {try SandboxStore.shared.connect(url);try prepare();refresh()}catch{self.error=error.localizedDescription}}
    func prepare() throws {
        let store=SandboxStore.shared
        let existing=try store.list("config")
        if !existing.contains("config/oracle.md"){try store.write(SandboxPath("config/oracle.md"),content:nativeOraclePolicy,createOnly:true)}
        if existing.contains("config/policy.json"){var restored=try store.load(ResourcePolicy.self,path:"config/policy.json");if restored.provider=="openai"{restored.provider="chatgpt"};policy=try restored.validated();UserDefaults.standard.set(try JSONEncoder().encode(policy),forKey:"policy")}else{try store.save(policy,path:"config/policy.json");UserDefaults.standard.set(try JSONEncoder().encode(policy),forKey:"policy")}
        if !(try store.list("workspace")).contains("workspace/test.txt"){try store.write(SandboxPath("workspace/test.txt"),content:"Status: pending",createOnly:true)}
    }
    func refresh() {
        connected=SandboxStore.shared.connected;folderName=SandboxStore.shared.folderName
        guard connected else {files=[];receipts=[];return}
        do {files=try SandboxStore.shared.list("workspace");receipts=try SandboxStore.shared.receipts()}catch{self.error=error.localizedDescription}
        if let value=try? SandboxStore.shared.load(RunCheckpoint.self,path:"state/active.json"),["planning","executing","ready"].contains(value.phase){checkpoint=value}else{checkpoint=nil}
    }
    func savePolicy() {do {let valid=try policy.validated();UserDefaults.standard.set(try JSONEncoder().encode(valid),forKey:"policy");if connected{try SandboxStore.shared.save(valid,path:"config/policy.json")};progress="Authorization saved"}catch{self.error=error.localizedDescription}}
    func run(_ goal:String) async {
        guard checkpoint == nil else {error="Inspect the interrupted run before starting another task.";return}
        running=true;defer{running=false;refresh()}
        do {let result=try await AgentRunner.shared.run(goal:goal,policy:policy){self.progress=$0};progress="\(result.status.rawValue): \(result.summary)"}catch{self.error=error.localizedDescription}
    }
    func acknowledgeCheckpoint() {
        guard let checkpoint else{return}
        do {try SandboxStore.shared.save(checkpoint,path:"output/reviewed-\(checkpoint.runID).json");try SandboxStore.shared.save(RunCheckpoint(runID:checkpoint.runID,goal:checkpoint.goal,nextStep:checkpoint.nextStep,capsule:"User reviewed the interrupted run. No action replayed.",lastResult:checkpoint.lastResult,phase:"blocked"),path:"state/active.json");self.checkpoint=nil}catch{self.error=error.localizedDescription}
    }
    func deleteProfile(){Keychain.delete("appleUser");Keychain.delete("openaiKey");Keychain.delete("openaiModel");Keychain.delete("githubToken");for provider in AppProvider.allCases{UserDefaults.standard.removeObject(forKey:"adapter.\(provider.rawValue)")};UserDefaults.standard.removeObject(forKey:"githubTarget");userID="";SandboxStore.shared.disconnect();UserDefaults.standard.removeObject(forKey:"policy");policy=ResourcePolicy();refresh()}
}

@main
struct LocalSandboxApp: App {
    @StateObject private var model=AppModel()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {WindowGroup {RootView().environmentObject(model).tint(.primary).onChange(of:phase){_,value in if value == .active{model.refresh()} else if value == .background {model.unlocked=false}}}}
}
struct RootView: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @EnvironmentObject private var model:AppModel
    var body:some View {
        Group {if model.userID.isEmpty {WelcomeView()} else if !model.unlocked {VStack(spacing:24){Image("Brand").resizable().scaledToFit().frame(width:100,height:100);Text("Your workspace is locked").font(.title2);Button("Unlock with Face ID or passcode"){Task{await model.unlock()}}.buttonStyle(.borderedProminent)}} else {
            TabView {
                ControlView().tabItem{Label("Inbox",systemImage:"tray")}
                FilesView().tabItem{Label("Sandbox",systemImage:"folder")}
                ActivityView().tabItem{Label("Activity",systemImage:"waveform.path")}
                SettingsView().tabItem{Label("Settings",systemImage:"slider.horizontal.3")}
            }.transition(.opacity)
        }}.animation(reduceMotion ? nil:.easeInOut(duration:0.4),value:model.userID.isEmpty).alert("Local Sandbox",isPresented:Binding(get:{!model.error.isEmpty},set:{if !$0{model.error=""}})){Button("OK"){model.error=""}}message:{Text(model.error)}
    }
}
struct AppleLoginButton:View {
    @EnvironmentObject private var model:AppModel
    @Environment(\.colorScheme) private var scheme
    @State private var state=""
    var body:some View {SignInWithAppleButton(.signIn){request in state=UUID().uuidString;request.state=state;request.requestedScopes=[]}onCompletion:{result in switch result {case .success(let auth):if let credential=auth.credential as? ASAuthorizationAppleIDCredential,credential.state==state{do{if let previous=Keychain.get("appleUser"),previous != credential.user{model.deleteProfile()};try Keychain.set(credential.user,for:"appleUser");model.userID=credential.user;model.unlocked=true;try SandboxStore.shared.restore();try model.prepare();model.refresh()}catch{model.error=error.localizedDescription}}else{model.error="Apple credential could not be verified."};case .failure(let error):model.error=error.localizedDescription}}.signInWithAppleButtonStyle(scheme == .dark ? .white:.black).frame(height:50).clipShape(Capsule())}
}
struct WelcomeView:View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var glow=false
    var body:some View {VStack(spacing:23){Spacer();Image("Brand").resizable().scaledToFit().frame(width:145,height:145).shadow(color:.gray.opacity(glow ? 0.35:0.08),radius:glow ? 45:16).scaleEffect(glow ? 1.03:1);Text("Local Sandbox").font(.system(size:37,weight:.semibold));Text("Your apps. One workspace.").font(.title3).foregroundStyle(.secondary);Spacer();AppleLoginButton().frame(maxWidth:340);Text("Sign-in prepares a private workspace on this iPhone. Next, connect your app Shortcuts. App subscriptions stay in their own apps.").font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth:330);Spacer().frame(height:30)}.padding(30).frame(maxWidth:.infinity).background(Color(uiColor:.systemBackground)).onAppear{if !reduceMotion{withAnimation(.easeInOut(duration:2.8).repeatForever(autoreverses:true)){glow=true}}}}
}
struct ControlView:View {
    @EnvironmentObject private var model:AppModel
    @State private var goal=""
    var body:some View {NavigationStack {ScrollView {VStack(alignment:.leading,spacing:28){
        LazyVGrid(columns:[GridItem(.flexible()),GridItem(.flexible())],spacing:14){
            NavigationLink{ProvidersView()}label:{inboxCard("All Agents",count:AppProvider.allCases.count,icon:"paperplane",color:.orange)}
            NavigationLink{SetupView()}label:{inboxCard("Needs Attention",count:model.connected ? 1:2,icon:"bell.badge",color:.orange)}
            NavigationLink{ActivityView()}label:{inboxCard("Working",count:model.running ? 1:0,icon:"circle.dotted",color:.blue)}
            NavigationLink{ActivityView()}label:{inboxCard("In Review",count:model.receipts.count,icon:"checkmark.circle",color:.purple)}
        }.buttonStyle(.plain)
        Text("Workspaces").font(.title3).foregroundStyle(.secondary)
        VStack(spacing:0){NavigationLink{FilesView()}label:{workspaceRow(model.connected ? model.folderName:"Connect iCloud folder",icon:"folder",count:model.files.count)};Divider().padding(.leading,45);NavigationLink{GitHubSettingsView()}label:{workspaceRow("GitHub worktrees",icon:"arrow.triangle.branch",count:nil)};Divider().padding(.leading,45);NavigationLink{SettingsView()}label:{workspaceRow("Add workspace",icon:"folder.badge.plus",count:nil)}}.buttonStyle(.plain)
        if let session=ShortcutCoordinator.shared.current(),["awaiting_response","applying"].contains(session.phase){NavigationLink{OracleView()}label:{Label("Continue app handoff · step \(session.step)",systemImage:"arrow.uturn.backward").padding().frame(maxWidth:.infinity,alignment:.leading).background(.thinMaterial,in:RoundedRectangle(cornerRadius:20))}}
        if let checkpoint=model.checkpoint {VStack(alignment:.leading,spacing:12){Label("Interrupted native run",systemImage:"exclamationmark.circle");Text(checkpoint.goal);Text(checkpoint.lastResult).font(.footnote);Button("I reviewed affected files"){model.acknowledgeCheckpoint()}}.padding().background(.thinMaterial,in:RoundedRectangle(cornerRadius:22))}
    }.padding(22)}.navigationTitle("Inbox").toolbar{ToolbarItem(placement:.topBarLeading){NavigationLink{SettingsView()}label:{Image("Brand").resizable().scaledToFit().frame(width:38,height:38).clipShape(Circle())}};ToolbarItem(placement:.topBarTrailing){NavigationLink{FilesView()}label:{Image(systemName:"magnifyingglass")}};ToolbarItem(placement:.topBarTrailing){NavigationLink{SetupView()}label:{Image(systemName:"folder.badge.plus")}}}.safeAreaInset(edge:.bottom){NavigationLink{OracleView()}label:{HStack{Image(systemName:"plus.circle.fill");Text("Plan, ask, build…");Spacer();Image(systemName:"arrow.up")}.font(.title3).foregroundStyle(.secondary).padding(18).glassEffect(.regular,in:Capsule()).padding(.horizontal,18).padding(.bottom,10)}}}}
    func inboxCard(_ title:String,count:Int,icon:String,color:Color)->some View {VStack(alignment:.leading,spacing:25){Image(systemName:icon).foregroundStyle(color).font(.title2);HStack(spacing:7){Text(title);Text("\(count)").foregroundStyle(.secondary)}}.font(.system(size:18)).frame(maxWidth:.infinity,minHeight:118,alignment:.bottomLeading).padding(19).background(Color(uiColor:.secondarySystemGroupedBackground),in:RoundedRectangle(cornerRadius:25)).overlay(RoundedRectangle(cornerRadius:25).stroke(.primary.opacity(0.06)))}
    func workspaceRow(_ title:String,icon:String,count:Int?)->some View {HStack(spacing:18){Image(systemName:icon).foregroundStyle(.secondary);Text(title);Spacer();if let count{Text("\(count)").foregroundStyle(.secondary)};Image(systemName:"chevron.right").foregroundStyle(.tertiary)}.font(.title3).padding(.vertical,20)}
}
struct OracleView:View {
    @EnvironmentObject private var model:AppModel
    @Environment(\.openURL) private var openURL
    @State private var goal="";@State private var response="";@State private var prompt="";@State private var applying=false
    var body:some View {ScrollView{VStack(alignment:.leading,spacing:22){Text("What should your phone do?").font(.title2);TextField("A small, verifiable task",text:$goal,axis:.vertical).lineLimit(3...6).padding().background(.thinMaterial,in:RoundedRectangle(cornerRadius:20))
        if model.policy.provider=="apple" {Button(model.running ? "Running…":"Run with Apple Intelligence"){Task{await model.run(goal)}}.disabled(model.running || goal.isEmpty);if model.running{Button("Stop",role:.destructive){AgentRunner.shared.cancel()}}}
        else {Button("Begin app handoff"){do{prompt=try ShortcutCoordinator.shared.begin(goal:goal,policy:model.policy);launch()}catch{model.error=error.localizedDescription}}.buttonStyle(.borderedProminent).disabled(goal.isEmpty || !model.connected)}
        if let session=ShortcutCoordinator.shared.current(),["awaiting_response","applying"].contains(session.phase){Text("Step \(session.step) · \(session.phase.replacingOccurrences(of:"_",with:" "))").font(.footnote).foregroundStyle(.secondary);Button("Resume in app Shortcut"){prompt=ShortcutCoordinator.shared.prompt(session);launch()}.disabled(session.phase != "awaiting_response");Text("Return the app’s JSON response").font(.headline);TextEditor(text:$response).frame(minHeight:170).font(.system(.body,design:.monospaced)).padding(12).background(.thinMaterial,in:RoundedRectangle(cornerRadius:18));Text("Review the proposed tool and arguments before applying. File writes require the exact read hash and produce a readback receipt.").font(.footnote).foregroundStyle(.secondary);Button("Apply reviewed response"){applying=true;Task{defer{applying=false;model.refresh()};do{prompt=try await ShortcutCoordinator.shared.accept(response);response="";model.progress="App response processed"}catch{model.error=error.localizedDescription}}}.disabled(applying || response.isEmpty);Button("Stop handoff",role:.destructive){Task{do{try await ShortcutCoordinator.shared.stop();model.refresh()}catch{model.error=error.localizedDescription}}}}
        if !prompt.isEmpty{ShareLink("Share current prompt",item:prompt)};Text(model.progress).font(.footnote).foregroundStyle(.secondary)
    }.padding(22)}.navigationTitle("Oracle").onAppear{if let current=ShortcutCoordinator.shared.current(){goal=current.goal;prompt=ShortcutCoordinator.shared.prompt(current)}}}
    private func launch(){let provider=AppProvider(rawValue:model.policy.provider) ?? .local;let adapter=AdapterSettings.get(provider);guard adapter.tested else {model.error="Complete the device round-trip in Settings before running this Shortcut.";return};if let url=AdapterSettings.runURL(name:adapter.name,input:prompt){openURL(url){ok in if !ok{model.error="Shortcuts could not open. Install or configure the named shortcut first."}}}}
}
struct FilesView:View {
    @EnvironmentObject private var model:AppModel
    @State private var selected:String?
    @State private var content=""
    @State private var expectedHash=""
    @State private var newName=""
    @State private var create=false
    var body:some View {
        NavigationStack {List {Section("Approved workspace"){ForEach(model.files,id:\.self){file in Button{do{content=try SandboxStore.shared.read(SandboxPath(file));expectedHash=SandboxStore.hash(content);selected=file}catch{model.error=error.localizedDescription}}label:{Label(file,systemImage:"doc.text")}};if !model.connected{Text("Select an iCloud Drive folder in Settings.").foregroundStyle(.secondary)}}.navigationTitle("Sandbox").toolbar{Button{create=true}label:{Image(systemName:"plus")}.disabled(!model.connected)}.refreshable{model.refresh()}.sheet(isPresented:Binding(get:{selected != nil},set:{if !$0{selected=nil}})){NavigationStack{TextEditor(text:$content).font(.system(.body,design:.monospaced)).padding().navigationTitle(selected ?? "File").navigationBarTitleDisplayMode(.inline).toolbar{ToolbarItem(placement:.cancellationAction){Button("Cancel"){selected=nil}};ToolbarItem(placement:.confirmationAction){Button("Save"){do{if let selected{try SandboxStore.shared.write(SandboxPath(selected),content:content,expectedSHA256:expectedHash)};selected=nil;model.refresh()}catch{model.error=error.localizedDescription}}}}}.alert("New file",isPresented:$create){TextField("notes.md",text:$newName);Button("Create"){do{try SandboxStore.shared.write(SandboxPath("workspace/\(newName)"),content:"",createOnly:true);model.refresh();newName=""}catch{model.error=error.localizedDescription}};Button("Cancel",role:.cancel){}}message:{Text("Creates a text file inside workspace. Existing files are preserved.")}}
    }
}
struct ActivityView:View {
    @EnvironmentObject private var model:AppModel
    var body:some View {NavigationStack{List{if model.receipts.isEmpty{ContentUnavailableView("No receipts yet",systemImage:"waveform.path",description:Text("Run a bounded task to create its execution record."))};ForEach(model.receipts){receipt in NavigationLink{ScrollView{VStack(alignment:.leading,spacing:16){Text(receipt.goal).font(.title2);Text(receipt.summary);Text("\(receipt.status.rawValue) · \(receipt.steps) steps · \(receipt.failures) failures").font(.caption.monospaced());ForEach(Array(receipt.trace.enumerated()),id:\.offset){_,entry in VStack(alignment:.leading){Label(entry.tool,systemImage:entry.status=="ok" ? "checkmark.circle":"exclamationmark.circle");Text(entry.detail).font(.footnote).foregroundStyle(.secondary)}};ShareLink("Export JSON receipt",item:receiptJSON(receipt))}.padding()}}label:{VStack(alignment:.leading,spacing:7){Text(receipt.goal).lineLimit(2);Text(receipt.status.rawValue.uppercased()).font(.caption.monospaced()).foregroundStyle(receipt.status == .verified ? .green:.orange)}}}}.navigationTitle("Activity").refreshable{model.refresh()}}}
    func receiptJSON(_ receipt:RunReceipt)->String {(try? String(decoding:JSONEncoder.sorted.encode(receipt),as:UTF8.self)) ?? "{}"}
}
struct SettingsView:View {
    @EnvironmentObject private var model:AppModel
    @State private var picker=false;@State private var delete=false
    var body:some View {NavigationStack{Form{
        Section("Apple account"){Label(model.userID.isEmpty ? "Sign in required":"Signed in with Apple",systemImage:"person.crop.circle.badge.checkmark");if model.userID.isEmpty{AppleLoginButton()}}
        Section("Local workspace · optional iCloud"){Label(model.folderName,systemImage:"folder");Button("Use private on-device workspace"){do{try SandboxStore.shared.useLocal();try model.prepare();model.refresh()}catch{model.error=error.localizedDescription}};Button("Choose LocalSandbox folder"){picker=true};Text("On your next iPhone, sign in again and select this same iCloud folder. iOS rechecks file permission and provider availability.").font(.footnote).foregroundStyle(.secondary)}
        Section{NavigationLink{ProvidersView()}label:{Label("Apps & Shortcuts",systemImage:"square.stack.3d.up")};NavigationLink{GitHubSettingsView()}label:{Label("GitHub authentication & sync",systemImage:"arrow.triangle.branch")};NavigationLink{SetupView()}label:{Label("Shortcut setup",systemImage:"link")}}
        Section("Resource authorization"){budget("Battery drop",value:$model.policy.batteryBudget,range:1...80);budget("Memory target",value:$model.policy.memoryTarget,range:10...80);Stepper("Battery reserve: \(model.policy.batteryReserve)%",value:$model.policy.batteryReserve,in:5...80);Stepper("Maximum steps: \(model.policy.maxSteps)",value:$model.policy.maxSteps,in:1...24);Stepper("Prompt cap: \(model.policy.contextChars) characters",value:$model.policy.contextChars,in:2000...12000,step:500);Toggle("Allow cloud app handoffs",isOn:$model.policy.cloudAllowed);Toggle("Completion notifications",isOn:$model.policy.notifications);Button("Enable notifications"){Task{do{_ = try await UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound])}catch{model.error=error.localizedDescription}}};Button("Save authorization"){model.savePolicy()};Text("Memory covers this app’s process, not another provider app. iOS owns resource allocation and background execution.").font(.footnote).foregroundStyle(.secondary)}
        Section("Device capabilities"){ShareLink("Export device report",item:AdapterSettings.deviceReport());Text("Import this JSON in the dashboard to update its device capability display. Native checks always read current availability.").font(.footnote).foregroundStyle(.secondary)}
        Section("Siri & local privacy"){Text("Say: Open Local Sandbox, or Prepare my workspace in Local Sandbox. App Intents add Oracle actions to Siri; this build does not replace the system assistant.");Button("Lock now"){model.unlocked=false};Text("Face ID or the device passcode unlocks this app. App Intent file operations request device authentication. Apple identity and GitHub credentials stay in this device’s Keychain.").font(.footnote).foregroundStyle(.secondary)}
        Section("Updates"){Text("Local Sandbox 0.3.0");Link("Current dashboard & downloads",destination:URL(string:"https://local-sandbox.ctyy4wd4c2.chatgpt.site")!);Text("Native updates use signed Xcode, TestFlight, or App Store builds. Workspace data is preserved. Shortcuts use reviewed, versioned shared links; no executable code is downloaded and run as an app patch.").font(.footnote).foregroundStyle(.secondary)}
        Section{Button("Delete local profile",role:.destructive){delete=true}}
    }.navigationTitle("Settings").fileImporter(isPresented:$picker,allowedContentTypes:[.folder],allowsMultipleSelection:false){result in do{if let url=try result.get().first{model.connect(url)}}catch{model.error=error.localizedDescription}}.alert("Delete local profile?",isPresented:$delete){Button("Delete",role:.destructive){model.deleteProfile()};Button("Cancel",role:.cancel){}}message:{Text("Removes local identity, GitHub credentials, preferences, and folder access. Your iCloud files remain.")}}}
    func budget(_ title:String,value:Binding<Int>,range:ClosedRange<Double>)->some View {VStack{HStack{Text(title);Spacer();Text("\(value.wrappedValue)%").monospacedDigit()};Slider(value:Binding(get:{Double(value.wrappedValue)},set:{value.wrappedValue=Int($0)}),in:range,step:1)}}
}
struct ProvidersView:View {
    @EnvironmentObject private var model:AppModel
    @State private var selected:AppProvider?
    var body:some View {List{ForEach(AppProvider.allCases){provider in Button{if let reason=provider.unavailableReason{model.error=reason}else{selected=provider}}label:{HStack(spacing:15){Image(systemName:provider == .apple ? "sparkles":"square.stack.3d.up");VStack(alignment:.leading,spacing:4){Text(provider.title).foregroundStyle(.primary);Text(provider.unavailableReason == nil ? (AdapterSettings.get(provider).tested ? "Shortcut tested":"Configure app Shortcut"):"Not available on this iPhone").font(.footnote).foregroundStyle(.secondary)};Spacer();if model.policy.provider==provider.rawValue{Image(systemName:"checkmark")};Image(systemName:"chevron.right").foregroundStyle(.tertiary)}}};Section{Text("App sign-in and subscription limits remain in each provider’s app. Opening an app is not proof that its Shortcuts action is installed. Test the text round-trip below.").font(.footnote).foregroundStyle(.secondary)}}.navigationTitle("Apps & Shortcuts").sheet(item:$selected){provider in NavigationStack{AdapterView(provider:provider)}}}
}
struct AdapterView:View {
    let provider:AppProvider
    @EnvironmentObject private var model:AppModel
    @Environment(\.openURL) private var openURL
    @Environment(\.dismiss) private var dismiss
    @State private var adapter=ShortcutAdapter(name:"")
    @State private var installed=false
    var body:some View {Form{Section("App account"){Text("Sign in to \(provider.title) in its own app. No model API key is used.")};Section("Shortcut"){TextField("Name",text:$adapter.name);Toggle("Manual return",isOn:Binding(get:{adapter.mode=="manual"},set:{adapter.mode=$0 ? "manual":"action"}));TextField("Shared iCloud install link (optional)",text:$adapter.installURL).textInputAutocapitalization(.never).autocorrectionDisabled();Button(adapter.installURL.isEmpty ? "Open blank editor":"Add shared Shortcut"){do{try AdapterSettings.save(adapter,for:provider);if let url=URL(string:adapter.installURL.isEmpty ? "shortcuts://create-shortcut":adapter.installURL){openURL(url)}}catch{model.error=error.localizedDescription}};Toggle("I saved this Shortcut on this device",isOn:$installed);Text("First save this exact name in Shortcuts. Opening the editor alone does not install anything.").font(.footnote);Button("Test saved Shortcut"){if let url=AdapterSettings.runURL(name:adapter.name,input:"Return only {\"kind\":\"final\",\"summary\":\"Shortcut text round-trip works\"}. Do not edit files."){openURL(url)}}.disabled(!installed);Toggle("I received the test response",isOn:$adapter.tested).disabled(!installed)};Section("Build order"){Text("1. Accept Shortcut Input as text.\n2. Pass it to the text-returning action offered by the installed app.\n3. Stop and Output the result.\n\nIf no action is offered, use Open App and manually return the response. Grokbot and LM Link require selecting your actual installed app action.")};Button("Save and select"){do{try AdapterSettings.save(adapter,for:provider);model.policy.provider=provider.rawValue;model.savePolicy();dismiss()}catch{model.error=error.localizedDescription}}}.navigationTitle(provider.title).navigationBarTitleDisplayMode(.inline).toolbar{Button("Done"){dismiss()}}.onAppear{adapter=AdapterSettings.get(provider)}.onChange(of:adapter.name){_,_ in installed=false;adapter.tested=false}.onChange(of:adapter.mode){_,_ in installed=false;adapter.tested=false}}
}
struct SetupView:View {
    @EnvironmentObject private var model:AppModel
    var body:some View {List{Section("1 · Prepare"){NavigationLink{SettingsView()}label:{Label("Sign in & prepare local files",systemImage:"person.crop.circle")};Button("Prepare workspace"){do{try model.prepare();model.refresh()}catch{model.error=error.localizedDescription}}.disabled(!model.connected)};Section("2 · App Shortcuts"){Text("Installing this native app registers Begin Oracle Task, Apply Reviewed Action, Prepare Workspace, and Open Local Sandbox. Find these under Local Sandbox in the Shortcuts app.");NavigationLink{ProvidersView()}label:{Label("Connect provider Shortcuts",systemImage:"link")}};Section("3 · Run a stack"){Text("Begin Oracle Task → selected app text action → Apply Reviewed Action. For each next step, use the returned prompt. Stop when the returned phase is no longer awaiting_response. Start with a read-only test and six steps maximum.");Link("Open blank runner editor",destination:URL(string:"shortcuts://create-shortcut")!)};Section("Visual guide"){Link("Open setup guide",destination:URL(string:"https://local-sandbox.ctyy4wd4c2.chatgpt.site/downloads/Local-Sandbox-Setup-Guide.pdf")!)}}.navigationTitle("Set up Shortcuts")}
}
struct SafariView:UIViewControllerRepresentable {
    let url:URL
    func makeUIViewController(context:Context)->SFSafariViewController {SFSafariViewController(url:url)}
    func updateUIViewController(_ controller:SFSafariViewController,context:Context){}
}
