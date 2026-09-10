import SwiftUI
import Combine
import AuthenticationServices
import UniformTypeIdentifiers
import UserNotifications
import SafariServices

@MainActor
final class AppModel: ObservableObject {
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
        if let saved=UserDefaults.standard.data(forKey:"policy"),let parsed=try? JSONDecoder().decode(ResourcePolicy.self,from:saved),let valid=try? parsed.validated(){policy=valid}
        userID=Keychain.get("appleUser") ?? ""
        do {try SandboxStore.shared.restore();refresh()} catch {self.error=error.localizedDescription}
        if !userID.isEmpty {
            ASAuthorizationAppleIDProvider().getCredentialState(forUserID:userID){state,_ in
                Task { @MainActor in if state != .authorized {self.userID="";Keychain.delete("appleUser")} }
            }
        }
    }
    func connect(_ url:URL) {do {try SandboxStore.shared.connect(url);try prepare();refresh()}catch{self.error=error.localizedDescription}}
    func prepare() throws {
        let store=SandboxStore.shared
        let existing=try store.list("config")
        if !existing.contains("config/oracle.md"){try store.write(SandboxPath("config/oracle.md"),content:nativeOraclePolicy,createOnly:true)}
        try store.save(policy,path:"config/policy.json")
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
    func deleteProfile(){Keychain.delete("appleUser");Keychain.delete("openaiKey");Keychain.delete("openaiModel");userID="";SandboxStore.shared.disconnect();UserDefaults.standard.removeObject(forKey:"policy");policy=ResourcePolicy();refresh()}
}

@main
struct LocalSandboxApp: App {
    @StateObject private var model=AppModel()
    var body: some Scene {WindowGroup {RootView().environmentObject(model).preferredColorScheme(.dark).tint(Color(red:0.75,green:0.93,blue:0.52))}}
}
struct RootView: View {
    @EnvironmentObject private var model:AppModel
    var body:some View {
        TabView {
            ControlView().tabItem{Label("Control",systemImage:"square.stack.3d.up")}
            FilesView().tabItem{Label("Sandbox",systemImage:"folder")}
            ActivityView().tabItem{Label("Activity",systemImage:"waveform.path")}
            SettingsView().tabItem{Label("Settings",systemImage:"slider.horizontal.3")}
        }.alert("Local Sandbox",isPresented:Binding(get:{!model.error.isEmpty},set:{if !$0{model.error=""}})){Button("OK"){model.error=""}}message:{Text(model.error)}
    }
}
struct ControlView:View {
    @EnvironmentObject private var model:AppModel
    @State private var goal=""
    @State private var dashboard=false
    @Environment(\.openURL) private var openURL
    var body:some View {
        NavigationStack {ScrollView {VStack(alignment:.leading,spacing:24){
            Text("LOCAL SANDBOX / CONTROL ROOM").font(.caption.monospaced()).foregroundStyle(.secondary)
            Text("Your agents.\nYour rules.").font(.system(size:36,weight:.medium,design:.rounded))
            VStack(alignment:.leading,spacing:16){Label("Oracle",systemImage:"sparkles").font(.title3.weight(.semibold));Text("What should your phone do?").font(.title2);TextField("Change Status: pending to Status: complete in workspace/test.txt",text:$goal,axis:.vertical).lineLimit(3...7).padding().background(.black.opacity(0.3),in:RoundedRectangle(cornerRadius:12))
                if model.policy.provider=="local" {Button{var url=URLComponents();url.scheme="shortcuts";url.host="run-shortcut";url.queryItems=[URLQueryItem(name:"name",value:"Local Sandbox"),URLQueryItem(name:"input",value:"text"),URLQueryItem(name:"text",value:goal)];if let link=url.url{openURL(link)}}label:{Label("Open local runner in Shortcuts",systemImage:"arrow.up.right")}.buttonStyle(.borderedProminent).disabled(goal.isEmpty)}
                else {Button{Task{await model.run(goal)}}label:{Label(model.running ? "Running…":"Run bounded task",systemImage:"arrow.right")}.buttonStyle(.borderedProminent).disabled(model.running || goal.isEmpty || !model.connected)}
                if model.running{Button("Stop run",role:.destructive){AgentRunner.shared.cancel()}}
                Text(model.progress).font(.footnote).foregroundStyle(.secondary)
            }.padding(22).background(Color(red:0.12,green:0.17,blue:0.10),in:RoundedRectangle(cornerRadius:18))
            if let checkpoint=model.checkpoint {VStack(alignment:.leading,spacing:12){Label("Interrupted run",systemImage:"exclamationmark.circle");Text(checkpoint.goal);Text("Phase: \(checkpoint.phase). Inspect affected files. Pending mutations are never replayed automatically.").font(.footnote);Button("I reviewed the checkpoint"){model.acknowledgeCheckpoint()}}.padding().background(.orange.opacity(0.1),in:RoundedRectangle(cornerRadius:14))}
            HStack{Label(model.connected ? model.folderName:"Choose a sandbox folder",systemImage:"folder.badge.gearshape");Spacer();Image(systemName:model.connected ? "checkmark.shield":"lock")}.font(.subheadline)
            VStack(alignment:.leading,spacing:14){Text("Power, with permission.").font(.title3);budget("Battery drop per run",value:$model.policy.batteryBudget,range:1...80);budget("Memory target",value:$model.policy.memoryTarget,range:10...80);Text("Memory measures this app’s footprint. System model services are outside that measurement; iOS owns allocation.").font(.caption).foregroundStyle(.secondary);Button("Save authorization"){model.savePolicy()}.buttonStyle(.bordered)}.padding(20).background(.white.opacity(0.035),in:RoundedRectangle(cornerRadius:16))
            Button{dashboard=true}label:{Label("Open observation dashboard",systemImage:"globe")}.buttonStyle(.bordered)
            Text("One model step → validated tool → readback → receipt.").font(.footnote).foregroundStyle(.secondary)
        }.padding(22)}.navigationTitle("Local Sandbox").navigationBarTitleDisplayMode(.inline).sheet(isPresented:$dashboard){SafariView(url:URL(string:"https://local-sandbox.candy-lyric-5390.chatgpt.site")!)}}
    }
    func budget(_ title:String,value:Binding<Int>,range:ClosedRange<Double>)->some View {VStack{HStack{Text(title);Spacer();Text("\(value.wrappedValue)%").monospacedDigit()};Slider(value:Binding(get:{Double(value.wrappedValue)},set:{value.wrappedValue=Int($0)}),in:range,step:1)}}
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
    @State private var picker=false
    @State private var apiKey=""
    @State private var apiModel=""
    @State private var delete=false
    @State private var authState=""
    var body:some View {
        NavigationStack {Form {
            Section("Apple account") {
                if model.userID.isEmpty{SignInWithAppleButton(.signIn){request in authState=UUID().uuidString;request.state=authState;request.requestedScopes=[]}onCompletion:{result in switch result {case .success(let auth):if let credential=auth.credential as? ASAuthorizationAppleIDCredential,credential.state==authState{do{try Keychain.set(credential.user,for:"appleUser");model.userID=credential.user}catch{model.error=error.localizedDescription}}else{model.error="Apple credential could not be verified."};case .failure(let error):model.error=error.localizedDescription}}.signInWithAppleButtonStyle(.white).frame(height:46)}else{Label("Signed in with Apple",systemImage:"checkmark.seal")}
                Text("Apple identity is local to this app. The web dashboard uses a separate ChatGPT session.").font(.caption).foregroundStyle(.secondary)
            }
            Section("iCloud folder") {Label(model.folderName,systemImage:"folder");Button("Choose LocalSandbox folder"){picker=true};Text("Choose iCloud Drive / Shortcuts / LocalSandbox. iOS grants access only to this folder. Signing in does not grant file access.").font(.caption).foregroundStyle(.secondary)}
            Section("Reasoning provider") {Picker("Provider",selection:$model.policy.provider){Text("Apple Intelligence").tag("apple");Text("OpenAI").tag("openai");Text("Locally AI / LM Link via Shortcuts").tag("local")};TextField("Local adapter Shortcut",text:$model.policy.localShortcut);Toggle("Allow cloud reasoning",isOn:$model.policy.cloudAllowed);Text("Local providers require the named Shortcuts stack. They cannot be invoked through an invented app API.").font(.caption).foregroundStyle(.secondary)}
            Section("OpenAI, your own API project") {SecureField("API key",text:$apiKey).textInputAutocapitalization(.never).autocorrectionDisabled();TextField("Model ID available to your project",text:$apiModel).textInputAutocapitalization(.never).autocorrectionDisabled();Button("Save in Keychain"){do{guard !apiKey.isEmpty,!apiModel.isEmpty else{throw SandboxError.invalid("Enter both a key and a model ID.")};try Keychain.set(apiKey,for:"openaiKey");try Keychain.set(apiModel,for:"openaiModel");apiKey="";model.progress="API configuration saved"}catch{model.error=error.localizedDescription}};Text("API billing is separate. Your key stays in this device’s Keychain and is sent only to api.openai.com.").font(.caption).foregroundStyle(.secondary)}
            Section("Run limits") {Stepper("Battery reserve: \(model.policy.batteryReserve)%",value:$model.policy.batteryReserve,in:5...80);Stepper("Maximum steps: \(model.policy.maxSteps)",value:$model.policy.maxSteps,in:1...24);Stepper("Prompt cap: \(model.policy.contextChars) characters",value:$model.policy.contextChars,in:2000...12000,step:500);Toggle("Completion notifications",isOn:$model.policy.notifications);Button("Enable iOS notifications"){Task{do{let allowed=try await UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound]);if !allowed{model.error="Notifications are disabled in iOS Settings."}}catch{model.error=error.localizedDescription}}};Button("Save authorization"){model.savePolicy()}}
            Section("Setup and privacy") {Link("Visual Shortcuts setup guide",destination:URL(string:"https://local-sandbox.candy-lyric-5390.chatgpt.site/downloads/Local-Sandbox-Setup-Guide.pdf")!);Text("Local files stay in the folder you select. Cloud providers receive compact task context only when authorized. This app does not include analytics or advertising SDKs.").font(.footnote);Button("Delete local profile",role:.destructive){delete=true}}
        }.navigationTitle("Settings").fileImporter(isPresented:$picker,allowedContentTypes:[.folder],allowsMultipleSelection:false){result in do{if let url=try result.get().first{model.connect(url)}}catch{model.error=error.localizedDescription}}.alert("Delete local profile?",isPresented:$delete){Button("Delete profile",role:.destructive){model.deleteProfile()};Button("Cancel",role:.cancel){}}message:{Text("Removes Apple identity, API secrets, settings, and folder access from this app. Your iCloud files remain in Files.")}.onAppear{apiModel=Keychain.get("openaiModel") ?? ""}}
    }
}
struct SafariView:UIViewControllerRepresentable {
    let url:URL
    func makeUIViewController(context:Context)->SFSafariViewController {SFSafariViewController(url:url)}
    func updateUIViewController(_ controller:SFSafariViewController,context:Context){}
}
