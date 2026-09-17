from argparse import ArgumentParser
from importlib.resources import files as resource_files
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from xml.sax.saxutils import escape
import json, subprocess

ROOT=Path(__file__).resolve().parent.parent
parser=ArgumentParser(description='Generate the Local Sandbox setup guide.')
parser.add_argument('--output',type=Path,default=ROOT/'public/downloads/Local-Sandbox-Setup-Guide.pdf')
options=parser.parse_args()
payload=subprocess.check_output(['node','--experimental-strip-types','--input-type=module','-e',"import {shortcuts,aspects} from './lib/catalog.ts'; process.stdout.write(JSON.stringify({shortcuts,aspects}));"],cwd=ROOT,text=True)
data=json.loads(payload)
font_root=resource_files('reportlab').joinpath('fonts')
font=str(font_root.joinpath('Vera.ttf'))
bold=str(font_root.joinpath('VeraBd.ttf'))
pdfmetrics.registerFont(TTFont('Guide',font));pdfmetrics.registerFont(TTFont('GuideBold',bold))
OUT=options.output.absolute();OUT.parent.mkdir(parents=True,exist_ok=True)
c=canvas.Canvas(str(OUT),pagesize=(612,792),invariant=1,pageCompression=1,pdfVersion=(1,4));c.setTitle('Local Sandbox - iOS setup and release guide');c.setAuthor('Local Sandbox');c.setCreator('Local Sandbox guide generator')
INK=HexColor('#222226');MUTED=HexColor('#73737d');LINE=HexColor('#ddddE5');FILL=HexColor('#f5f5f8');ACCENT=HexColor('#9999aa')
body=ParagraphStyle('body',fontName='Guide',fontSize=9.4,leading=13,textColor=INK)
compact_body=ParagraphStyle('compact-body',parent=body,leading=11.5)
small=ParagraphStyle('small',fontName='Guide',fontSize=8.2,leading=12,textColor=MUTED)
action=ParagraphStyle('action',fontName='GuideBold',fontSize=10.4,leading=13,textColor=INK)
page=0

def safe_escape(text):
    return escape(text.replace('\u2192','->'))

def para(text,x,y,width,style=body):
    p=Paragraph(safe_escape(text).replace('\n','<br/>'),style);_,h=p.wrap(width,1000);p.drawOn(c,x,y-h);return h

def start(title,sub,pills,sidebar):
    global page
    if page:c.showPage()
    page+=1;c.setFillColor(INK);c.setFont('GuideBold',25 if len(title)<31 else 21);c.drawString(42,746,title)
    para(sub,43,722,526,small)
    if title=='Local Sandbox':c.drawImage(ImageReader(str(ROOT/'public/app-icon.png')),510,735,58,58,mask='auto')
    x=43
    for pill in pills:
        c.setStrokeColor(LINE);c.setLineWidth(.6);c.roundRect(x,666,123,23,11);c.setFillColor(MUTED);c.setFont('Guide',8);c.drawString(x+8,674,pill);x+=132
    c.setStrokeColor(INK);c.line(43,651,569,651);c.setStrokeColor(LINE);c.line(169,633,169,61)
    y=630
    for label,text in sidebar:
        y-=para(label.upper(),44,y,108,ParagraphStyle('side-label',parent=small,fontName='GuideBold',fontSize=8,spaceAfter=4))+9
        y-=para(text,44,y,108,small)+25
    c.setStrokeColor(LINE);c.line(43,44,569,44);c.setFillColor(MUTED);c.setFont('Guide',7);c.drawString(43,29,'LOCAL SANDBOX  /  v0.3 IMPLEMENTATION PREVIEW  /  10 SEP 2026');c.drawRightString(569,29,f'{page:02d}')
    return 629

def block(n,title,text,y,body_style=body):
    p=Paragraph(safe_escape(text),body_style);_,ph=p.wrap(343,1000)
    t=Paragraph(safe_escape(title),action);_,th=t.wrap(343,1000)
    height=ph+th+20
    c.setFillColor(FILL);c.setStrokeColor(LINE);c.roundRect(191,y-height,378,height-6,7,fill=1,stroke=1)
    c.setFillColor(INK);c.setFont('GuideBold',10);c.drawString(178,y-18,str(n))
    t.drawOn(c,207,y-14-th);p.drawOn(c,207,y-18-th-ph)
    return y-height-8

def note(title,text,y):
    p=Paragraph(safe_escape(text),body);_,h=p.wrap(350,1000)
    total=h+37;c.setFillColor(HexColor('#eeeeF4'));c.setStrokeColor(ACCENT);c.roundRect(191,y-total,378,total-4,7,fill=1,stroke=1)
    para(title,205,y-13,350,action);p.drawOn(c,205,y-total+13)
    return y-total-14

side=[('Build order','1. Folder\n2. Dispatcher\n3. Provider\n4. Runner\n5. Receipt\n6. Siri'),('Budgets','6 steps initially\n3 failures maximum\n2 identical failures stop\nOne model at a time'),('Identity','Web: ChatGPT or Apple\nNative: Apple sign-in\nFolder: separate permission')]
y=start('Local Sandbox','A visual setup guide for Oracle-guided iOS tools, bounded local reasoning, and verifiable execution.',['Oracle guidance','Shortcuts executor','Scoped file access','Xcode companion'],side)
y=block(1,'Use one executor and interchangeable reasoning', 'Oracle prepares a compact task. A micro-model or frontier provider proposes one tool call. A deterministic dispatcher validates and executes it. Readback evidence becomes a receipt. Siri is a voice entry and Apple-owned orchestrator.',y)
y=block(2,'Open the private observation dashboard','https://local-sandbox.ctyy4wd4c2.chatgpt.site - authenticate with ChatGPT or configured app-level Apple sign-in. The hosting provider can require its own access gate first. The online sandbox saves text files, policy, progress, and receipts. It is not a live mount of iCloud Drive.',y)
y=block(3,'Choose the iPhone path','For Shortcuts-only use, configure the recipes on the following pages. For native use, open ios/LocalSandbox.xcodeproj in Xcode, choose your developer team, enable Sign in with Apple, build to your device, then sign in to prepare an on-device workspace. Selecting an iCloud folder is optional.',y)
y=note('What is ready, and what is still required','The macOS verifier parses the Swift sources and compiles and runs portable native crypto, account and sync, autosave, and recursive-filesystem contracts. Those checks do not build the full Xcode app, run a simulator, sign the app, or install it on an iPhone. Live Apple configuration, device acceptance, external app Shortcuts actions, real GitHub account sync, and App Review remain release gates.',y)

for idx,recipe in enumerate(data['shortcuts']):
    sidebar=[('Shortcut',recipe['name']),('Role',recipe['role']),('Inputs','Goal, compact state, latest result, saved policy.'),('Output','One action or one typed result. Keep detailed traces on disk.'),('Approval','Install/configure on iPhone. Grant folder and notification access through iOS. Never infer permission from model text.')]
    sub=recipe['description']
    y=start(f"{idx+1:02d} / {recipe['name']}",sub,['Sequential','Compact context','Typed results','User-owned policy'],sidebar)
    for n,(label,text) in enumerate(recipe['steps'],1):
        p=Paragraph(safe_escape(text),body);_,h=p.wrap(343,1000)
        if y-(h+47)<65:y=start(recipe['name']+' / continued',sub,['Same shortcut','Continue in order','Validate','Record evidence'],sidebar)
        y=block(n,label,text,y)
    p=Paragraph(safe_escape(recipe['verify']),body);_,h=p.wrap(350,1000)
    if y-h-40<65:y=start(recipe['name']+' / validation','Check the complete action before continuing.',['Acceptance','Actual device','No silent retries','Receipt'],sidebar)
    note('Acceptance check',recipe['verify'],y)

y=start('Native setup / Xcode','Apple identity, scoped iCloud access, and local execution are separate capabilities.',['iOS 26+ / test 27','SwiftUI','App Intents','Foundation Models'],[('Open','ios/LocalSandbox.xcodeproj'),('Signing','Select an Apple Developer team and a unique bundle ID.'),('Capabilities','Sign in with Apple is declared. The system folder picker grants scoped access.'),('Release gate','Run on a supported iPhone. Simulator battery readings are unavailable, so resource admission blocks there.')])
for n,(title,text) in enumerate([
('Build and sign','Use Xcode with an SDK and device support matching your installed iOS release. The deployment target is iOS 26; the iOS 27.0 device acceptance matrix is explicit. Set DEVELOPMENT_TEAM and a unique PRODUCT_BUNDLE_IDENTIFIER in Signing & Capabilities. The project contains no signing identity or private key.'),
('Sign in with Apple','AuthenticationServices binds the native Apple credential to a nonce. The app can exchange the identity token for a 15-minute, device-only bearer for the same opaque workspace owner. The server supports standalone Apple sign-in and deliberate linking to a ChatGPT-owned workspace. It never merges accounts by email. Production Apple identifiers, keys, domain, and accounts still require live qualification.'),
('Select your sandbox','In native Settings choose iCloud Drive / Shortcuts / LocalSandbox through the system folder picker. The app stores a scoped bookmark and coordinates file reads and writes. A revoked or unavailable folder blocks execution.'),
('Configure a provider','Installing the native app registers its App Shortcuts automatically. Saved and explicit choices never substitute. Best local considers only Apple and Locally. Cold start applies only while neither has comparable evidence: it targets available Apple, otherwise Locally, but blocks until that route is task-qualified. As soon as either has comparable evidence, measured ranking applies and an ineligible selected route blocks. Each run fixes its provider before the first action. Provider authentication stays in each app. Local validation does not prove provider login, active model, response origin, or Shortcut contents.'),
('Test the actual device','Run the model contract test against workspace/test.txt. Verify file contents, app receipt, interruption behavior, permission denial, battery reserve, cancellation, and thermal admission. Inspect the checkpoint after a crash before starting another run.')],1):y=block(n,title,text,y)

y=start('Resource policy / exact meaning','Your sliders authorize stop thresholds and model context choices, not OS-level resource reservations.',['Consent','Measurement','Admission','Cancellation'],[('Default policy','15% battery drop\n20% reserve\n35% app memory target\n6 steps\n3 failures'),('Cloud','Off by default. Selecting an app does not authorize sending it your task.'),('Context','6,000 characters is a proxy, not a guaranteed token count. Measure tokenizer counts in qualified runtimes.')])
for n,(title,text) in enumerate([
('Battery','The runner reads the current battery percentage before and during a model step. It stops below the reserve or at the observed level-drop budget. While charging, that drop is not a measurement of consumed energy.'),
('Memory','The native monitor reads this app process footprint relative to physical memory. It does not observe separate Foundation Models services or another local-provider app. iOS owns allocation and can terminate work earlier.'),
('Thermal and cancellation','Serious or critical thermal pressure requests cancellation. Cooperative cancellation can take time; the runner rechecks limits before a tool runs. The web dashboard never displays fabricated live device telemetry.'),
('Failure recovery','Invalid JSON and patch conflicts return to the model within the failure budget. Edits require a fresh hash and one literal old-text match. Call journals record pending before mutation and refuse uncertain replays. An interrupted run must be reviewed.'),
('Evidence-driven qualification','Run strict-json, read-tool, list-tool, patch-tool, and bounded-context. The first suite needs all five completed probe types, at least four schema-valid responses, at least four passing assertions, and zero integrity faults. The protected ledger stores at most 240 attempts. Scores use only the 20 freshest attempts and require both pass rates to stay at or above 80 percent.')],1):y=block(n,title,text,y)


y=start('App handoffs / native stack','Use a persistent task checkpoint while iOS switches between the apps you already use.',['App accounts','No model API','One action','Return to Oracle'],[('Account','Sign in inside ChatGPT, Grok, Grokbot, Claude, or Locally.'),('Installation','Native App Shortcuts register with the installed app. A personal Shortcut needs review and Apple confirmation.'),('Capability','No undocumented vendor action, scheme, or subscription scope is assumed.')])
for n,(title,text) in enumerate([
('Begin or Run','Add Local Sandbox - Begin Oracle Task or Run Bounded Task. Supply Goal and choose Saved provider, Best local, Apple Intelligence, Locally, ChatGPT, Grok, Grokbot, or Claude. Saved and explicit choices stay pinned. The selected route cannot switch mid-run.'),
('Decode and run provider','Use Get Dictionary from Input. Send only payload to the user-reviewed provider Shortcut and save its output as raw Response. Authentication stays in that provider app. Local Sandbox validates only the returned challenge response; it does not attest the response source, Shortcut contents, or login state. Record live visual device evidence.'),
('Apply Validated Action','Pass the returned raw Response to Local Sandbox - Apply Validated Action. It validates and executes one tool inside the saved resource, cloud, clipboard, path, hash, step, and failure boundaries, then returns another version 1 JSON envelope. An unattended flow does not display a separate content-review screen. Decode that output with Get Dictionary from Input.'),
('Continue or finish','If phase is awaiting_response, read payload and send only that text to the same provider Shortcut. Otherwise retain or import the receipt stored in payload and stop. Set Repeat to the saved maximum steps. The receipt records provider, Siri/App Shortcut origin, action order, and hashes for both handoff directions.'),
('Measure and apply','Run Begin Provider Check, send only payload to the user-reviewed provider action, then use Record Provider Check with the raw response. Every route requires five probe types, at least 80 percent schema and assertion pass rates, zero integrity faults, all tool probes, and enough context. An external Siri route also requires an observed App Intent return for every probe. This records only that returned text reached Record Provider Check. It does not prove unattended execution or provider, account, or model provenance. Live physical-device evidence qualifies unattended operation. Manual return is never eligible for unattended Siri. Oracle ranks schema validation, assertion quality, lower observed App Intent handoff time, then a fixed provider order. The metric is not inference latency.')],1):y=block(n,title,text,y,compact_body)

y=start('GitHub / compare and sync','Connect repository access separately from your model app subscriptions.',['Settings','Compare','Commit','Worktree'],[('Authentication','Fine-grained GitHub token: selected repository, Contents read/write.'),('Credential storage','Web: this tab only. Native: device Keychain. No token enters a model prompt.'),('Conflict rule','Branch movement blocks publishing. No force push.')])
for n,(title,text) in enumerate([
('Connect GitHub','Open Settings - GitHub authentication and sync. Create a fine-grained token on GitHub for the intended repository, then paste it in the password field. The app verifies the account name.'),
('Save a worktree target','Enter owner/repository, an existing branch, and a regular repository file path. The local-sandbox/phone branch is a suggestion; it must exist before inspection.'),
('Compare both files','Select the sandbox file and Compare with GitHub. Inspect the remote commit and both contents. The branch and path are bound to this comparison.'),
('Publish or import','Commit sandbox to GitHub creates a new commit based on the compared branch. Import GitHub version uses the sandbox file revision. Refresh and compare again after any conflict.'),
('Use a real Git worktree','Pull the published branch on its computer, or export a worktree patch before publishing. Run scripts/worktree-sync.py with the patch and --worktree absolute-path. Review the dry run, then add --apply. The branch, base commit, origin, paths, and hashes must match.')],1):y=block(n,title,text,y)

y=start('Updates / move to your next iPhone','Keep configuration and evidence while changing devices or installing a newer build.',['Version 0.3','Preserve data','Detect again','Signed updates'],[('Lower-device path','Select a lower-device test iPhone, such as iPhone 14 Pro, in the release matrix. Keep the native workspace and Siri App Intents through configured Shortcuts; Apple Intelligence is not assumed available.'),('Positive model target','On iPhone 18 Pro Max, qualify the selected Apple provider through Foundation Models online and in Airplane Mode.'),('New device','Sign in with Apple, select the same iCloud folder, test adapters again.'),('Release gate','No real iOS 27 execution or App Store approval is claimed.')])
for n,(title,text) in enumerate([
('Apple capability menu','The native app reads SystemLanguageModel availability at routing time. Best local uses a cold-start target only while neither route has comparable evidence, then ranks comparable, task-qualified Apple and Locally candidates as soon as either has a suite; it never selects cloud. Every runnable route still requires current five-probe evidence. Saved and explicit choices fail instead of substituting another provider.'),
('Transfer the workspace','The protected ledger stores at most 240 attempts. Qualification scores use only the 20 freshest attempts from seven days. One provider-probe pair can record once per UTC day. Device, full OS version and build, app version and build, or adapter changes start a new epoch. Repeat the checks on the new device.'),
('Update the dashboard device report','In native Settings export the device report. Save the JSON and import it in web Settings. The web labels it as an imported snapshot; it does not infer hardware from a browser user agent.'),
('Update the app safely','Install signed Xcode, TestFlight, or App Store updates. There is no runtime download-and-execute app patcher. Site releases preserve the database and compare-and-swap file revisions. public/updates.json identifies this version.'),
('Update Shortcut stacks',"A published iCloud share link opens Apple's Add Shortcut screen. The user must review and confirm the workflow and permissions. Without a published signed link, Open blank editor installs nothing. A link opening is not provider qualification and does not let Local Sandbox inspect the workflow.")],1):y=block(n,title,text,y)

y=start('Release / every aspect is a goal','The complete goal map is also available in the dashboard as an exportable checklist.',['Web','Device','Apple','Distribution'],[('Distribution','No App Store submission is claimed. Apple signing, store metadata, screenshots, privacy labels, support details, and App Review are required.'),('Repository','Source is downloadable. A publication script is included. GitHub publication is reported only after a successful remote push.')])
for n,a in enumerate(data['aspects'],1):
    text=a[1]+' Status: '+a[2]+'.'
    p=Paragraph(safe_escape(text),body);_,h=p.wrap(343,1000)
    if y-h-48<65:y=start('Release goals / continued','Preserve the same execution contract across every provider.',['Track','Test','Approve','Release'],[('Readiness','Passing portable Swift contracts and a full Xcode device build are different evidence levels.'),('Do not skip','Real device checks and Apple account configuration.')])
    y=block(n,a[0],text,y)

y=start('On device / private workspace','A separate local web workspace with an encrypted editor and session notebook.',['Local storage','Password unlock','Offline shell','Export backup'],[('Open','Site / local / index.html. This vault is independent of the online dashboard.'),('Identity','A vault password is not Apple sign-in, a passkey, or Face ID.'),('Device testing','Offline Home Screen behavior has not been tested on an iPhone here.')])
for n,(title,text) in enumerate([
('Create the vault','Open On-device workspace from the dashboard. Choose at least 12 characters. Files and transferred messages are encrypted before browser storage. No file content or password is sent to the dashboard server.'),
('Save to Home Screen','In Safari use Share, Add to Home Screen, and Open as Web App where offered. Open once online to download the shell. The native Xcode app is a separate installation.'),
('Edit and record sessions','Use Code to create and save text files. Oracle session records prompts and returned text you explicitly transfer. It cannot read the private conversation history in your provider apps.'),
('Back up before moving devices','Settings exports an encrypted backup. Restore with the same vault password. Clearing website data or losing the password can lose access. There is no password recovery.'),
('Own the web app','Host public/local on your own HTTPS origin. Export and restore the encrypted backup when changing origins. The local app needs no model API or dashboard backend.')],1):y=block(n,title,text,y)

y=start('Repair / missing Shortcut','A saved name is a dependency, not an installed workflow.',['Create','Save exact name','Test on phone','Then run'],[('Observed failure','The user saw: Could not find Agent Step - Local.'),('Root cause','The old run link targeted a name that had not been installed.'),('One tap','Requires a real shared Shortcut link. No fabricated installer is bundled.')])
for n,(title,text) in enumerate([
('Prepare native files','After Apple sign-in the native source prepares a protected local workspace. Settings can switch to a selected Files or iCloud folder. Existing folders are not copied or deleted by switching.'),
('Find the app actions',"Installing the native app registers nine iOS 26 App Shortcuts, including Begin Provider Check, Record Provider Check, Qualify Apple Intelligence, and Apply Oracle Recommendation. iOS 27 also registers Run Long Apple Task. Every protected action requires local authentication on the executing iPhone; only data-free Open Local Sandbox may run locked. The native Shortcuts link opens this app's actions; it does not install a personal provider workflow."),
('Build the provider adapter','Save Agent Step - Local in Shortcuts using the text action actually exposed by your installed Locally app. Pass Shortcut Input into it and Stop and Output the result. If no action exists, use manual transfer.'),
('Validate before running','Complete all five distinct device-local probes in one epoch. Both schema-validation and assertion-pass rates must be at least 80 percent, with zero integrity faults. Local Sandbox cannot inspect Shortcut contents, prove returned-response provenance or provider login, or observe another provider app\'s live model activity. The native app gates new work with its own qualification, run, pending-response, and applying-response state. After deliberate terminal-receipt import, the dashboard shows the validated committed route and ordered handoff hashes; it receives no live native or provider activity.'),
('Publish a real installer','Use the tested Shortcut sharing flow to obtain an iCloud link or Apple-validated export. Add that link in Settings. Apple presents installation and permission prompts on each phone.')],1):y=block(n,title,text,y)

y=start('Sources / implementation notes','Primary documentation checked 11 September 2026. Source sections are named for direct verification.',['Apple','OpenAI','Reference guide','Traceable'],[('Reference','User-supplied iOS_ChatGPT_Local_Agent_Setup_Guide.pdf, pp. 1-5. Its structure and bounded loop are retained; no model availability claims were assumed.'),('SDK baseline','The project targets documented iOS 26 APIs. Later system features must be qualified on the actual device.')])
sources=[
('Apple: run a shortcut from a URL','Shortcuts User Guide, “Run a shortcut from a URL.” A run URL starts an existing personal Shortcut and does not install it. https://support.apple.com/guide/shortcuts/run-a-shortcut-from-a-url-apd624386f42/ios'),
('Apple: App Intents interactions',"App Intents, 'Accelerating app interactions with App Intents' and 'ShortcutsLink.' The app registers its native actions. The link opens this app's Shortcuts page and does not confirm a personal workflow install. https://developer.apple.com/documentation/appintents/app-shortcuts"),
('Apple: App Intent parameters','App Intents, “Adding parameters to an app intent.” Parameter summaries keep Goal and Provider visible in Shortcuts. https://developer.apple.com/documentation/appintents/adding-parameters-to-an-app-intent'),
('Apple: App Intent execution modes','App Intents, “supportedModes.” Immediate foreground mode brings the app forward before device authentication and protected file actions. It does not extend runtime. https://developer.apple.com/documentation/appintents/appintent/supportedmodes'),
('Apple: App Intent authentication','App Intents, “authenticationPolicy” and “requiresLocalDeviceAuthentication.” Protected actions require the executing iPhone to unlock; an unlocked originating device is not sufficient. https://developer.apple.com/documentation/appintents/intentauthenticationpolicy/requireslocaldeviceauthentication'),
('Apple: long-running intents','App Intents, “LongRunningIntent.” iOS 27 extended execution uses performBackgroundTask, regular progress, and cancellation cleanup. https://developer.apple.com/documentation/appintents/longrunningintent'),
('Apple: Xcode system requirements','Xcode 27 RC requires macOS 26.6 or later and provides the iOS 27 SDK and device support used by this release gate. https://developer.apple.com/xcode/system-requirements/'),
('Apple: cross-app orchestration','WWDC26 Apple Intelligence Group Lab, 00:08:18 cross-app intent routing; 00:13:26 background limits; 01:00:09 on-device context. https://developer.apple.com/videos/play/wwdc2026/8011/'),
('Apple: Sign in with Apple for the web','Account Help, “Associate your website to your app.” Local Sandbox implements the Services ID flow at /api/auth/apple/*. Production use still needs a Services ID associated with a primary App ID, a registered domain and return URL, and server secrets. https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/'),
('Apple: Foundation Models','Developer Documentation, Foundation Models framework overview. Availability must be checked at runtime. https://developer.apple.com/documentation/foundationmodels'),
('GitHub: branch conflict handling','REST API endpoints for Git references, “Update a reference,” force=false. This refuses non-fast-forward updates. https://docs.github.com/en/rest/git/refs#update-a-reference'),
('GitHub: authentication','Managing personal access tokens, fine-grained tokens and resource-owner/repository permissions. https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens'),
('Apple: device availability','How to get Apple Intelligence, “Device requirements” and “Turn on Apple Intelligence,” published July 7, 2026. iPhone 15 Pro or newer supported families; runtime availability is still checked. https://support.apple.com/en-us/121115'),
('Implementation evidence','See docs/APPLE-AUTH.md, docs/RELEASE.md, scripts/verify-release.mjs, tests/apple-auth.test.ts, tests/apple-native-auth.test.ts, and the portable Swift contract suites. The verifier records only executed checks. No device, thermal, model-quality, or live Apple-login result is claimed.')]
for n,(title,text) in enumerate(sources,1):
    p=Paragraph(safe_escape(text),body);_,h=p.wrap(343,1000)
    if y-h-47<65:y=start('Sources / continued','Source provenance and implementation boundaries.',['Primary sources','Exact sections','Date checked','Evidence'],[])
    y=block(n,title,text,y)
c.save()
OUT.chmod(0o644)
print(json.dumps({'file':str(OUT),'pages':page}))
