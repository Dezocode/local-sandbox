from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor
from reportlab.platypus import Paragraph
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from xml.sax.saxutils import escape
import json, subprocess

ROOT=Path(__file__).resolve().parent.parent
payload=subprocess.check_output(['node','--experimental-strip-types','--input-type=module','-e',"import {shortcuts,aspects} from './lib/catalog.ts'; process.stdout.write(JSON.stringify({shortcuts,aspects}));"],cwd=ROOT,text=True)
data=json.loads(payload)
font='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
bold='/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
pdfmetrics.registerFont(TTFont('Guide',font));pdfmetrics.registerFont(TTFont('GuideBold',bold))
OUT=ROOT/'public/downloads/Local-Sandbox-Setup-Guide.pdf';OUT.parent.mkdir(parents=True,exist_ok=True)
c=canvas.Canvas(str(OUT),pagesize=(612,792));c.setTitle('Local Sandbox - iOS setup and release guide');c.setAuthor('Local Sandbox')
INK=HexColor('#202420');MUTED=HexColor('#647060');LINE=HexColor('#d4dad0');FILL=HexColor('#f4f6f1');ACCENT=HexColor('#8ead69')
body=ParagraphStyle('body',fontName='Guide',fontSize=9.4,leading=13,textColor=INK)
small=ParagraphStyle('small',fontName='Guide',fontSize=8.2,leading=12,textColor=MUTED)
action=ParagraphStyle('action',fontName='GuideBold',fontSize=10.4,leading=13,textColor=INK)
page=0

def para(text,x,y,width,style=body):
    p=Paragraph(escape(text).replace('\n','<br/>'),style);_,h=p.wrap(width,1000);p.drawOn(c,x,y-h);return h

def start(title,sub,pills,sidebar):
    global page
    if page:c.showPage()
    page+=1;c.setFillColor(INK);c.setFont('GuideBold',25 if len(title)<31 else 21);c.drawString(42,746,title)
    para(sub,43,722,526,small)
    x=43
    for pill in pills:
        c.setStrokeColor(LINE);c.setLineWidth(.6);c.rect(x,666,123,23);c.setFillColor(MUTED);c.setFont('Guide',8);c.drawString(x+8,674,pill);x+=132
    c.setStrokeColor(INK);c.line(43,651,569,651);c.setStrokeColor(LINE);c.line(169,633,169,61)
    y=630
    for label,text in sidebar:
        y-=para(label.upper(),44,y,108,ParagraphStyle('side-label',parent=small,fontName='GuideBold',fontSize=8,spaceAfter=4))+9
        y-=para(text,44,y,108,small)+25
    c.setStrokeColor(LINE);c.line(43,44,569,44);c.setFillColor(MUTED);c.setFont('Guide',7);c.drawString(43,29,'LOCAL SANDBOX  /  IMPLEMENTATION PREVIEW  /  10 SEP 2026');c.drawRightString(569,29,f'{page:02d}')
    return 629

def block(n,title,text,y):
    p=Paragraph(escape(text),body);_,ph=p.wrap(343,1000)
    t=Paragraph(escape(title),action);_,th=t.wrap(343,1000)
    height=ph+th+20
    c.setFillColor(FILL);c.setStrokeColor(LINE);c.roundRect(191,y-height,378,height-6,7,fill=1,stroke=1)
    c.setFillColor(INK);c.setFont('GuideBold',10);c.drawString(178,y-18,str(n))
    t.drawOn(c,207,y-14-th);p.drawOn(c,207,y-18-th-ph)
    return y-height-8

def note(title,text,y):
    p=Paragraph(escape(text),body);_,h=p.wrap(350,1000)
    total=h+37;c.setFillColor(HexColor('#edf2e7'));c.setStrokeColor(ACCENT);c.roundRect(191,y-total,378,total-4,7,fill=1,stroke=1)
    para(title,205,y-13,350,action);p.drawOn(c,205,y-total+13)
    return y-total-14

side=[('Build order','1. Folder\n2. Dispatcher\n3. Provider\n4. Runner\n5. Receipt\n6. Siri'),('Budgets','6 steps initially\n3 failures maximum\n2 identical failures stop\nOne model at a time'),('Identity','Web: ChatGPT session\nNative: Apple sign-in\nFolder: separate permission')]
y=start('Local Sandbox','A visual setup guide for Oracle-guided iOS tools, bounded local reasoning, and verifiable execution.',['Oracle guidance','Shortcuts executor','Scoped file access','Xcode companion'],side)
y=block(1,'Use one executor and interchangeable reasoning', 'Oracle prepares a compact task. A micro-model or frontier provider proposes one tool call. A deterministic dispatcher validates and executes it. Readback evidence becomes a receipt. Siri is a voice entry and Apple-owned orchestrator.',y)
y=block(2,'Open the private observation dashboard','https://local-sandbox.candy-lyric-5390.chatgpt.site - use your ChatGPT session. The online sandbox saves text files, policy, progress, and receipts. It is a separate source workspace, not a live mount of iCloud Drive.',y)
y=block(3,'Choose the iPhone path','For Shortcuts-only use, configure the recipes on the following pages. For native use, open ios/LocalSandbox.xcodeproj in Xcode, choose your developer team, enable Sign in with Apple, build to your device, then select your LocalSandbox folder.',y)
y=note('What is ready, and what is still required','The web application and native source are prepared. The native app has not been compiled or run on an Apple device in this Linux environment. Signed shortcuts, Apple provisioning, device acceptance, external local-provider actions, API credentials, and App Review remain release gates.',y)

for idx,recipe in enumerate(data['shortcuts']):
    sidebar=[('Shortcut',recipe['name']),('Role',recipe['role']),('Inputs','Goal, compact state, latest result, saved policy.'),('Output','One action or one typed result. Keep detailed traces on disk.'),('Approval','Install/configure on iPhone. Grant folder and notification access through iOS. Never infer permission from model text.')]
    sub=recipe['description']
    y=start(f"{idx+1:02d} / {recipe['name']}",sub,['Sequential','Compact context','Typed results','User-owned policy'],sidebar)
    for n,(label,text) in enumerate(recipe['steps'],1):
        p=Paragraph(escape(text),body);_,h=p.wrap(343,1000)
        if y-(h+47)<65:y=start(recipe['name']+' / continued',sub,['Same shortcut','Continue in order','Validate','Record evidence'],sidebar)
        y=block(n,label,text,y)
    p=Paragraph(escape(recipe['verify']),body);_,h=p.wrap(350,1000)
    if y-h-40<65:y=start(recipe['name']+' / validation','Check the complete action before continuing.',['Acceptance','Actual device','No silent retries','Receipt'],sidebar)
    note('Acceptance check',recipe['verify'],y)

y=start('Native setup / Xcode','Apple identity, scoped iCloud access, and local execution are separate capabilities.',['iOS 26+ target','SwiftUI','App Intents','Foundation Models'],[('Open','ios/LocalSandbox.xcodeproj'),('Signing','Select an Apple Developer team and a unique bundle ID.'),('Capabilities','Sign in with Apple is declared. The system folder picker grants scoped access.'),('Release gate','Run on a supported iPhone. Simulator battery readings are unavailable, so resource admission blocks there.')])
for n,(title,text) in enumerate([
('Build and sign','Use Xcode with the iOS 26 SDK or later. Set DEVELOPMENT_TEAM and a unique PRODUCT_BUNDLE_IDENTIFIER in Signing & Capabilities. The project contains no signing identity or private key.'),
('Sign in with Apple','The app uses AuthenticationServices, checks the authorization state, and saves the opaque user ID in Keychain. This is a local identity feature. It does not authenticate the separate Sites dashboard or create a remote Apple-backed account.'),
('Select your sandbox','In native Settings choose iCloud Drive / Shortcuts / LocalSandbox through the system folder picker. The app stores a scoped bookmark and coordinates file reads and writes. A revoked or unavailable folder blocks execution.'),
('Configure a provider','Apple Intelligence requires a supported device and enabled model availability. OpenAI uses your own project key and model ID from Keychain after cloud consent. Locally AI or LM Link runs through an installed named Shortcuts adapter.'),
('Test the actual device','Run the model contract test against workspace/test.txt. Verify file contents, app receipt, interruption behavior, permission denial, battery reserve, cancellation, and thermal admission. Inspect the checkpoint after a crash before starting another run.')],1):y=block(n,title,text,y)

y=start('Resource policy / exact meaning','Your sliders authorize stop thresholds and model context choices, not OS-level resource reservations.',['Consent','Measurement','Admission','Cancellation'],[('Default policy','15% battery drop\n20% reserve\n35% app memory target\n6 steps\n3 failures'),('Cloud','Off by default. API configuration alone does not authorize a cloud call.'),('Context','6,000 characters is a proxy, not a guaranteed token count. Measure tokenizer counts in qualified runtimes.')])
for n,(title,text) in enumerate([
('Battery','The runner reads the current battery percentage before and during a model step. It stops below the reserve or at the observed level-drop budget. While charging, that drop is not a measurement of consumed energy.'),
('Memory','The native monitor reads this app process footprint relative to physical memory. It does not observe separate Foundation Models services or another local-provider app. iOS owns allocation and can terminate work earlier.'),
('Thermal and cancellation','Serious or critical thermal pressure requests cancellation. Cooperative cancellation can take time; the runner rechecks limits before a tool runs. The web dashboard never displays fabricated live device telemetry.'),
('Failure recovery','Invalid JSON and patch conflicts return to the model within the failure budget. Edits require a fresh hash and one literal old-text match. Call journals record pending before mutation and refuse uncertain replays. An interrupted run must be reviewed.'),
('Evidence-driven improvement','Record model/runtime, device, exact task, policy, verified outcome, wall time, and errors. Change one prompt or schema parameter at a time. Promote a larger budget only after user authorization. Do not infer local model quality from a deterministic web check.')],1):y=block(n,title,text,y)

y=start('Release / every aspect is a goal','The complete goal map is also available in the dashboard as an exportable checklist.',['Web','Device','Apple','Distribution'],[('Distribution','No App Store submission is claimed. Apple signing, store metadata, screenshots, privacy labels, support details, and App Review are required.'),('Repository','Source is downloadable. A publication script is included. GitHub publication is reported only after a successful remote push.')])
for n,a in enumerate(data['aspects'],1):
    text=a[1]+' Status: '+a[2]+'.'
    p=Paragraph(escape(text),body);_,h=p.wrap(343,1000)
    if y-h-48<65:y=start('Release goals / continued','Preserve the same execution contract across every provider.',['Track','Test','Approve','Release'],[('Readiness','Implemented web features and prepared native source are different evidence levels.'),('Do not skip','Real device checks and Apple account configuration.')])
    y=block(n,a[0],text,y)

y=start('Sources / implementation notes','Primary documentation checked 10 September 2026. Source sections are named for direct verification.',['Apple','OpenAI','Reference guide','Traceable'],[('Reference','User-supplied iOS_ChatGPT_Local_Agent_Setup_Guide.pdf, pp. 1-5. Its structure and bounded loop are retained; no model availability claims were assumed.'),('SDK baseline','The project targets documented iOS 26 APIs. Later system features must be qualified on the actual device.')])
sources=[
('Apple: run a shortcut from a URL','Shortcuts User Guide, “Run a shortcut from a URL.” https://support.apple.com/guide/shortcuts/run-a-shortcut-from-a-url-apd624386f42/ios'),
('Apple: cross-app orchestration','WWDC26 Apple Intelligence Group Lab, 00:08:18 cross-app intent routing; 00:13:26 background limits; 01:00:09 on-device context. https://developer.apple.com/videos/play/wwdc2026/8011/'),
('Apple: Sign in with Apple for the web','Account Help, “Associate your website to your app.” A web Apple sign-in needs a Services ID associated with a primary App ID. The private Sites version uses platform authentication instead. https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/'),
('Apple: Foundation Models','Developer Documentation, Foundation Models framework overview. Availability must be checked at runtime. https://developer.apple.com/documentation/foundationmodels'),
('OpenAI: function calling','API guide, “Function calling.” A model proposes a call; application code executes it. Strict schemas do not grant authority. https://developers.openai.com/api/docs/guides/function-calling'),
('Implementation evidence','See docs/RELEASE.md, docs/ARCHITECTURE.md, tests/contracts.test.ts, the generated migration, and native SandboxTests.swift. Only completed tests are recorded as passing. No device, thermal, model-quality, or Apple-login result is fabricated.')]
for n,(title,text) in enumerate(sources,1):
    p=Paragraph(escape(text),body);_,h=p.wrap(343,1000)
    if y-h-47<65:y=start('Sources / continued','Source provenance and implementation boundaries.',['Primary sources','Exact sections','Date checked','Evidence'],[])
    y=block(n,title,text,y)
c.save()
print(json.dumps({'file':str(OUT),'pages':page}))
