from pathlib import Path
import hashlib,json,plistlib
root=Path(__file__).resolve().parent.parent/'ios'; app=root/'LocalSandbox';project=root/'LocalSandbox.xcodeproj'
project.mkdir(exist_ok=True)
def ident(key):return hashlib.sha256(key.encode()).hexdigest()[:24].upper()
objects={}
def obj(key,body):objects[ident(key)]=body;return ident(key)
def q(text):return json.dumps(str(text))
sources=sorted(app.glob('*.swift'));tests=sorted((root/'LocalSandboxTests').glob('*.swift'))
fileids=[];sourceids=[];testfileids=[];testbuildids=[];resourceids=[]
for f in sources+tests:
    fid=obj('file:'+f.name,f'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {q(f.relative_to(root))}; sourceTree = SOURCE_ROOT;')
    bid=obj('build:'+f.name,f'isa = PBXBuildFile; fileRef = {fid};')
    if f in tests:testfileids.append(fid);testbuildids.append(bid)
    else:fileids.append(fid);sourceids.append(bid)
for name,kind in [('LocalSandbox/Assets.xcassets','folder.assetcatalog'),('LocalSandbox/PrivacyInfo.xcprivacy','text.xml')]:
    fid=obj('resource:'+name,f'isa = PBXFileReference; lastKnownFileType = {kind}; path = {q(name)}; sourceTree = SOURCE_ROOT;');fileids.append(fid)
    resourceids.append(obj('resourcebuild:'+name,f'isa = PBXBuildFile; fileRef = {fid};'))
product=obj('app-product','isa = PBXFileReference; explicitFileType = wrapper.application; path = LocalSandbox.app; sourceTree = BUILT_PRODUCTS_DIR;')
testproduct=obj('test-product','isa = PBXFileReference; explicitFileType = wrapper.cfbundle; path = LocalSandboxTests.xctest; sourceTree = BUILT_PRODUCTS_DIR;')
products=obj('products',f'isa = PBXGroup; children = ({product},{testproduct},); name = Products; sourceTree = "<group>";')
main=obj('main',f'isa = PBXGroup; children = ({",".join(fileids+testfileids+[products])},); sourceTree = "<group>";')
def phase(name,kind,ids):return obj(name,f'isa = {kind}; buildActionMask = 2147483647; files = ({",".join(ids)}{"," if ids else ""}); runOnlyForDeploymentPostprocessing = 0;')
sp=phase('sources','PBXSourcesBuildPhase',sourceids);rp=phase('resources','PBXResourcesBuildPhase',resourceids);fp=phase('frameworks','PBXFrameworksBuildPhase',[])
tsp=phase('test-sources','PBXSourcesBuildPhase',testbuildids);tfp=phase('test-frameworks','PBXFrameworksBuildPhase',[])
def configs(prefix,common):
    ids=[]
    for name in ['Debug','Release']:
        setting={**common,'SWIFT_OPTIMIZATION_LEVEL':'-Onone' if name=='Debug' else '-O','DEBUG_INFORMATION_FORMAT':'dwarf' if name=='Debug' else 'dwarf-with-dsym'}
        if name=='Debug':setting['SWIFT_ACTIVE_COMPILATION_CONDITIONS']='DEBUG'
        body=' '.join(f'{k} = {q(v)};' for k,v in setting.items())
        ids.append(obj(prefix+name,f'isa = XCBuildConfiguration; buildSettings = {{{body}}}; name = {name};'))
    return obj(prefix+'list',f'isa = XCConfigurationList; buildConfigurations = ({",".join(ids)},); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
base={'SDKROOT':'iphoneos','IPHONEOS_DEPLOYMENT_TARGET':'26.0','SWIFT_VERSION':'5.0','CLANG_ENABLE_MODULES':'YES','CLANG_ENABLE_OBJC_ARC':'YES','ENABLE_USER_SCRIPT_SANDBOXING':'YES'}
pc=configs('project',base)
ac=configs('app',{**base,'PRODUCT_BUNDLE_IDENTIFIER':'com.dezocode.LocalSandbox','PRODUCT_NAME':'$(TARGET_NAME)','INFOPLIST_FILE':'LocalSandbox/Info.plist','CODE_SIGN_ENTITLEMENTS':'LocalSandbox/LocalSandbox.entitlements','CODE_SIGN_STYLE':'Automatic','DEVELOPMENT_TEAM':'','CURRENT_PROJECT_VERSION':'3','MARKETING_VERSION':'0.3.0','TARGETED_DEVICE_FAMILY':'1,2','ASSETCATALOG_COMPILER_APPICON_NAME':'AppIcon','GENERATE_INFOPLIST_FILE':'NO','LD_RUNPATH_SEARCH_PATHS':'$(inherited) @executable_path/Frameworks'})
tc=configs('test',{**base,'PRODUCT_BUNDLE_IDENTIFIER':'com.dezocode.LocalSandboxTests','PRODUCT_NAME':'$(TARGET_NAME)','GENERATE_INFOPLIST_FILE':'YES','CODE_SIGN_STYLE':'Automatic','DEVELOPMENT_TEAM':'','TEST_HOST':'$(BUILT_PRODUCTS_DIR)/LocalSandbox.app/LocalSandbox','BUNDLE_LOADER':'$(TEST_HOST)','TARGETED_DEVICE_FAMILY':'1,2'})
proxy=obj('proxy',f'isa = PBXContainerItemProxy; containerPortal = {ident("project")}; proxyType = 1; remoteGlobalIDString = {ident("app-target")}; remoteInfo = LocalSandbox;')
dependency=obj('dependency',f'isa = PBXTargetDependency; target = {ident("app-target")}; targetProxy = {proxy};')
at=obj('app-target',f'isa = PBXNativeTarget; buildConfigurationList = {ac}; buildPhases = ({sp},{fp},{rp},); buildRules = (); dependencies = (); name = LocalSandbox; productName = LocalSandbox; productReference = {product}; productType = "com.apple.product-type.application";')
tt=obj('test-target',f'isa = PBXNativeTarget; buildConfigurationList = {tc}; buildPhases = ({tsp},{tfp},); buildRules = (); dependencies = ({dependency},); name = LocalSandboxTests; productName = LocalSandboxTests; productReference = {testproduct}; productType = "com.apple.product-type.bundle.unit-test";')
pr=obj('project',f'isa = PBXProject; attributes = {{LastUpgradeCheck = 2600; TargetAttributes = {{{at} = {{CreatedOnToolsVersion = 26.0; SystemCapabilities = {{com.apple.SignInWithApple = {{enabled = 1;}};}};}}; {tt} = {{CreatedOnToolsVersion = 26.0; TestTargetID = {at};}};}};}}; buildConfigurationList = {pc}; compatibilityVersion = "Xcode 15.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en,Base,); mainGroup = {main}; productRefGroup = {products}; projectDirPath = ""; projectRoot = ""; targets = ({at},{tt},);')
(project/'project.pbxproj').write_text('// !$*UTF8*$!\n{archiveVersion = 1; classes = {}; objectVersion = 60; objects = {\n'+''.join(f'{k} = {{{v}}};\n' for k,v in objects.items())+f'}}; rootObject = {pr};}}\n')
(project/'project.xcworkspace/contents.xcworkspacedata').write_text('<?xml version="1.0" encoding="UTF-8"?><Workspace version="1.0"><FileRef location="self:"/></Workspace>')
(project/'xcshareddata/xcschemes/LocalSandbox.xcscheme').write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2600" version="1.7"><BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{at}" BuildableName="LocalSandbox.app" BlueprintName="LocalSandbox" ReferencedContainer="container:LocalSandbox.xcodeproj"/></BuildActionEntry></BuildActionEntries></BuildAction><TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{tt}" BuildableName="LocalSandboxTests.xctest" BlueprintName="LocalSandboxTests" ReferencedContainer="container:LocalSandbox.xcodeproj"/></TestableReference></Testables></TestAction><LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{at}" BuildableName="LocalSandbox.app" BlueprintName="LocalSandbox" ReferencedContainer="container:LocalSandbox.xcodeproj"/></BuildableProductRunnable></LaunchAction><ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"/><AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/></Scheme>''')
info={'CFBundleDevelopmentRegion':'en','CFBundleDisplayName':'Local Sandbox','CFBundleExecutable':'$(EXECUTABLE_NAME)','CFBundleIdentifier':'$(PRODUCT_BUNDLE_IDENTIFIER)','CFBundleName':'$(PRODUCT_NAME)','CFBundlePackageType':'APPL','CFBundleShortVersionString':'$(MARKETING_VERSION)','CFBundleVersion':'$(CURRENT_PROJECT_VERSION)','LSApplicationQueriesSchemes':['shortcuts'],'LSRequiresIPhoneOS':True,'UIApplicationSceneManifest':{'UIApplicationSupportsMultipleScenes':False},'UILaunchScreen':{},'UISupportedInterfaceOrientations':['UIInterfaceOrientationPortrait','UIInterfaceOrientationLandscapeLeft','UIInterfaceOrientationLandscapeRight'],'LSSupportsOpeningDocumentsInPlace':True,'UIFileSharingEnabled':False,'NSFaceIDUsageDescription':'Unlock your private workspace and authorize Local Sandbox actions.','ITSAppUsesNonExemptEncryption':False}
(app/'Info.plist').write_bytes(plistlib.dumps(info))
(app/'LocalSandbox.entitlements').write_bytes(plistlib.dumps({'com.apple.developer.applesignin':['Default']}))
privacy={'NSPrivacyTracking':False,'NSPrivacyTrackingDomains':[],'NSPrivacyCollectedDataTypes':[],'NSPrivacyAccessedAPITypes':[{'NSPrivacyAccessedAPIType':'NSPrivacyAccessedAPICategoryUserDefaults','NSPrivacyAccessedAPITypeReasons':['CA92.1']},{'NSPrivacyAccessedAPIType':'NSPrivacyAccessedAPICategoryFileTimestamp','NSPrivacyAccessedAPITypeReasons':['C617.1']}]}
(app/'PrivacyInfo.xcprivacy').write_bytes(plistlib.dumps(privacy))
assets=app/'Assets.xcassets/AppIcon.appiconset';assets.mkdir(parents=True,exist_ok=True)
(assets.parent/'Contents.json').write_text(json.dumps({'info':{'author':'xcode','version':1}}))
(assets/'Contents.json').write_text(json.dumps({'images':[{'filename':'AppIcon.png','idiom':'universal','platform':'ios','size':'1024x1024'}],'info':{'author':'xcode','version':1}}))
from PIL import Image
image=Image.open(root.parent/'public/app-icon.png').convert('RGBA').resize((1024,1024),Image.Resampling.LANCZOS)
opaque=Image.new('RGB',image.size,'#111112');opaque.paste(image,mask=image.getchannel('A'));opaque.save(assets/'AppIcon.png')
brand=app/'Assets.xcassets/Brand.imageset';brand.mkdir(exist_ok=True)
image.save(brand/'Brand.png')
(brand/'Contents.json').write_text(json.dumps({'images':[{'filename':'Brand.png','idiom':'universal'}],'info':{'author':'xcode','version':1}}))
print(json.dumps({'project':str(project),'swift_files':len(sources),'test_files':len(tests)}))
