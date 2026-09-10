#!/usr/bin/env python3
"""Local Mac build/install/archive/upload automation. Upload is not App Review approval."""
import argparse,json,os,platform,plistlib,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def run(args):subprocess.run(args,cwd=ROOT,check=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('stage',choices=['check','test','install','archive','upload']);p.add_argument('--team');p.add_argument('--bundle-id',default='com.dezocode.LocalSandbox');p.add_argument('--device');p.add_argument('--simulator');p.add_argument('--build-number',default='4');a=p.parse_args()
 if platform.system()!='Darwin':raise RuntimeError('Run this on your Mac with Xcode. No Apple build was performed.')
 if not re.fullmatch(r'[A-Za-z0-9.-]+',a.bundle_id) or not a.build_number.isdigit():raise ValueError('Invalid bundle ID or build number.')
 run(['xcodebuild','-version']);run(['xcodebuild','-showsdks'])
 if a.stage=='check':run(['/usr/bin/shortcuts','--help']);return
 out=ROOT/'release-output';out.mkdir(exist_ok=True)
 base=['xcodebuild','-project','ios/LocalSandbox.xcodeproj','-scheme','LocalSandbox']
 if a.stage=='test':
  if not a.simulator:raise ValueError('Supply --simulator with an available iPhone simulator UDID from xcrun simctl list devices available.')
  run(base+['-destination','platform=iOS Simulator,id='+a.simulator,'CODE_SIGNING_ALLOWED=NO','test']);return
 if not a.team or not re.fullmatch(r'[A-Z0-9]{10}',a.team):raise ValueError('Supply your 10-character Apple Developer team ID.')
 auth=[]
 keys=['LS_ASC_KEY_PATH','LS_ASC_KEY_ID','LS_ASC_ISSUER_ID']
 if any(os.environ.get(k) for k in keys):
  if not all(os.environ.get(k) for k in keys):raise ValueError('Set all three LS_ASC key environment values, or use your Xcode account.')
  auth=['-authenticationKeyPath',os.environ[keys[0]],'-authenticationKeyID',os.environ[keys[1]],'-authenticationKeyIssuerID',os.environ[keys[2]]]
 signing=['DEVELOPMENT_TEAM='+a.team,'PRODUCT_BUNDLE_IDENTIFIER='+a.bundle_id,'CURRENT_PROJECT_VERSION='+a.build_number,'-allowProvisioningUpdates']+auth
 if a.stage=='install':
  if not a.device:raise ValueError('Supply --device from xcrun devicectl list devices.')
  derived=out/'device-build';run(base+['-configuration','Debug','-destination','id='+a.device,'-derivedDataPath',str(derived)]+signing+['build'])
  run(['xcrun','devicectl','device','install','app','--device',a.device,str(derived/'Build/Products/Debug-iphoneos/LocalSandbox.app')]);return
 archive=out/('LocalSandbox-'+a.build_number+'.xcarchive')
 if archive.exists():raise FileExistsError('Archive already exists. Use a new build number; prior artifacts are preserved.')
 run(base+['-configuration','Release','-destination','generic/platform=iOS','-archivePath',str(archive)]+signing+['archive'])
 options={'method':'app-store-connect','teamID':a.team,'signingStyle':'automatic','destination':'upload' if a.stage=='upload' else 'export','manageAppVersionAndBuildNumber':False,'uploadSymbols':True}
 export=out/('ExportOptions-'+a.build_number+'.plist');export.write_bytes(plistlib.dumps(options))
 run(['xcodebuild','-exportArchive','-archivePath',str(archive),'-exportPath',str(out/('export-'+a.build_number)),'-exportOptionsPlist',str(export),'-allowProvisioningUpdates']+auth)
 print(json.dumps({'stage':a.stage,'archive':str(archive),'appReviewApproved':False,'next':'Check App Store Connect processing, test on device, complete metadata, then submit for review.'}))
if __name__=='__main__':main()
