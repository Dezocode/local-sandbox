#!/usr/bin/env python3
"""Sign real exported workflows on macOS and stage an immutable web catalog.
No invented provider action identifiers or unsigned-install fallback.
"""
import argparse,hashlib,json,platform,re,subprocess,tempfile,os,shutil
from pathlib import Path
from urllib.parse import urlparse
ROOT=Path(__file__).resolve().parents[2]
def main():
 p=argparse.ArgumentParser();p.add_argument('--exports',type=Path,required=True);p.add_argument('--base-url',required=True);p.add_argument('--recipe',type=Path,default=ROOT/'release/shortcuts/recipe.json');p.add_argument('--output',type=Path,default=ROOT/'public/shortcuts');p.add_argument('--check',action='store_true');a=p.parse_args()
 base=urlparse(a.base_url)
 if base.scheme!='https' or not base.hostname or base.username or base.password or base.query or base.fragment:raise ValueError('Use your HTTPS package-host URL without credentials, query, or fragment.')
 recipe=json.loads(a.recipe.read_text());release=recipe['release']
 if not re.fullmatch(r'\d+\.\d+\.\d+',release):raise ValueError('Release must be a semantic version.')
 rows=recipe['packages'];ids=[r['id'] for r in rows]
 if not rows or len(ids)!=len(set(ids)):raise ValueError('Unique, nonempty packages required.')
 for r in rows:
  if not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',r['id']) or Path(r['file']).name!=r['file'] or not r['file'].endswith('.shortcut'):raise ValueError('Invalid package path.')
  f=a.exports/r['file']
  if f.is_symlink() or not f.is_file() or not 1<=f.stat().st_size<=5000000:raise ValueError(f'Missing or invalid exported workflow: {r["file"]}')
  if not set(r['requires']).issubset(ids):raise ValueError('Unknown dependency.')
 visited=set();active=set()
 def visit(i):
  if i in active:raise ValueError('Dependency cycle.')
  if i in visited:return
  active.add(i)
  for dep in next(r for r in rows if r['id']==i)['requires']:visit(dep)
  active.remove(i);visited.add(i)
 for i in ids:visit(i)
 if a.check:print(json.dumps({'checked':ids,'signed':False}));return
 if platform.system()!='Darwin':raise RuntimeError('Apple shortcuts signing requires macOS. No unsigned fallback will be published.')
 destination=a.output/release
 if destination.exists():raise FileExistsError('Immutable release exists. Use a new package version instead of replacing it.')
 a.output.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(dir=a.output) as temporary:
  stage=Path(temporary);packages=[]
  for r in rows:
   output=stage/(r['id']+'.shortcut')
   subprocess.run(['/usr/bin/shortcuts','sign','--mode','anyone','--input',str((a.exports/r['file']).resolve()),'--output',str(output)],check=True)
   if not output.is_file() or output.stat().st_size==0:raise RuntimeError('Signer did not produce a package.')
   packages.append({'id':r['id'],'name':r['name'],'requires':r['requires'],'url':a.base_url.rstrip('/')+'/'+release+'/'+output.name,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'bytes':output.stat().st_size})
  os.rename(stage,destination)
 catalog={'version':1,'release':release,'status':'signed-awaiting-device-acceptance','packages':packages}
 fd,tmp=tempfile.mkstemp(dir=a.output,prefix='catalog-');os.close(fd)
 Path(tmp).write_text(json.dumps(catalog,indent=2)+'\n');os.replace(tmp,a.output/'catalog.json')
 print(json.dumps({'catalog':str(a.output/'catalog.json'),'packages':len(packages),'deviceVerified':False}))
if __name__=='__main__':main()
