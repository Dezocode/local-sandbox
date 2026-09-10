from pathlib import Path
import zipfile,json
root=Path(__file__).resolve().parent.parent
output=root/'public/downloads/Local-Sandbox-Source.zip'
exclude={'node_modules','.git','dist','.sites-runtime','.next','.wrangler','upload','work','outputs','.codex','.agents','__pycache__','release-output','private-exports'}
files=[]
for p in root.rglob('*'):
    if not p.is_file():continue
    relative=p.relative_to(root)
    if any(part in exclude for part in relative.parts):continue
    if p.name.startswith('.env') and p.name!='.env.example':continue
    if p.name.endswith(('.zip','.tsbuildinfo','.pem','.pyc','.p8','.p12','.mobileprovision')):continue
    files.append(p)
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=7) as archive:
    for p in sorted(files):archive.write(p,'Local-Sandbox/'+str(p.relative_to(root)))
with zipfile.ZipFile(output) as archive:
    assert archive.testzip() is None
    names=archive.namelist()
    assert 'Local-Sandbox/ios/LocalSandbox.xcodeproj/project.pbxproj' in names
    assert not any('/.env' in n and not n.endswith('.env.example') for n in names)
print(json.dumps({'archive':str(output),'files':len(files),'bytes':output.stat().st_size}))
