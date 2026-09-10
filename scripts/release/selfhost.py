#!/usr/bin/env python3
"""Package only the local web client and public Shortcut packages, never user data."""
from pathlib import Path
import shutil,zipfile,json,tempfile
root=Path(__file__).resolve().parents[2]
out=root/'public/downloads/Local-Sandbox-Selfhost.zip'
with tempfile.TemporaryDirectory() as temporary:
 stage=Path(temporary)
 for name in ['Caddyfile','compose.yaml']:shutil.copy2(root/'selfhost'/name,stage/name)
 for name in ['local','shortcuts']:shutil.copytree(root/'public'/name,stage/'site'/name)
 (stage/'site/downloads').mkdir()
 shutil.copy2(root/'public/downloads/Local-Sandbox-Source.zip',stage/'site/downloads/Local-Sandbox-Source.zip')
 shutil.copy2(root/'docs/ROADMAP-AUTOMATION.md',stage/'site/downloads/ROADMAP-AUTOMATION.md')
 (stage/'site/index.html').write_text('<!doctype html><meta http-equiv="refresh" content="0;url=/local/index.html"><a href="/local/index.html">Open Local Sandbox</a>')
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for p in sorted(stage.rglob('*')):
   if p.is_file():z.write(p,p.relative_to(stage))
print(json.dumps({'archive':str(out),'containsUserData':False,'appleWebAuthConfigured':False}))
