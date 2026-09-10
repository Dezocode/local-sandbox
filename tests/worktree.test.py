from pathlib import Path
import importlib.util, tempfile, subprocess, hashlib, copy, json
source=Path(__file__).resolve().parent.parent/'scripts/worktree-sync.py'
spec=importlib.util.spec_from_file_location('sync',source);sync=importlib.util.module_from_spec(spec);spec.loader.exec_module(sync)
checks=[]
def fails(fn):
    try:fn()
    except ValueError:return
    raise AssertionError('Expected conflict')
with tempfile.TemporaryDirectory() as folder:
    root=Path(folder)
    def git(*args):return subprocess.check_output(['git','-C',folder,*args],stderr=subprocess.PIPE,text=True).strip()
    git('init','-b','phone');git('config','user.name','Test');git('config','user.email','test@example.invalid');git('remote','add','origin','https://github.com/Dezocode/example.git')
    (root/'notes.md').write_text('before');git('add','notes.md');git('commit','-m','base')
    patch={'format':'local-sandbox.patch','version':1,'repository':'Dezocode/example','branch':'phone','baseCommit':git('rev-parse','HEAD'),'changes':[{'path':'notes.md','beforeSHA256':sync.digest(b'before'),'afterSHA256':sync.digest(b'after'),'content':'after'}]}
    assert sync.apply(root,patch)['status']=='reviewed';assert (root/'notes.md').read_text()=='before';checks.append('Dry run does not edit')
    assert sync.apply(root,patch,True)['files']==1;assert (root/'notes.md').read_text()=='after';checks.append('Real worktree apply reads back expected content')
    assert sync.apply(root,patch,True)['files']==0;checks.append('Replay is idempotent')
    (root/'notes.md').write_text('independent');fails(lambda:sync.apply(root,patch,True));assert (root/'notes.md').read_text()=='independent';checks.append('Independent edits are preserved')
    wrong=copy.deepcopy(patch);wrong['branch']='other';fails(lambda:sync.apply(root,wrong));checks.append('Wrong branch rejected')
    wrong=copy.deepcopy(patch);wrong['changes'][0]['path']='../escape';fails(lambda:sync.apply(root,wrong));checks.append('Traversal rejected')
    (root/'link').symlink_to('/tmp');wrong=copy.deepcopy(patch);wrong['changes'][0]['path']='link/escape';fails(lambda:sync.apply(root,wrong));checks.append('Symlink escape rejected')
    wrong=copy.deepcopy(patch);wrong['changes'][0]['content']='tampered';fails(lambda:sync.apply(root,wrong));checks.append('Tampered output hash rejected')
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
