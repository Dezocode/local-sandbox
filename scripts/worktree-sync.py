#!/usr/bin/env python3
"""Apply a reviewed Local Sandbox patch to an existing Git worktree. Dry run by default."""
from pathlib import Path
import argparse, hashlib, json, os, re, subprocess, tempfile

def git(root, *args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True,stderr=subprocess.PIPE).strip()
def digest(value): return hashlib.sha256(value).hexdigest()
def github_repository(remote):
    match=re.fullmatch(r'(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?',remote)
    if not match: raise ValueError('Origin must identify the selected GitHub repository.')
    return match[1].lower()
def prepare(root, patch):
    root=Path(root).resolve()
    if Path(git(root,'rev-parse','--show-toplevel')).resolve()!=root: raise ValueError('Select the exact worktree root.')
    if patch.get('format')!='local-sandbox.patch' or patch.get('version')!=1: raise ValueError('Unsupported patch format.')
    if not re.fullmatch(r'[a-f0-9]{40}',patch.get('baseCommit','')): raise ValueError('Missing base commit.')
    if github_repository(git(root,'remote','get-url','origin'))!=patch.get('repository','').lower(): raise ValueError('Repository mismatch.')
    if git(root,'branch','--show-current')!=patch.get('branch'): raise ValueError('Worktree branch mismatch.')
    if git(root,'rev-parse','HEAD')!=patch['baseCommit']: raise ValueError('Worktree base changed. Re-export after comparing.')
    changes=patch.get('changes')
    if not isinstance(changes,list) or not 1<=len(changes)<=25: raise ValueError('Expected 1–25 bounded text changes.')
    prepared=[];seen=set()
    for item in changes:
        path=item.get('path','')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,179}',path) or any(p in ('','.','..','.git') for p in path.split('/')) or path.startswith('.github/'): raise ValueError('Unsafe file path.')
        if path in seen: raise ValueError('Duplicate patch path.')
        seen.add(path);target=root/path
        if any(p.is_symlink() for p in [target,*target.parents] if p!=root and root in p.parents): raise ValueError('Symlink paths are refused.')
        target.resolve().relative_to(root)
        content=item.get('content')
        if not isinstance(content,str): raise ValueError('Expected text content.')
        after=content.encode('utf-8')
        if len(after)>64000 or b'\0' in after or digest(after)!=item.get('afterSHA256'): raise ValueError('Invalid output hash or text size.')
        before=target.read_bytes() if target.exists() else None
        if before==after: continue  # A repeated application converges without another write.
        if (digest(before) if before is not None else None)!=item.get('beforeSHA256'): raise ValueError('File changed: '+path)
        if before is not None and (len(before)>64000 or b'\0' in before): raise ValueError('Invalid source file.')
        prepared.append((target,before,after))
    return prepared
def apply(root,patch,write=False):
    prepared=prepare(root,patch)
    if not write:return {'status':'reviewed','changes':[str(p.relative_to(Path(root).resolve())) for p,_,_ in prepared]}
    lock=Path(git(root,'rev-parse','--path-format=absolute','--git-path','local-sandbox-sync.lock'))
    fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.close(fd);written=[]
    try:
        prepared=prepare(root,patch)
        for target,before,after in prepared:
            target.parent.mkdir(parents=True,exist_ok=True)
            current=target.read_bytes() if target.exists() else None
            if current!=before:raise ValueError('File changed during application: '+str(target))
            with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as stream:
                temporary=Path(stream.name);stream.write(after);stream.flush();os.fsync(stream.fileno())
            try:
                if before is None:os.link(temporary,target);temporary.unlink()
                else:os.chmod(temporary,target.stat().st_mode);os.replace(temporary,target)
            finally:
                temporary.unlink(missing_ok=True)
            written.append((target,before,after))
            if target.read_bytes()!=after:raise ValueError('Readback failed.')
        return {'status':'applied','files':len(written),'committed':False,'pushed':False}
    except Exception:
        for target,before,after in reversed(written):
            # Never roll back an independent edit that happened after ours.
            if target.exists() and target.read_bytes()==after:
                if before is None:target.unlink()
                else:target.write_bytes(before)
        raise
    finally:lock.unlink(missing_ok=True)
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('patch');parser.add_argument('--worktree',required=True);parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    try:
        source=Path(args.patch)
        if source.stat().st_size>1700000:raise ValueError('Patch exceeds size limit.')
        print(json.dumps(apply(args.worktree,json.loads(source.read_text()),args.apply),indent=2))
    except Exception as error:parser.exit(1,str(error)+'\n')
