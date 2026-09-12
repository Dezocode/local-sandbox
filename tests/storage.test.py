from pathlib import Path
import sqlite3,re,json
root=Path(__file__).resolve().parent.parent
connection=sqlite3.connect(':memory:')
connection.row_factory=sqlite3.Row
for file in sorted((root/'drizzle').glob('*.sql')):connection.executescript(file.read_text())
sources='\n'.join(p.read_text() for p in [root/'lib/server.ts',root/'lib/workspace-file-d1.ts',*(root/'app/api').glob('*/route.ts')])
owner_source=(root/'lib/apple-auth-owner-d1.ts').read_text()
owner_gate=re.search(r"export const APPLE_OWNER_OPERATION_ALLOWED_SQL = `(.+?)`;",owner_source,re.DOTALL)
assert owner_gate
owner_gate_argument_count=owner_gate.group(1).count('?')
queries=[]
for match in re.finditer(r"\.prepare\(\s*(['`])(.+?)\1\s*,?\s*\)",sources,re.DOTALL):
 queries.append(match.group(2).replace('${APPLE_OWNER_OPERATION_ALLOWED_SQL}',owner_gate.group(1)))
def query(starts,argument_count,contains=None):
 matches=[q for q in queries if q.startswith(starts) and q.count('?')==argument_count and (contains is None or contains in q)]
 assert matches,starts
 return matches[0]
def execute(starts,*args):return connection.execute(query(starts,len(args)),args)
def execute_matching(starts,contains,*args):return connection.execute(query(starts,len(args),contains),args)
def operation_gate(user_id):return (2_000_000_000,user_id,None,None,None,user_id,None,1_999_999_999)
assert len(operation_gate('binding-contract'))==owner_gate_argument_count
maximum_file_version=9_007_199_254_740_991
def create_file(user_id,path,content,claim):
 allocation=execute_matching('UPDATE workspaces','AND NOT EXISTS',claim,user_id,maximum_file_version,user_id,path,user_id,*operation_gate(user_id)).fetchone()
 created=execute_matching('INSERT OR IGNORE INTO files','workspace.file_clock_claim=?',user_id,path,content,user_id,claim,user_id,path,user_id,*operation_gate(user_id)).fetchone()
 cleared=execute('UPDATE workspaces SET file_clock_claim=NULL',user_id,claim).fetchone()
 return allocation,created,cleared
def save_file(user_id,path,content,version,claim):
 allocation=execute_matching('UPDATE workspaces','AND EXISTS(',claim,user_id,maximum_file_version,user_id,path,version,*operation_gate(user_id)).fetchone()
 saved=execute_matching('UPDATE files','file_clock_claim=?',content,user_id,claim,user_id,path,version,user_id,claim,*operation_gate(user_id)).fetchone()
 cleared=execute('UPDATE workspaces SET file_clock_claim=NULL',user_id,claim).fetchone()
 return allocation,saved,cleared
checks=[]
execute('INSERT OR IGNORE INTO workspaces','user-a','{}','[]',*operation_gate('user-a'))
execute('INSERT OR IGNORE INTO workspaces','user-b','{}','[]',*operation_gate('user-b'))
allocation,created,cleared=create_file('user-a','workspace/a.txt','original','A'*43)
assert allocation['file_clock']==created['version']==cleared['file_clock']==0
assert execute('SELECT path,content,version FROM files','user-b').fetchall()==[]
checks.append('Source queries isolate file reads by owner')
allocation,row,cleared=save_file('user-a','workspace/a.txt','updated',0,'B'*43)
assert allocation['file_clock']==row['version']==cleared['file_clock']
assert row['version']==1
allocation,row,cleared=save_file('user-a','workspace/a.txt','lost',0,'C'*43)
assert allocation is None and row is None and cleared is None
checks.append('File compare-and-swap rejects stale revision')
assert execute('UPDATE workspaces SET policy=?','{"allowed":false}','user-a',0,*operation_gate('user-a')).fetchone()['revision']==1
assert execute('UPDATE workspaces SET policy=?','{}','user-a',0,*operation_gate('user-a')).fetchone() is None
checks.append('Policy compare-and-swap rejects stale authorization')
allocation,row,cleared=create_file('user-a','workspace/a.txt','overwrite','D'*43)
assert allocation is None and row is None and cleared is None
assert connection.execute('SELECT content FROM files WHERE user_id=? AND path=?',('user-a','workspace/a.txt')).fetchone()['content']=='updated'
checks.append('Create does not overwrite an existing file')
execute('INSERT OR IGNORE INTO receipts','user-a','receipt-1','original','2026-09-10T00:00:00Z',*operation_gate('user-a'))
execute('INSERT OR IGNORE INTO receipts','user-a','receipt-1','forged','2026-09-10T01:00:00Z',*operation_gate('user-a'))
assert execute('SELECT payload FROM receipts WHERE user_id=? AND id=?','user-a','receipt-1',*operation_gate('user-a')).fetchone()['payload']=='original'
checks.append('Receipt IDs cannot overwrite prior evidence')
assert 'api.openai.com' not in sources
checks.append('Retired model API endpoint cannot spend API credits')
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
(root/'docs/storage-validation.json').write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2)+'\n')
