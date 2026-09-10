from pathlib import Path
import sqlite3,re,json
root=Path(__file__).resolve().parent.parent
connection=sqlite3.connect(':memory:')
connection.row_factory=sqlite3.Row
for file in sorted((root/'drizzle').glob('*.sql')):connection.executescript(file.read_text())
sources='\n'.join(p.read_text() for p in [root/'lib/server.ts',*(root/'app/api').glob('*/route.ts')])
queries=re.findall(r"\.prepare\('([^']+)'\)",sources)
def query(starts):
 matches=[q for q in queries if q.startswith(starts)]
 assert matches,starts
 return matches[0]
def execute(starts,*args):return connection.execute(query(starts),args)
checks=[]
execute('INSERT OR IGNORE INTO workspaces','user-a','{}','[]')
execute('INSERT OR IGNORE INTO workspaces','user-b','{}','[]')
execute('INSERT OR IGNORE INTO files','user-a','workspace/a.txt','original')
assert execute('SELECT path,content,version FROM files','user-b').fetchall()==[]
checks.append('Source queries isolate file reads by owner')
row=execute('UPDATE files SET content=?','updated','user-a','workspace/a.txt',0).fetchone()
assert row['version']==1
assert execute('UPDATE files SET content=?','lost','user-a','workspace/a.txt',0).fetchone() is None
checks.append('File compare-and-swap rejects stale revision')
assert execute('UPDATE workspaces SET policy=?','{"allowed":false}','user-a',0).fetchone()['revision']==1
assert execute('UPDATE workspaces SET policy=?','{}','user-a',0).fetchone() is None
checks.append('Policy compare-and-swap rejects stale authorization')
execute('INSERT OR IGNORE INTO files','user-a','workspace/a.txt','overwrite')
assert execute('SELECT content FROM files','user-a','workspace/a.txt').fetchone()['content']=='updated'
checks.append('Create does not overwrite an existing file')
execute('INSERT OR IGNORE INTO receipts','user-a','receipt-1','original','2026-09-10T00:00:00Z')
execute('INSERT OR IGNORE INTO receipts','user-a','receipt-1','forged','2026-09-10T01:00:00Z')
assert execute('SELECT payload FROM receipts WHERE user_id=? AND id=?','user-a','receipt-1').fetchone()['payload']=='original'
checks.append('Receipt IDs cannot overwrite prior evidence')
for _ in range(30):assert execute('INSERT INTO usage','user-a','2026-09-10T01').fetchone() is not None
assert execute('INSERT INTO usage','user-a','2026-09-10T01').fetchone() is None
checks.append('Hourly cloud quota caps at 30 calls')
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
(root/'docs/storage-validation.json').write_text(json.dumps({'passed':len(checks),'checks':checks},indent=2)+'\n')
