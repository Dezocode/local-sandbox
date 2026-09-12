import{LocalAutosaveEngine}from'./local-autosave.js';
import{GitHubConnection,resetGitHubComparisonView,validateGitHubTarget}from'./github.js';
import{OriginConnection}from'./origin.js';
import{openLocalDatabase,storagePersistenceReport}from'./storage.js';
import{createVaultSession,openVault}from'./vault.js';
import{EncryptedWorkspaceClient,createHostedSyncRepository}from'./workspace-sync.js';
import{capabilityEnabled,loadDeploymentCapabilities}from'./capabilities.js';

const el=id=>document.getElementById(id);
const capabilities=await loadDeploymentCapabilities();
const pageCapabilities={github:'githubDirect',origin:'cursorOrigin',sync:'encryptedWorkspaceSync'};
const capabilityForPage=id=>pageCapabilities[id];
const hasCapability=name=>capabilityEnabled(capabilities,name);
function capabilityMessage(name){return name==='cursorOrigin'?'Cursor Origin needs the hosted Local Sandbox identity and API service.':name==='encryptedWorkspaceSync'?'Shared encrypted sync needs the hosted Local Sandbox identity and API service.':'This feature is unavailable in this package.';}
function reportUnavailable(name){const message=capabilityMessage(name);el('deployment-capability-notice').textContent=`${message} Open the hosted /local app to use it.`;el('message').textContent=message;}
function capabilityAction(name,operation){return(...args)=>{if(!hasCapability(name)){reportUnavailable(name);showPage('settings');return;}return operation(...args);};}
function applyDeploymentCapabilities(){
  for(const [page,name] of Object.entries(pageCapabilities)){
    const enabled=hasCapability(name),tab=document.querySelector(`[data-page="${page}"]`),panel=el(page);
    if(tab){tab.hidden=!enabled;tab.disabled=!enabled;tab.setAttribute('aria-hidden',String(!enabled));}
    if(panel&&!enabled)panel.hidden=true;
  }
  el('deployment-capability-notice').textContent=capabilities.mode==='hosted'
    ?'This hosted /local app includes the Local Sandbox identity and API service for Cursor Origin and shared encrypted sync.'
    :capabilities.mode==='static-selfhost'
      ?'This static package has no hosted identity or API service. Direct GitHub access remains available. Open the hosted /local app for Cursor Origin and shared encrypted sync.'
      :'No recognized deployment capability manifest was available. Direct GitHub access remains available, while Cursor Origin and shared encrypted sync are disabled.';
}
applyDeploymentCapabilities();
const defaultVault=()=>({version:1,files:{'workspace/welcome.md':'# Local Sandbox\n\nYour private on-device workspace.','config/oracle.md':'Return one JSON action at a time. Read before editing, require a matching hash, and stop on a failed validation.'},messages:[]});
let databasePromise;
const localDatabase=()=>databasePromise??=openLocalDatabase();
let engine=null,selected='',unsubscribe=()=>{},registration,gitComparison=null,gitBusy=false,originBusy=false,syncBusy=false,syncGeneration=0,syncClient=null,syncConflict=null,syncWorkspaces=[],syncRemote=[];
const github=new GitHubConnection();
const origin=new OriginConnection();
const syncRepository=createHostedSyncRepository();
const syncWriter=`pwa-${crypto.randomUUID().replaceAll('-','')}`;
const initialURL=new URL(location.href),receivedOriginCallback=initialURL.searchParams.get('cursor_origin');
let originCallback=hasCapability('cursorOrigin')?receivedOriginCallback:null;
if(receivedOriginCallback!==null){initialURL.searchParams.delete('cursor_origin');history.replaceState(null,'',`${initialURL.pathname}${initialURL.search}${initialURL.hash}`);}
const sessionActions=document.createElement('div');sessionActions.className='bar';
const sessionRetry=document.createElement('button');sessionRetry.textContent='Retry';
const sessionUseSaved=document.createElement('button');sessionUseSaved.textContent='Use saved session';
const sessionKeepDraft=document.createElement('button');sessionKeepDraft.textContent='Keep draft session';
sessionActions.append(sessionRetry,sessionUseSaved,sessionKeepDraft);el('session-status').after(sessionActions);

function error(value){const issue=value instanceof Error?value:Error('The operation failed.');el('message').textContent=issue.message;alert(issue.message);}

function stateLabel(state){
  const labels={
    clean:'Saved locally · encrypted',
    dirty:'Encrypting recovery draft…',
    dirtyJournaled:state.recovered?'Recovered encrypted draft · autosave pending':'Recovery draft encrypted · autosave pending',
    saving:'Saving encrypted vault…',
    offline:state.message??'Encrypted draft pending while storage is unavailable.',
    conflict:state.message??'Saved content and the encrypted draft conflict.',
    failed:state.message??'Autosave failed. The editor still holds your draft.',
  };
  return labels[state.kind]??'Local · encrypted';
}

function renderStatus(){
  const state=selected&&engine?engine.getState(selected):{kind:'clean'};
  el('status').textContent=stateLabel(state);
  el('retry').hidden=!['offline','failed'].includes(state.kind);
  el('use-saved').hidden=state.kind!=='conflict';
  el('keep-draft').hidden=state.kind!=='conflict';
  el('save').disabled=!selected||['dirty','saving','offline','conflict','failed'].includes(state.kind);
}

function renderTree(){
  el('tree').replaceChildren();
  for(const file of engine.listFiles()){
    const button=document.createElement('button');button.textContent=file.path;button.className=file.path===selected?'active':'';
    button.onclick=()=>{selected=file.path;renderFile();renderTree();};el('tree').append(button);
  }
}

function renderFile(){el('path').textContent=selected||'Select a file';el('editor').value=selected?engine.fileContent(selected)??'':'';renderStatus();}

function renderSessionStatus(){
  const state=engine.getMessageState();el('session-status').textContent=stateLabel(state);
  sessionRetry.hidden=!['offline','failed'].includes(state.kind);sessionUseSaved.hidden=state.kind!=='conflict';sessionKeepDraft.hidden=state.kind!=='conflict';
}

function renderTranscript(){
  el('transcript').replaceChildren();
  for(const message of engine.messages()){
    const box=document.createElement('div');box.className='message';const heading=document.createElement('b');heading.textContent=message.role+' · '+new Date(message.at).toLocaleString();box.append(heading,document.createTextNode(message.text));el('transcript').append(box);
  }
  renderSessionStatus();
}

function render(){renderTree();renderFile();renderTranscript();renderGitHubFiles();renderGitHub();renderOrigin();renderDeviceSync();}

function gitTarget(){return{repository:el('github-repository').value,branch:el('github-branch').value,path:el('github-path').value};}

function gitTargetKey(target){return JSON.stringify(validateGitHubTarget(target));}

function setGitStatus(message,tone=''){el('github-status').textContent=message;el('github-status').dataset.tone=tone;}

function clearGitComparison(message='Compare manually before importing or committing.'){
  gitComparison=null;resetGitHubComparisonView({remote:el('github-remote'),local:el('github-local'),meta:el('github-comparison-meta')},message);setGitStatus(message);renderGitHub();
}

function renderGitHubFiles(){
  const select=el('github-local-file'),previous=select.value;
  select.replaceChildren();
  if(!engine)return;
  const files=engine.listFiles().filter(file=>file.path.startsWith('workspace/')||file.path.startsWith('output/'));
  for(const file of files){const option=document.createElement('option');option.value=file.path;option.textContent=file.path;select.append(option);}
  const preferred=files.some(file=>file.path===previous)?previous:files.some(file=>file.path===selected)?selected:files[0]?.path??'';
  select.value=preferred;
  if(!el('github-path').value&&preferred)el('github-path').value=preferred;
}

function renderGitHub(){
  const identity=github.identity,connected=github.connected;
  el('github-connect-controls').hidden=connected;el('github-connected-controls').hidden=!connected;
  el('github-identity').textContent=identity?`Connected as ${identity.login} for this app session.`:'GitHub is disconnected.';
  el('github-connect').disabled=gitBusy;el('github-compare').disabled=gitBusy||!connected||!engine;
  const currentLocal=gitComparison&&engine?.fileContent(gitComparison.localPath);
  const comparisonCurrent=Boolean(gitComparison&&currentLocal===gitComparison.localContent&&el('github-local-file').value===gitComparison.localPath);
  el('github-push').disabled=gitBusy||!connected||!comparisonCurrent||gitComparison?.snapshot.content===gitComparison?.localContent;
  el('github-import').disabled=gitBusy||!connected||!comparisonCurrent||gitComparison?.snapshot.content===null||gitComparison?.snapshot.content===gitComparison?.localContent;
}

function fillSelect(select,items,value,label){
  const previous=select.value;select.replaceChildren();
  for(const item of items){const option=document.createElement('option');option.value=value(item);option.textContent=label(item);select.append(option);}
  if(items.some(item=>value(item)===previous))select.value=previous;
}

function setOriginStatus(message,tone=''){el('origin-status').textContent=message;el('origin-status').dataset.tone=tone;}

function renderOrigin(){
  const installations=origin.installations,repositories=origin.repositories;
  fillSelect(el('origin-installation'),installations,item=>item.installationId,item=>`${item.namespaceId} · ${new Date(item.updatedAt*1000).toLocaleDateString()}`);
  fillSelect(el('origin-repository'),repositories,item=>item.id,item=>`${item.fullName} · ${item.defaultBranch}`);
  el('origin-refresh').disabled=originBusy;el('origin-connect').disabled=originBusy;el('origin-load').disabled=originBusy||installations.length===0;el('origin-sync').disabled=originBusy||repositories.length===0;el('origin-disconnect').disabled=originBusy||installations.length===0;el('origin-ack-cleanup').hidden=!origin.manualCleanupRequired;el('origin-ack-cleanup').disabled=originBusy;
  el('origin-meta').textContent=repositories.length?`${repositories.length} repository${repositories.length===1?'':'ies'} available. Clone credentials remain inside Cursor Origin and the Local Sandbox server.`:'Load repositories from a connected installation. No installation token is sent to this app.';
}

async function originAction(operation){if(!hasCapability('cursorOrigin')){reportUnavailable('cursorOrigin');return;}if(originBusy)return;originBusy=true;renderOrigin();try{await operation();}catch(value){setOriginStatus(value instanceof Error?value.message:'Cursor Origin could not complete the action.','error');}finally{originBusy=false;renderOrigin();}}
async function refreshOrigin(){if(!hasCapability('cursorOrigin'))return;await originAction(async()=>{const installations=await origin.refresh();setOriginStatus(origin.manualCleanupRequired?'Cursor Origin may contain an installation that Local Sandbox could not save. Review or remove it in Cursor Origin settings.':installations.length?`${installations.length} Cursor Origin installation${installations.length===1?'':'s'} connected.`:'No Cursor Origin installation is connected.',origin.manualCleanupRequired?'error':'success');});}

function setSyncStatus(message,tone=''){el('device-sync-status').textContent=message;el('device-sync-status').dataset.tone=tone;}
function syncRecords(){const records=[...syncRemote];if(syncConflict&&!records.some(item=>item.value.path===syncConflict.path))records.push({record:{revision:syncConflict.remoteRevision},value:syncConflict.remote});return records.sort((left,right)=>left.value.path.localeCompare(right.value.path));}
function selectedSyncRecord(){const path=el('device-sync-remote-file').value;return syncRecords().find(item=>item.value.path===path)??null;}

function renderDeviceSync(){
  fillSelect(el('device-sync-workspace'),syncWorkspaces,item=>item.workspaceId,item=>`${item.workspaceId.slice(0,8)}… · ${new Date(item.updatedAt).toLocaleDateString()}`);
  const localFiles=engine?engine.listFiles().filter(file=>file.path.startsWith('workspace/')||file.path.startsWith('output/')):[];
  fillSelect(el('device-sync-local-file'),localFiles,item=>item.path,item=>item.path);
  const records=syncRecords();fillSelect(el('device-sync-remote-file'),records,item=>item.value.path,item=>`${item.value.path} · r${item.record.revision}`);
  const localPath=el('device-sync-local-file').value,localContent=engine&&localPath?engine.fileContent(localPath):undefined,remote=selectedSyncRecord();
  el('device-sync-local').textContent=localContent??'No local workspace or output file selected.';
  el('device-sync-remote').textContent=remote?(remote.value.content??'(Authenticated deletion tombstone)'):'No encrypted remote record selected.';
  el('device-sync-identity').textContent=syncClient?`Unlocked for this app session · ${syncClient.workspaceId.slice(0,8)}…`:'Encrypted workspace is locked.';
  el('device-sync-import').textContent=remote?.value.content===null?'Apply reviewed deletion':'Import reviewed remote';
  const replacement=el('device-sync-new-passphrase').value,replacementMatches=replacement===el('device-sync-new-confirm').value;
  el('device-sync-create').disabled=syncBusy;el('device-sync-unlock').disabled=syncBusy||syncWorkspaces.length===0;el('device-sync-refresh').disabled=syncBusy;el('device-sync-lock').disabled=syncBusy||!syncClient;el('device-sync-rotate').disabled=syncBusy||!syncClient||el('device-sync-passphrase').value.length<12||replacement.length<12||!replacementMatches;el('device-sync-delete').disabled=syncBusy||!syncClient;el('device-sync-pull').disabled=syncBusy||!syncClient;el('device-sync-push').disabled=syncBusy||!syncClient||!localPath;el('device-sync-import').disabled=syncBusy||!syncClient||!remote||!engine;el('device-sync-tombstone').disabled=syncBusy||!syncClient||!remote||remote.value.content===null;el('device-sync-keep').hidden=!syncConflict;el('device-sync-keep').disabled=syncBusy||!syncConflict;
}

function ensureSyncActive(generation){if(generation!==syncGeneration||!engine)throw new Error('Encrypted sync was locked.');}
async function syncAction(operation){if(!hasCapability('encryptedWorkspaceSync')){reportUnavailable('encryptedWorkspaceSync');return;}if(syncBusy)return;const generation=syncGeneration;syncBusy=true;renderDeviceSync();try{await operation(generation);ensureSyncActive(generation);}catch(value){if(generation===syncGeneration)setSyncStatus(value instanceof Error?value.message:'Encrypted sync could not complete the action.','error');}finally{if(generation===syncGeneration){syncBusy=false;renderDeviceSync();}}}
async function loadDeviceSyncWorkspaces(){if(!hasCapability('encryptedWorkspaceSync'))return;await syncAction(async generation=>{const workspaces=await syncRepository.list();ensureSyncActive(generation);syncWorkspaces=workspaces;setSyncStatus(workspaces.length?`${workspaces.length} recovery-protected workspace${workspaces.length===1?'':'s'} available.`:'No encrypted workspace is enrolled yet.','success');});}
async function pullDeviceSync(generation){if(!hasCapability('encryptedWorkspaceSync'))throw Error(capabilityMessage('encryptedWorkspaceSync'));if(!syncClient)throw Error('Unlock an encrypted workspace first.');const records=await syncClient.pull();ensureSyncActive(generation);syncRemote=records;syncConflict=null;setSyncStatus(`${records.length} encrypted record${records.length===1?'':'s'} authenticated and decrypted locally.`,'success');return records;}
function clearSyncSecrets(){el('device-sync-passphrase').value='';el('device-sync-confirm').value='';el('device-sync-new-passphrase').value='';el('device-sync-new-confirm').value='';}
function lockDeviceSync(message='Encrypted workspace locked for this app session.'){syncGeneration+=1;syncRepository.clear();syncClient=null;syncConflict=null;syncRemote=[];syncWorkspaces=[];syncBusy=false;clearSyncSecrets();renderDeviceSync();setSyncStatus(message);}

async function gitAction(operation,{invalidateOnFailure=false}={}){
  if(gitBusy)return;gitBusy=true;renderGitHub();
  try{await operation();}
  catch(value){
    const issue=value instanceof Error?value:Error('GitHub could not complete this action.');
    if(invalidateOnFailure&&['conflict','uncertain','readback'].includes(issue.code))clearGitComparison(issue.message);
    setGitStatus(issue.message,'error');
  }finally{gitBusy=false;renderGitHub();}
}

async function updatePersistenceStatus(){
  try{el('storage').textContent=(await storagePersistenceReport()).message;}
  catch(value){el('storage').textContent=value instanceof Error?value.message:'Storage persistence could not be checked.';}
}

el('unlock').onclick=async()=>{
  let password=el('password').value;
  try{
    const {vaultStore,draftStore}=await localDatabase();
    const stored=await vaultStore.read();
    if(!stored&&password.length<12)throw Error('Choose a password of at least 12 characters.');
    const opened=stored?await openVault(stored,password):{vault:defaultVault(),session:await createVaultSession(password)};
    engine=await LocalAutosaveEngine.open({vault:opened.vault,envelope:stored,session:opened.session,vaultStore,draftStore});
    unsubscribe=engine.subscribe(()=>{renderStatus();renderSessionStatus();renderDeviceSync();});
    selected=engine.listFiles()[0]?.path??'';
    el('gate').hidden=true;el('workspace').hidden=false;el('message').textContent='';render();void updatePersistenceStatus();
    if(originCallback==='connected'){originCallback=null;showPage('origin');void refreshOrigin();}
  }catch(value){engine?.dispose();engine=null;error(value);}
  finally{password='';el('password').value='';}
};

el('lock').onclick=()=>{
  unsubscribe();unsubscribe=()=>{};engine?.dispose();engine=null;selected='';github.disconnect();origin.clear();lockDeviceSync('Locked. Encrypted sync keys and reviewed plaintext were cleared.');el('github-token').value='';clearGitComparison('Disconnected. The reviewed GitHub and local text was cleared.');renderOrigin();setOriginStatus('Locked. Cursor Origin repository metadata was cleared.');
  el('editor').value='';el('prompt').value='';el('transcript').replaceChildren();el('tree').replaceChildren();el('workspace').hidden=true;el('gate').hidden=false;
};

el('editor').oninput=()=>{try{if(selected&&engine){if(gitComparison?.localPath===selected)clearGitComparison('The local file changed. Compare with GitHub again.');void engine.editFile(selected,el('editor').value).catch(error);}}catch(value){error(value);}};
el('save').onclick=async()=>{try{if(!selected||!engine)throw Error('Create a file first.');await engine.flushFile(selected);renderStatus();}catch(value){error(value);}};
el('retry').onclick=async()=>{try{await engine.retryFile(selected);renderStatus();}catch(value){error(value);}};
el('use-saved').onclick=async()=>{try{await engine.useSavedFile(selected);renderFile();renderTree();}catch(value){error(value);}};
el('keep-draft').onclick=async()=>{try{await engine.keepDraftFile(selected);renderFile();renderTree();}catch(value){error(value);}};

el('github-connect').onclick=()=>void gitAction(async()=>{
  let token=el('github-token').value;
  try{const identity=await github.connect(token);setGitStatus(`Connected as ${identity.login}. The token stays only in this app session.`,'success');}
  finally{token='';el('github-token').value='';}
});

el('github-disconnect').onclick=()=>{github.disconnect();gitComparison=null;el('github-token').value='';clearGitComparison('Disconnected. The in-memory token was cleared.');setGitStatus('GitHub disconnected. The in-memory token was cleared.','success');};

for(const id of ['github-repository','github-branch','github-path'])el(id).oninput=()=>clearGitComparison('The GitHub target changed. Compare again.');
el('github-local-file').onchange=()=>clearGitComparison('The local file changed. Compare again.');
el('github-use-local-path').onclick=()=>{const path=el('github-local-file').value;if(path){el('github-path').value=path;clearGitComparison('The GitHub path now matches the selected local file. Compare again.');}};

el('github-compare').onclick=()=>void gitAction(async()=>{
  const localPath=el('github-local-file').value;if(!engine||!localPath)throw Error('Create a workspace or output file before comparing.');
  await engine.flushFile(localPath);const state=engine.getState(localPath);if(state.kind!=='clean')throw Error(state.message??'Resolve the local autosave before comparing.');
  const target=validateGitHubTarget(gitTarget()),snapshot=await github.inspectFile(target),localContent=engine.fileContent(localPath);
  gitComparison={targetKey:gitTargetKey(target),localPath,localContent,snapshot};
  el('github-remote').textContent=snapshot.content??'(File does not exist on this branch base.)';el('github-local').textContent=localContent;
  el('github-comparison-meta').textContent=snapshot.branchExists?`Compared at ${snapshot.head.slice(0,8)}. Any branch movement blocks the commit.`:`${target.branch} does not exist. A commit will create it from ${snapshot.defaultBranch} at ${snapshot.head.slice(0,8)}.`;
  setGitStatus(snapshot.content===localContent?'The files match.':'Review both versions before importing or committing.','success');renderGitHub();
});

el('github-push').onclick=()=>void gitAction(async()=>{
  if(!engine||!gitComparison)throw Error('Compare with GitHub first.');
  const target=validateGitHubTarget(gitTarget()),localPath=el('github-local-file').value;
  if(gitTargetKey(target)!==gitComparison.targetKey||localPath!==gitComparison.localPath)throw Error('The target changed. Compare again.');
  await engine.flushFile(localPath);const state=engine.getState(localPath);if(state.kind!=='clean')throw Error(state.message??'Resolve the local autosave before committing.');
  const content=engine.fileContent(localPath);if(content!==gitComparison.localContent){clearGitComparison('The local file changed. Compare with GitHub again.');throw Error('The local file changed. Compare with GitHub again.');}
  const effect=gitComparison.snapshot.branchExists?`update ${target.branch}`:`create ${target.branch} from ${gitComparison.snapshot.defaultBranch} and update it`;
  if(!confirm(`Commit ${localPath} to ${target.repository}/${target.path}? This will ${effect}. GitHub history will never be force-pushed.`))return;
  const snapshot=await github.pushFile(gitComparison.snapshot,content,el('github-message').value);
  gitComparison={...gitComparison,snapshot,localContent:content};el('github-remote').textContent=content;el('github-local').textContent=content;el('github-comparison-meta').textContent=`GitHub read back commit ${snapshot.head.slice(0,8)} and the exact file content.`;setGitStatus('Committed and verified on GitHub.','success');
},{invalidateOnFailure:true});

el('github-import').onclick=()=>void gitAction(async()=>{
  if(!engine||!gitComparison||gitComparison.snapshot.content===null)throw Error('Compare an existing GitHub file first.');
  const target=validateGitHubTarget(gitTarget()),localPath=el('github-local-file').value;
  if(gitTargetKey(target)!==gitComparison.targetKey||localPath!==gitComparison.localPath)throw Error('The target changed. Compare again.');
  if(engine.fileContent(localPath)!==gitComparison.localContent){clearGitComparison('The local file changed. Compare again before importing.');throw Error('The local file changed. Compare again before importing.');}
  if(!confirm(`Replace ${localPath} with the reviewed GitHub version from ${gitComparison.snapshot.head.slice(0,8)}?`))return;
  await engine.editFile(localPath,gitComparison.snapshot.content);await engine.flushFile(localPath);const state=engine.getState(localPath);if(state.kind!=='clean')throw Error(state.message??'The imported file is pending local autosave.');
  selected=localPath;gitComparison.localContent=gitComparison.snapshot.content;render();el('github-local').textContent=gitComparison.localContent;el('github-remote').textContent=gitComparison.localContent;el('github-comparison-meta').textContent=`Imported the reviewed GitHub version from ${gitComparison.snapshot.head.slice(0,8)} and saved it to the encrypted vault.`;setGitStatus('GitHub version saved locally.','success');
});

el('origin-connect').onclick=capabilityAction('cursorOrigin',()=>{location.assign(origin.startURL('/local/index.html'));});
el('origin-refresh').onclick=capabilityAction('cursorOrigin',()=>void refreshOrigin());
el('origin-load').onclick=capabilityAction('cursorOrigin',()=>void originAction(async()=>{const installationId=el('origin-installation').value;if(!installationId)throw Error('Connect Cursor Origin first.');const result=await origin.listRepositories(installationId);setOriginStatus(`${result.repositories.length} repository${result.repositories.length===1?'':'ies'} loaded${result.truncated?' · more are available in Cursor':''}.`,'success');}));
el('origin-sync').onclick=capabilityAction('cursorOrigin',()=>void originAction(async()=>{const installationId=el('origin-installation').value,repositoryId=el('origin-repository').value;if(!installationId||!repositoryId)throw Error('Load and choose a Cursor Origin repository first.');const chosen=origin.repositories.find(item=>item.id===repositoryId);if(!chosen)throw Error('Load the Cursor Origin repositories again.');if(!confirm(`Synchronize the Cursor Origin mirror for ${chosen.fullName}?`))return;const result=await origin.syncMirror(installationId,repositoryId);setOriginStatus(result.status==='pending'?`Mirror synchronization for ${result.repository.fullName} was accepted and is pending.`:`Mirror synchronization for ${result.repository.fullName} completed.`,'success');}));
el('origin-disconnect').onclick=capabilityAction('cursorOrigin',()=>void originAction(async()=>{const installationId=el('origin-installation').value;if(!installationId)throw Error('Choose a Cursor Origin installation.');if(!confirm('Disconnect this Cursor Origin installation from Local Sandbox?'))return;await origin.disconnect(installationId);setOriginStatus('Cursor Origin installation disconnected.','success');}));
el('origin-ack-cleanup').onclick=capabilityAction('cursorOrigin',()=>void originAction(async()=>{if(!confirm('Confirm that you reviewed or removed the unresolved Local Sandbox installation in Cursor Origin settings.'))return;await origin.acknowledgeManualCleanup();setOriginStatus('Manual Cursor Origin cleanup review acknowledged.','success');}));

el('device-sync-refresh').onclick=capabilityAction('encryptedWorkspaceSync',()=>void loadDeviceSyncWorkspaces());
el('device-sync-create').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{let passphrase=el('device-sync-passphrase').value;try{if(passphrase!==el('device-sync-confirm').value)throw Error('Recovery passphrases do not match.');const created=await EncryptedWorkspaceClient.create(passphrase,syncRepository,syncWriter);ensureSyncActive(generation);syncClient=created.client;syncConflict=null;syncRemote=[];syncWorkspaces=await syncRepository.list();ensureSyncActive(generation);setSyncStatus('Encrypted workspace enrolled. Store the passphrase safely; the server cannot recover it.','success');}finally{passphrase='';clearSyncSecrets();}}));
el('device-sync-unlock').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{let passphrase=el('device-sync-passphrase').value;try{const workspaceId=el('device-sync-workspace').value;if(!workspaceId)throw Error('Choose an encrypted workspace.');const snapshot=await syncRepository.readWorkspace(workspaceId),client=await EncryptedWorkspaceClient.restore(snapshot.recovery,passphrase,syncRepository,syncWriter);ensureSyncActive(generation);syncClient=client;syncRemote=await client.pull();ensureSyncActive(generation);syncConflict=null;setSyncStatus('Encrypted workspace unlocked and records authenticated for this app session.','success');}finally{passphrase='';clearSyncSecrets();}}));
el('device-sync-lock').onclick=capabilityAction('encryptedWorkspaceSync',()=>lockDeviceSync());
for(const id of ['device-sync-passphrase','device-sync-new-passphrase','device-sync-new-confirm'])el(id).oninput=renderDeviceSync;
el('device-sync-rotate').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{if(!syncClient)throw Error('Unlock an encrypted workspace first.');let current=el('device-sync-passphrase').value,replacement=el('device-sync-new-passphrase').value;try{if(replacement!==el('device-sync-new-confirm').value)throw Error('New recovery passphrases do not match.');if(!confirm('Replace this workspace recovery passphrase? Other devices must use the new passphrase after this completes.'))return;const rotated=await syncClient.rotateRecovery(current,replacement);ensureSyncActive(generation);syncClient=rotated.client;syncConflict=null;syncRemote=await syncClient.pull();ensureSyncActive(generation);syncWorkspaces=await syncRepository.list();ensureSyncActive(generation);setSyncStatus('Recovery passphrase rotated, snapshot advanced, and the new envelope read back. Store the new passphrase before locking.','success');}finally{current='';replacement='';clearSyncSecrets();}}));
el('device-sync-delete').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{if(!syncClient)throw Error('Unlock an encrypted workspace first.');const workspaceId=syncClient.workspaceId;if(!confirm(`Permanently delete encrypted workspace ${workspaceId.slice(0,8)}… and every hosted ciphertext record? Local vault files are not deleted.`))return;await syncClient.deleteWorkspace();ensureSyncActive(generation);syncClient=null;syncConflict=null;syncRemote=[];syncWorkspaces=await syncRepository.list();ensureSyncActive(generation);setSyncStatus('Hosted encrypted workspace and ciphertext records deleted. Local vault files were retained.','success');}));
el('device-sync-pull').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(pullDeviceSync));
el('device-sync-push').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{if(!syncClient||!engine)throw Error('Unlock both the local vault and encrypted workspace first.');const path=el('device-sync-local-file').value;if(!path)throw Error('Choose a local workspace or output file.');await engine.flushFile(path);ensureSyncActive(generation);const state=engine.getState(path);if(state.kind!=='clean')throw Error(state.message??'Resolve local autosave before syncing.');const content=engine.fileContent(path);if(content===undefined)throw Error('The selected local file no longer exists.');const result=await syncClient.push({path,content,generation:engine.getFileGeneration(path)});ensureSyncActive(generation);if(result.kind==='conflict'){syncConflict=result;el('device-sync-remote-file').value=result.path;setSyncStatus('Conflict: review the authenticated remote and local versions before choosing.','error');return;}await pullDeviceSync(generation);setSyncStatus('Latest saved local file encrypted, synced, and read back.','success');}));
el('device-sync-import').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{if(!engine||!syncClient)throw Error('Unlock both the local vault and encrypted workspace first.');const remote=selectedSyncRecord();if(!remote)throw Error('Choose an authenticated remote record.');const path=remote.value.path,deleted=remote.value.content===null;if(!confirm(deleted?`Delete the local ${path} using the reviewed encrypted tombstone?`:`Replace the local ${path} with the reviewed encrypted remote version?`))return;if(deleted){if(engine.fileContent(path)!==undefined){await engine.deleteFile(path);await engine.flushFile(path);}ensureSyncActive(generation);if(engine.fileContent(path)!==undefined)throw Error('The reviewed deletion did not read back from the local encrypted vault.');if(selected===path)selected=engine.listFiles()[0]?.path??'';}else{const existing=engine.fileContent(path);if(existing===undefined)await engine.createFile(path);await engine.editFile(path,remote.value.content);await engine.flushFile(path);ensureSyncActive(generation);if(engine.getState(path).kind!=='clean'||engine.fileContent(path)!==remote.value.content)throw Error('The imported remote version did not read back from the local encrypted vault.');selected=path;}syncConflict=null;await pullDeviceSync(generation);render();setSyncStatus(deleted?'Reviewed tombstone applied and local deletion read back.':'Reviewed remote file imported and read back from the encrypted local vault.','success');}));
el('device-sync-tombstone').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{if(!engine||!syncClient)throw Error('Unlock both the local vault and encrypted workspace first.');const remote=selectedSyncRecord();if(!remote||remote.value.content===null)throw Error('Choose an authenticated remote file.');if(!confirm(`Replace encrypted ${remote.value.path} with a deletion tombstone? The local vault copy will remain until you apply the tombstone.`))return;const localGeneration=engine.fileContent(remote.value.path)===undefined?0:engine.getFileGeneration(remote.value.path),result=await syncClient.push({path:remote.value.path,content:null,generation:Math.max(localGeneration,remote.value.generation+1)});ensureSyncActive(generation);if(result.kind==='conflict'){syncConflict=result;setSyncStatus('Conflict: the encrypted file changed after review. Pull and review it again.','error');return;}const pulled=await pullDeviceSync(generation),verified=pulled.find(item=>item.value.path===remote.value.path&&item.record.revision===result.record.revision&&item.value.content===null);if(!verified)throw Error('The deletion tombstone did not authenticate on readback.');setSyncStatus('Authenticated deletion tombstone encrypted, synced, and read back. The local copy was not deleted.','success');}));
el('device-sync-keep').onclick=capabilityAction('encryptedWorkspaceSync',()=>void syncAction(async generation=>{if(!syncClient||!syncConflict)throw Error('There is no encrypted sync conflict to resolve.');if(!confirm(`Overwrite the reviewed remote ${syncConflict.path} with the local version?`))return;await syncClient.keepMine(syncConflict);ensureSyncActive(generation);await pullDeviceSync(generation);setSyncStatus('Reviewed local version encrypted, saved over the conflict, and read back.','success');}));
el('device-sync-local-file').onchange=renderDeviceSync;el('device-sync-remote-file').onchange=renderDeviceSync;

el('new').onclick=async()=>{
  try{
    const path=prompt('Relative path','workspace/notes.md');if(!path)return;
    await engine.createFile(path);selected=path;render();
  }catch(value){error(value);}
};

function showPage(id){const required=capabilityForPage(id);if(required&&!hasCapability(required)){reportUnavailable(required);id='settings';}document.querySelectorAll('.page').forEach(page=>{page.hidden=page.id!==id;});document.querySelectorAll('[data-page]').forEach(tab=>tab.classList.toggle('active',tab.dataset.page===id));}
for(const button of document.querySelectorAll('[data-page]'))button.onclick=()=>{const required=capabilityForPage(button.dataset.page);if(required&&!hasCapability(required)){reportUnavailable(required);showPage('settings');return;}showPage(button.dataset.page);if(button.dataset.page==='origin'&&hasCapability('cursorOrigin'))void refreshOrigin();if(button.dataset.page==='sync'&&hasCapability('encryptedWorkspaceSync'))void loadDeviceSyncWorkspaces();};

async function record(role){
  const text=el('prompt').value.trim();if(!text)return'';
  await engine.addMessage(role,text);await engine.flushMessages();
  const state=engine.getMessageState();if(state.kind!=='clean')throw Error(state.message??'Resolve the session autosave before continuing.');
  renderTranscript();el('prompt').value='';return text;
}

el('copy').onclick=async()=>{try{const text=await record('Oracle');if(text)await navigator.clipboard.writeText(text);}catch(value){error(value);}};
el('response').onclick=async()=>{try{await record('Locally response');}catch(value){error(value);}};
sessionRetry.onclick=async()=>{try{await engine.retryMessages();renderTranscript();}catch(value){error(value);}};
sessionUseSaved.onclick=async()=>{try{await engine.useSavedMessages();renderTranscript();}catch(value){error(value);}};
sessionKeepDraft.onclick=async()=>{try{await engine.keepDraftMessages();renderTranscript();}catch(value){error(value);}};

el('backup').onclick=async()=>{
  try{
    const raw=await engine.exportEnvelope();const anchor=document.createElement('a');anchor.href=URL.createObjectURL(new Blob([JSON.stringify(raw)],{type:'application/json'}));anchor.download='Local-Sandbox-Encrypted-Backup.json';anchor.click();setTimeout(()=>URL.revokeObjectURL(anchor.href),1000);
  }catch(value){error(value);}
};

el('restore').onchange=async event=>{
  let backupPassword='';
  try{
    const file=event.target.files[0];if(!file)return;if(file.size>15000000)throw Error('Backup is too large.');
    const value=JSON.parse(await file.text());backupPassword=prompt('Enter the password for this encrypted backup.')??'';if(!backupPassword)return;
    const opened=await openVault(value,backupPassword);backupPassword='';
    if(!confirm('Replace this local vault with the verified backup? Export your current backup first.'))return;
    await engine.replaceVault(opened.vault,opened.session);selected=engine.listFiles()[0]?.path??'';render();
  }catch(value){error(value);}
  finally{backupPassword='';event.target.value='';}
};

el('test').onclick=()=>{
  if(!el('installed').checked)return error(Error('Save the Shortcut on your iPhone first, then confirm its exact name.'));
  location.href='shortcuts://run-shortcut?'+new URLSearchParams({name:el('shortcut').value,input:'text',text:'Return only: Local Sandbox round-trip works. Do not edit files.'});
};

el('update').onclick=async()=>{
  try{await registration?.update();el('offline').textContent='Update checked. Close and reopen the app to activate a downloaded shell.';}catch(value){error(value);}
};

if('serviceWorker'in navigator)navigator.serviceWorker.register('./sw.js',{scope:'./'}).then(value=>{registration=value;el('offline').textContent='Offline shell registered. First download may still be completing.';}).catch(()=>{el('offline').textContent='Offline shell unavailable in this browser. Files remain encrypted locally.';});

const displayMode=matchMedia('(display-mode: standalone)');
function updateAppMode(){el('app-mode').textContent=(displayMode.matches||navigator.standalone===true)?'Running as a Home Screen app.':'Running in a browser. Use Safari Share → Add to Home Screen, then launch the saved icon.';}
displayMode.addEventListener('change',updateAppMode);updateAppMode();

function flushBeforeSuspension(){if(engine)void engine.flushAll().catch(()=>undefined);}
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='hidden')flushBeforeSuspension();});
window.addEventListener('pagehide',flushBeforeSuspension);
