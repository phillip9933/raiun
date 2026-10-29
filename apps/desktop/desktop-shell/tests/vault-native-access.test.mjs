import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';
const source=await readFile(new URL('../src/main.ts',import.meta.url),'utf8');
const parsed=ts.createSourceFile('main.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const names=['nativeVaultBrowseAvailable','clearVaultBrowse','invalidateUnavailableNativeVaultBrowse','vaultDirectoryRows','isStrongVaultEtag','nativeExistingFileSaveMessage','nativeVaultLockIncomplete','nativeVaultAccess','vaultAppFeaturesAvailable','nativeVaultActionAllowed','request','vaultSecretRequest','openEncryptedAccess','loadCachedVaultRoots','loadVaultPath','loadVaultPins','startVaultOfflinePin','startVaultEditRetry','createEncryptedVault','useVaultFolder','savePair','nativeVaultDrivePanel','openNativeVaultDrive','vaultOfflinePinPanel','vaultEditRetryPanel','encryptedEditRecoveryCard','copyVerifyBindingCurrent','interruptedCreateRetryContextCurrent','currentCopyProducerContext','verifyCopyOperation','pollCopyVerification','checkCopyVerificationStatus','cancelCopyVerification','retryInterruptedFileCreate','pollInterruptedCreateRetry','pollCopyProducer','scheduleCopyVerifyPoll','scheduleInterruptedCreateRetryPoll','scheduleCopyProducerPoll'];
const functions=parsed.statements.filter(n=>ts.isFunctionDeclaration(n)&&names.includes(n.name?.text)).map(n=>n.getFullText(parsed)).join('\n');
const compiled=ts.transpileModule(functions,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
function harness(native=true){
  const calls=[];
  const state={status:{connected:true,mounted:true,...(native?{vault_access_mode:'native_read_only'}:{})},accountEpoch:1,selectedAccount:'profile-a',vaultGeneration:2,accountSwitching:false,agentReachable:true,pickerGeneration:0,vaultDialog:{unlocked:true,statusUnknown:false,vaultMountReady:true,loading:false,accountEpoch:1,generation:2}};
  const context={state,StaleAccountRequest:class extends Error{},featureAvailable:()=>true,isTauri:()=>true,profileIndependentActions:new Set(),invoke:async(command,args)=>{calls.push({command,...args});return[];},isCurrentAccount:(epoch,id=state.selectedAccount)=>epoch===state.accountEpoch&&id===state.selectedAccount,accountSwitchDisabled:()=>false,render:()=>{},isStaleAccountRequest:error=>error instanceof context.StaleAccountRequest,messageOf:error=>error.message,esc:value=>String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('\"','&quot;'),svg:()=>'',lastPath:value=>value.split('/').at(-1),parentPath:value=>value.slice(0,value.lastIndexOf('/'))||'/',formatBytes:value=>`${value} bytes`,canStartVaultCopyFrom:()=>false,copyProducerUi:{source:null},cachedVaultRootsUi:{generation:0,roots:[]},loadSpaces:async()=>calls.push({command:'spaces'}),openAccountFolder:async command=>calls.push({command})};
  vm.createContext(context);vm.runInContext(compiled,context);return{context,state,calls};
}
test('native picker only loads metadata, direct unsupported handlers do no work, ordinary requests still run',async()=>{
  const h=harness();await h.context.openEncryptedAccess();assert.deepEqual(h.calls,[{command:'spaces'}]);
  for(const name of ['loadCachedVaultRoots','loadVaultPath','loadVaultPins','startVaultOfflinePin','startVaultEditRetry','createEncryptedVault','useVaultFolder'])await h.context[name]();
  assert.equal(h.calls.length,1);
  h.state.spaces=[{id:'encrypted',encrypted:true,writable:true}];h.state.spaceId='encrypted';await h.context.savePair();assert.match(h.state.error,/not sync folders/);assert.equal(h.calls.length,1);
  for(const action of ['vault_list','vault_pins','vault_cached_roots','vault_unlocked_roots','vault_reconcile_edits_start','encrypted_edit_recoveries','vault_create'])await assert.rejects(h.context.request(action),/unavailable/);
  assert.equal(h.calls.length,1);
  for(const action of ['vault_inspect','vault_lock','vault_forget','spaces','pairs'])await h.context.request(action);
  assert.deepEqual(h.calls.slice(1).map(c=>c.message.action),['vault_inspect','vault_lock','vault_forget','spaces','pairs']);
});
test('native drive button requires current ready unlocked context and unsupported panels are absent',async()=>{
  const h=harness();const flow=h.state.vaultDialog;
  assert.match(h.context.nativeVaultDrivePanel(flow,false),/Read-only Windows drive access/);
  assert.doesNotMatch(h.context.nativeVaultDrivePanel(flow,false),/data-vault-pin|data-vault-path/);
  for(const name of ['vaultOfflinePinPanel','vaultEditRetryPanel','encryptedEditRecoveryCard'])assert.equal(h.context[name](flow),'');
  await h.context.openNativeVaultDrive();assert.deepEqual(h.calls,[{command:'open_cloud_folder'}]);
  flow.vaultMountReady=false;await h.context.openNativeVaultDrive();flow.vaultMountReady=true;flow.accountEpoch=0;await h.context.openNativeVaultDrive();flow.accountEpoch=1;flow.unlocked=false;await h.context.openNativeVaultDrive();assert.equal(h.calls.length,1);
});
test('absent mode preserves legacy vault RPC contract and pending response is rejected on mode transition',async()=>{
  const h=harness(false);assert.equal(h.context.vaultAppFeaturesAvailable(),true);
  await h.context.request('vault_list',{path:'/'});assert.equal(h.calls[0].message.action,'vault_list');
  let complete;h.context.invoke=()=>new Promise(resolve=>{complete=resolve;});const pending=h.context.request('vault_pins');h.state.status.vault_access_mode='native_read_only';complete({items:[]});await assert.rejects(pending);
  await assert.rejects(h.context.vaultSecretRequest({action:'vault_create'}),/unavailable/);
  h.state.status.vault_access_mode=undefined;const secretPending=h.context.vaultSecretRequest({action:'vault_create'});h.state.status.vault_access_mode='native_read_only';complete({created:true});await assert.rejects(secretPending);
});

test('native mode suppresses stale/programmatic copy and retry handlers and timer creation',async()=>{
  const h=harness();let timers=0;const cleared=[];
  h.context.window={setTimeout:()=>{timers++;return 999;},clearTimeout:id=>cleared.push(id)};
  h.context.interruptedCreateRetryUi={timer:22};h.context.clearCopyProducerTimer=()=>cleared.push(33);
  const job={timer:11};
  for(const name of ['copyVerifyBindingCurrent','interruptedCreateRetryContextCurrent','currentCopyProducerContext'])assert.equal(h.context[name]({}),false);
  for(const name of ['verifyCopyOperation','pollCopyVerification','checkCopyVerificationStatus','cancelCopyVerification','retryInterruptedFileCreate','pollInterruptedCreateRetry','pollCopyProducer'])await h.context[name]({});
  h.context.scheduleCopyVerifyPoll(job);h.context.scheduleInterruptedCreateRetryPoll({});h.context.scheduleCopyProducerPoll({},1);
  assert.equal(timers,0);assert.deepEqual(cleared,[11,22,33]);assert.equal(job.timer,0);assert.equal(h.context.interruptedCreateRetryUi.timer,0);assert.deepEqual(h.calls,[]);
  assert.match(h.context.nativeVaultDrivePanel({vaultMountReady:false},false),/Close and reopen this dialog/);
});


test('limited native saves never enable namespace actions or stale capability copy',async()=>{
  const h=harness();const flow=h.state.vaultDialog;
  flow.vaultMountExistingFileInPlace=true;
  const panel=h.context.nativeVaultDrivePanel(flow,false);
  assert.match(panel,/supported file saves/);
  assert.match(panel,/512 KiB/);
  assert.match(panel,/Editors that replace files/);
  assert.match(panel,/offline edits are not supported/);
  assert.doesNotMatch(panel,/can queue supported file edits/);
  await assert.rejects(h.context.request('vault_create'),/unavailable/);
  await assert.rejects(h.context.request('vault_move'),/unavailable/);
  flow.statusUnknown=true;
  assert.doesNotMatch(h.context.nativeVaultDrivePanel(flow,false),/512 KiB/);
  flow.statusUnknown=false;flow.unlocked=false;
  assert.doesNotMatch(h.context.nativeVaultDrivePanel(flow,false),/512 KiB/);
  flow.unlocked=true;h.state.status.connected=false;
  assert.doesNotMatch(h.context.nativeVaultDrivePanel(flow,false),/512 KiB/);
  h.state.status.connected=true;h.state.status.mounted=false;
  assert.doesNotMatch(h.context.nativeVaultDrivePanel(flow,false),/512 KiB/);
  h.state.status.mounted=true;flow.vaultMountExistingFileInPlace=false;
  assert.match(h.context.nativeVaultDrivePanel(flow,false),/Files cannot be edited here/);
  assert.deepEqual(h.calls,[]);
});

function enableBrowse(h) {
  Object.assign(h.state.status,{vault_in_app_browse_supported:true,auth_generation:7});
  Object.assign(h.state.vaultDialog,{rootResourceId:'root-id',rootPath:'/private.vault',spaceId:'space-a',rootEtag:'"root"',path:'/',entries:[],directoryBindings:new Map(),currentDirectoryBinding:null,offlineUnlockOnly:false});
  return h.state.vaultDialog;
}
test('Windows browsing capability only admits online current ready vault_list',async()=>{
  const h=harness();const flow=enableBrowse(h);
  assert.equal(h.context.nativeVaultBrowseAvailable(flow),true);
  assert.equal(h.context.vaultAppFeaturesAvailable(),false);
  for(const action of ['vault_create','vault_move','vault_pins','vault_reconcile_edits_start','vault_cached_roots','encrypted_edit_recoveries'])await assert.rejects(h.context.request(action),/unavailable/);
  for(const [object,key,value] of [[h.state.status,'vault_in_app_browse_supported',false],[h.state.status,'connected',false],[h.state.status,'offline',true],[h.state.status,'mounted',false],[h.state.status,'auth_generation',NaN],[h.state.status,'auth_generation',-1],[h.state,'accountSwitching',true],[flow,'offlineUnlockOnly',true],[flow,'statusUnknown',true],[flow,'unlocked',false],[flow,'vaultMountReady',false],[flow,'accountEpoch',0],[flow,'generation',1]]) {
    const prior=object[key];object[key]=value;
    assert.equal(h.context.nativeVaultBrowseAvailable(flow),false,key);
    await assert.rejects(h.context.request('vault_list'),/unavailable/,key);
    object[key]=prior;
  }
  assert.deepEqual(h.calls,[]);
});
test('actual list controller navigates root and subfolders with Windows generation only',async()=>{
  for(const native of [true,false]){
    const h=harness(native);const flow=enableBrowse(h);
    h.context.invoke=async(command,args)=>{h.calls.push({command,...args});return [{path:'/folder',directory:true,id:'folder-id',etag:'"folder"'}];};
    await h.context.loadVaultPath(flow,'/');
    assert.equal(flow.entries[0].path,'/folder');
    await h.context.loadVaultPath(flow,'/folder');
    assert.equal(flow.path,'/folder');
    assert.equal(h.calls.length,2);
    for(const call of h.calls){assert.equal(call.message.profile_id,'profile-a');assert.equal(call.message.root_resource_id,'root-id');assert.equal(call.message.expected_auth_generation,native?7:undefined);assert.equal(call.message.offline,undefined);}
    assert.deepEqual(h.calls.map(c=>c.message.path),['/','/folder']);
  }
});
test('list replies cannot restore names or bindings after lock, re-unlock, account or auth transitions',async()=>{
  for(const transition of ['lock','reunlock','account','auth','unknown']){
    const h=harness();const flow=enableBrowse(h);let finish;
    h.context.invoke=()=>new Promise(resolve=>{finish=resolve;});
    const pending=h.context.loadVaultPath(flow,'/');
    flow.directoryBindings.set('/old',{resourceId:'old',etag:'"old"'});
    if(transition==='account')h.state.accountEpoch++;
    else if(transition==='auth')h.state.status.auth_generation++;
    else {flow.statusUnknown=true;h.context.clearVaultBrowse(flow);flow.unlocked=false;if(transition==='reunlock'){flow.unlocked=true;flow.statusUnknown=false;}}
    h.context.invalidateUnavailableNativeVaultBrowse();
    finish([{path:'/secret-name',directory:true}]);await pending;
    assert.equal(flow.entries.length,0,transition);assert.equal(flow.directoryBindings.size,0,transition);assert.equal(flow.currentDirectoryBinding,null,transition);
  }
});
test('read-only rows escape names and paths and never expose unsupported controls',()=>{
  const h=harness();const flow=enableBrowse(h);
  flow.path='/folder';flow.entries=[{path:'/folder/<img src=x onerror="bad">',directory:true},{path:'/folder/<script>bad',directory:false,size:12}];
  const rows=h.context.vaultDirectoryRows(flow,false,false);
  assert.match(rows,/data-vault-path="\/"/);assert.match(rows,/&lt;img/);assert.match(rows,/&quot;bad&quot;/);assert.match(rows,/&lt;script&gt;/);assert.match(rows,/12 bytes/);
  assert.doesNotMatch(rows,/<img|<script|data-copy|data-vault-pin|data-vault-action|retry/);
  assert.match(h.context.vaultDirectoryRows(flow,true,false),/disabled/);
  assert.equal(h.context.vaultOfflinePinPanel(flow),'');assert.equal(h.context.vaultEditRetryPanel(flow),'');
  flow.statusUnknown=true;assert.equal(h.context.vaultDirectoryRows(flow,false,false),'');
});
