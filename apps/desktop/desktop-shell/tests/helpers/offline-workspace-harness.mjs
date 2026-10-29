import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

const storageSource = await readFile(new URL('../../src/offline-storage.ts', import.meta.url), 'utf8');
const storageApi = await import('data:text/javascript;base64,' + Buffer.from(ts.transpileModule(storageSource, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText).toString('base64'));
const main = await readFile(new URL('../../src/main.ts', import.meta.url), 'utf8');
const tree = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true);
const names = new Set(['offlineDisclosureKey', 'offlineRowOptions', 'offlineDetails', 'saveCacheLimit', 'cacheLimitScope', 'offlineStorageForm', 'offlineStorageSummary', 'offlineStoragePage', 'offlineActivityNotice', 'offlineWorkspacePage', 'offlinePickerBody', 'persistedOfflinePins', 'offlineEntryRow', 'folderPolicyControlsAvailable', 'folderPolicyCurrentControl', 'folderPolicyRowControls', 'offlineAvailabilityLabel', 'offlinePolicyKey', 'offlinePinsKey', 'offlinePinRemovalKey', 'validOfflineFolderPath', 'offlineFolderIsCurrent', 'formatBytes', 'keepOfflineFileFromView']);
const functions = tree.statements.filter(node => ts.isFunctionDeclaration(node) && names.has(node.name?.text));
if (functions.length !== names.size) throw new Error('Offline presentation function missing');
const icons = tree.statements.filter(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(decl => decl.name?.text === 'icon' || decl.name?.text === 'svg'));
const script = ts.transpileModule([...icons, ...functions].map(node => node.getText(tree)).join('\n'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;

export function offlineHarness({ windows = false, view = 'browse', kind = 'folders' } = {}) {
  const state = {
    page:'offline',accountEpoch:1, selectedAccount:'synthetic-account', accountSwitching:false,
    agentReachable:true, status:{auth_generation:3,connected:true,provider_supported:true,offline_cache:{available:true,used_bytes:800,pinned_bytes:500,protected_bytes:100,quota_bytes:2000,over_quota:false}},
    spaces:[{id:'space-a',name:'Personal',personal:true,encrypted:false}],spaceId:'space-a',spacesLoading:false,spacesError:'',
    pickerOpen:true,pickerPurpose:'offline',pickerPath:'/',pickerGeneration:1,pickerError:'',
    pickerEntries:[{id:'folder-a',path:'/Photos',directory:true,encrypted:false},{id:'file-a',path:'/Notes.txt',directory:false,encrypted:false,size:120}]
  };
  const offlineUi = {
    policies:new Map(),availabilityStates:new Map(),policyLoading:new Set(),policySaving:new Set(),folderPolicies:new Map(),folderPolicyLoading:new Map(),folderPolicySaving:new Map(),
    folderListing:{epoch:1,generation:1,spaceId:'space-a',path:'/'},pins:new Map(),pinsLoading:new Set(),pinsRemoving:new Set(),pin:null,error:''
  };
  const ui = {view,windowsKind:kind,disclosureScope:'',expanded:new Set()};
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fileController = {state:{loading:false,admissionUncertain:false,job:null}};
  const folderController = {controller:{state:{loading:false,admissionUncertain:false,job:null}}};
  const usage = {used_bytes:1234,quota_bytes:5000,pinned_bytes:400,protected_bytes:200,over_quota:false};
  const keepCalls = [], requests = [];
  const cacheLimitUi = {scope:'',amount:'',unit:'GiB',original:0,busy:false,error:'',notice:''};
  let rpcHandler = async (_action,args) => ({profile_id:state.selectedAccount,auth_generation:state.status.auth_generation,quota_bytes:args.quota_bytes,scope:windows?'device_all_accounts':'account',saved:true,eviction_performed:false});
  const context = vm.createContext({
    ...storageApi,cacheLimitUi,request:async(action,args)=>{requests.push({action,args});return rpcHandler(action,args);},render:()=>{},messageOf:e=>e.message||String(e),isStaleAccountRequest:()=>false,state,offlineUi,offlineWorkspaceUi:ui,windowsDeviceCacheUi:{usage},windowsOfflineFileController:fileController,windowsOfflineFoldersPanel:folderController,
    isWindowsAgentStatus:()=>windows,providerAvailable:value=>value===true,syncWindowsDeviceCacheContext:()=>({}),
    windowsDeviceCacheCard:()=>'<section class="settings-card"><h2>Storage on this device</h2><p>Shared by all accounts on this Windows device.</p><button class="button subtle" data-action="refresh-windows-device-cache">Refresh usage</button></section>',
    windowsOfflineFilesCard:()=>'<section class="settings-card windows-offline-files-card"><h2>Choose files to keep offline</h2><button class="button primary" data-action="start-windows-offline-file">Keep file offline</button></section>',
    windowsOfflineFoldersCard:()=>'<section class="settings-card windows-offline-folders-card"><h2>Choose folders to keep offline</h2><button class="button primary" data-action="start-windows-offline-folder">Keep folder offline</button></section>',
    isCurrentAccount:(epoch,profileId)=>epoch===state.accountEpoch && profileId===state.selectedAccount,
    setOfflinePolicy:async(path,policy)=>{keepCalls.push({path,policy});},
    esc:escape,formatBytes:value=>`${value} B`,
    lastPath:path=>path.split('/').filter(Boolean).at(-1)||'Root',parentPath:path=>path.slice(0,path.lastIndexOf('/'))||'/',windowsPortabilityNote:()=>''
  });
  vm.runInContext(script,context);
  return {state,offlineUi,ui,fileController,folderController,usage,keepCalls,cacheLimitUi,requests,setRpc:fn=>{rpcHandler=fn;},
    render:()=>vm.runInContext('offlineWorkspacePage()',context),
    call:(name,...args)=>context[name](...args)
  };
}
