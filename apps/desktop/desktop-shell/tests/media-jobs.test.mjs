import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import vm from 'node:vm';
const source = await readFile(new URL('../src/media-jobs.ts', import.meta.url), 'utf8');
const folderSettingsSource = await readFile(new URL('../src/folder-settings.ts', import.meta.url), 'utf8');
const folderSettingsCompiled = ts.transpileModule(folderSettingsSource, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const folderSettingsUrl = `data:text/javascript;base64,${Buffer.from(folderSettingsCompiled).toString('base64')}`;
const executableSource = source.replace("from './folder-settings'", `from '${folderSettingsUrl}'`);
const compiled = ts.transpileModule(executableSource, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const { MediaJobsView } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
function setup(request, supportsVerifyUpload) {
  let account = 'A'; let busy = 0;
  const view = new MediaJobsView({supportsVerifyUpload,key:()=>account,connected:()=>true,reachable:()=>true,supported:()=>true,settingsSupported:()=>true,blocked:()=>busy>0,spaces:()=>[],request,chooseSource:async()=>null,confirm:async()=>true,busy:value=>{busy+=value?1:-1;},render:()=>{}});
  return {view,switchAccount:()=>{account='B';view.reset();},busy:()=>busy};
}
test('late account-A list cannot appear in account B', async()=>{
  let resolve;
  const response = new Promise(done=>{resolve=done;});
  const {view,switchAccount}=setup(()=>response);
  const pending=view.refresh(); switchAccount();
  resolve({jobs:[{job:{id:'a',source_root:'/private-A',destination_root:'/A',enabled:true},status:null,queued:false,active_account:true}]});
  await pending;
  assert.doesNotMatch(view.html(), /private-A/);
});
test('mutation error survives a successful status refresh and busy state clears',async()=>{
  const {view,busy}=setup(async()=>({jobs:[]}));
  await view.mutate(async()=>{throw new Error('Destination changed; choose it again');});
  assert.match(view.html(),/Destination changed; choose it again/);
  assert.equal(busy(),0);
});
test('queued backup is never labeled as an uploaded completion',async()=>{
  const {view}=setup(async()=>({jobs:[{job:{id:'a',source_root:'/Photos',destination_root:'/Photos',enabled:true},status:null,queued:true,active_account:true}]}));
  await view.refresh();
  assert.match(view.html(),/Queued/);
  assert.doesNotMatch(view.html(),/\d+ uploaded/);
});
test('source and provider error text is escaped in the page',async()=>{
  const {view}=setup(async()=>({jobs:[{job:{id:'a',source_root:'/<script>',destination_root:'/Photos',enabled:true},status:{state:'failed',uploaded:0,unchanged:0,waiting_for_stability:0,conflicts:0,needs_attention:1,last_error:'<img onerror=x>'},queued:false,active_account:true}]}));
  await view.refresh();
  assert.doesNotMatch(view.html(),/<script>|<img onerror/);
  assert.match(view.html(),/&lt;img onerror=x&gt;/);
});
test('job actions carry the displayed revision rather than changing newer settings blindly',async()=>{
  const calls=[];
  const job={id:'a',revision:7,account_id:'subject-a',source_root:'/Photos',destination_root:'/Photos',enabled:true};
  const {view}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_jobs'?{jobs:[{job,status:null,queued:false,active_account:true}]}:{accepted:true};});
  await view.refresh();
  let click;
  const button={dataset:{mediaRun:'a'},addEventListener:(_event,handler)=>{click=handler;}};
  view.bind({querySelector:()=>null,querySelectorAll:()=>[button]});
  click();
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(calls.find(([action])=>action==='media_job_run')[1],{job_id:'a',expected_revision:7,expected_account_id:'subject-a'});
});
test('account switch during shared-folder destination lookup cannot create a job for another account',async()=>{
  let resolve; const lookup=new Promise(done=>{resolve=done;}); const calls=[];
  const {view,switchAccount}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_destination'?lookup:{jobs:[]};});
  const pending=view.createFromFolder({source:'/Photos',space:'space-a',destination:'/Backups',filter:'photos',organization:'preserve_relative_path',interval:'3600'},()=>{});switchAccount();resolve({id:'root-a',space_id:'space-a',path:'/Backups',account_id:'A'});await pending;
  assert.equal(calls.some(([action])=>action==='media_job_set'),false);
});
test('shared Add folder review route creates a media job with the selected destination and options',async()=>{
  const calls=[];let closed=0;
  const {view}=setup(async(action,args)=>{calls.push([action,args]);if(action==='media_destination')return {id:'resource-7',path:'/Archive',space_id:'space-2',account_id:'cloud-account-92'};return {jobs:[]};});
  const created=await view.createFromFolder({source:'/home/photos',space:'space-2',destination:'/Archive',filter:'videos',organization:'utc_year_month',interval:'900'},()=>closed++);
  assert.equal(created,true);assert.equal(closed,1);
  assert.deepEqual(calls[0],['media_destination',{space_id:'space-2',path:'/Archive'}]);
  const [,set]=calls.find(([action])=>action==='media_job_set');
  assert.equal(set.job.source_root,'/home/photos');assert.equal(set.job.destination_root,'/Archive');
  assert.equal(set.job.space_id,'space-2');assert.equal(set.job.filter,'videos');
  assert.equal(set.job.account_id,'cloud-account-92');assert.equal(set.expected_account_id,'cloud-account-92');
  assert.equal(set.job.organization,'utc_year_month');assert.equal(set.job.filesystem_mtime_utc,true);
  assert.equal(set.job.interval_seconds,900);assert.equal(set.expected_revision,0);
  assert.equal(calls.some(([action])=>action==='pair_add'),false);
});
test('shared Add folder media route rejects a destination response for another Space',async()=>{
  const calls=[];let closed=0;
  const {view}=setup(async(action,args)=>{calls.push([action,args]);if(action==='media_destination')return {id:'resource-7',path:'/Archive',space_id:'other-space',account_id:'A'};return {jobs:[]};});
  const created=await view.createFromFolder({source:'/home/photos',space:'space-2',destination:'/Archive',filter:'photos',organization:'preserve_relative_path',interval:'3600'},()=>closed++);
  assert.equal(created,false);assert.equal(closed,0);
  assert.equal(calls.some(([action])=>action==='media_job_set'),false);
  assert.match(view.html(),/did not match this Space/);
});
test('shared Add folder keeps creation errors visible for this account and clears them on retry',async()=>{
  const calls=[];let fail=true;let closed=0;
  const {view}=setup(async(action,args)=>{
    calls.push([action,args]);
    if(action==='media_destination'&&fail)throw new Error('Destination folder changed. Choose it again.');
    if(action==='media_destination')return {id:'resource-7',path:'/Archive',space_id:'space-2',account_id:'cloud-account-92'};
    return {jobs:[]};
  });
  const draft={source:'/home/photos',space:'space-2',destination:'/Archive',filter:'all',organization:'preserve_relative_path',interval:'3600'};
  assert.equal(await view.createFromFolder(draft,()=>closed++),false);
  assert.equal(view.folderCreationError('A'),'Destination folder changed. Choose it again.');
  assert.equal(view.folderCreationError('B'),'');
  assert.equal(closed,0);
  fail=false;
  assert.equal(await view.createFromFolder(draft,()=>closed++),true);
  assert.equal(view.folderCreationError('A'),'');
  assert.equal(closed,1);
  assert.equal(calls.filter(([action])=>action==='media_job_set').length,1);
});
test('a backup from another signed-in identity cannot queue a run',async()=>{
  const calls=[];
  const job={id:'old',revision:3,account_id:'old-user',source_root:'/Photos',destination_root:'/Backup',enabled:true};
  const {view}=setup(async(action,args)=>{calls.push([action,args]);return {jobs:[{job,status:null,queued:false,active_account:false}]};});
  await view.refresh();
  assert.match(view.html(),/Different signed-in account/);
  let click;
  view.bind({querySelector:()=>null,querySelectorAll:()=>[{dataset:{mediaRun:'old'},addEventListener:(_event,handler)=>{click=handler;}}]});
  click();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(calls.some(([action])=>action==='media_job_run'||action==='media_job_remove'),false);
});

function recoveryDom(jobId='backup') {
  const listeners = {};
  const inspect = {dataset:{mediaRecovery:jobId},addEventListener:(name,handler)=>{listeners.inspect=handler;}};
  const more = {dataset:{},addEventListener:(name,handler)=>{listeners.more=handler;}};
  return {listeners,root:{querySelector:selector=>selector==='[data-media-recovery-more]'?more:null,querySelectorAll:selector=>selector==='[data-media-recovery]'?[inspect]:[]}};
}
const recoveryJob = {id:'backup',revision:4,account_id:'account-a',source_root:'/private/photos',destination_root:'/Backup',enabled:true};
const recoveryRow = {job:recoveryJob,status:null,queued:false,active_account:true};
function recoveryResponse(items=[],overrides={}) {
  return {job_id:'backup',account_id:'account-a',revision:4,page:{items,has_more:false,next_cursor:null,account_has_unindexed_stage:false,...overrides}};
}
test('read-only retained-copy inspection shows an explicit empty result and only reads recovery IPC',async()=>{
  const calls=[];
  const {view}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_jobs'?{jobs:[recoveryRow]}:recoveryResponse();});
  await view.refresh();
  const dom=recoveryDom();view.bind(dom.root);dom.listeners.inspect();await new Promise(resolve=>setImmediate(resolve));
  const html=view.html();
  assert.match(html,/Hide retained copies/);
  assert.match(html,/No retained copies or unresolved upload records were found/);
  assert.match(html,/Read-only inspection/);
  assert.deepEqual(calls.find(([action])=>action==='media_job_recovery')[1],{job_id:'backup',expected_revision:4,expected_account_id:'account-a',limit:100,cursor:null});
  assert.deepEqual(calls.map(([action])=>action),['media_jobs','media_job_recovery']);
});
test('recovery inspection paginates by opaque cursor and labels unknown legacy revisions',async()=>{
  const calls=[];
  const cursor={origin:'https://dav.test',space_id:'space-a',source_root:'/private',source_relative_path:'Camera/a.jpg',destination_path:'/Backup/a.jpg'};
  const item={origin:'https://dav.test',space_id:'space-a',source_root:'/private',source_relative_path:'<img onerror=x>',destination_path:'/<script>',state:'stage_only',configuration_revision:null,attempt_generation:null,source_size:12,updated_unix:null,staged_copy_present:true,staged_copy_size:12,stage_generation:2};
  const {view}=setup(async(action,args)=>{calls.push([action,args]);if(action==='media_jobs')return {jobs:[recoveryRow]};return calls.filter(([name])=>name==='media_job_recovery').length===1?recoveryResponse([item],{has_more:true,next_cursor:cursor,account_has_unindexed_stage:true}):recoveryResponse([{...item,source_relative_path:'second.jpg',configuration_revision:4}]);});
  await view.refresh();
  const dom=recoveryDom();view.bind(dom.root);dom.listeners.inspect();await new Promise(resolve=>setImmediate(resolve));
  assert.match(view.html(),/Legacy or unbound revision/);
  assert.match(view.html(),/Some local recovery data could not be safely matched/);
  assert.doesNotMatch(view.html(),/<img onerror=x>|<script>/);
  assert.match(view.html(),/&lt;img onerror=x&gt;/);
  const moreDom=recoveryDom();view.bind(moreDom.root);moreDom.listeners.more();await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(calls.filter(([action])=>action==='media_job_recovery')[1][1].cursor,cursor);
  assert.match(view.html(),/second.jpg/);
  assert.equal(calls.filter(([action])=>action==='media_job_recovery').every(([,args])=>args.limit===100),true);
});
test('recovery errors are visible and account switching discards a late page',async()=>{
  const {view,switchAccount}=setup(async(action)=>action==='media_jobs'?{jobs:[recoveryRow]}:Promise.reject(new Error('Recovery is unavailable')));
  await view.refresh();const dom=recoveryDom();view.bind(dom.root);dom.listeners.inspect();await new Promise(resolve=>setImmediate(resolve));
  assert.match(view.html(),/Could not inspect retained copies: Recovery is unavailable/);

  let resolve;const pending=new Promise(done=>{resolve=done;});
  const switched=setup(async(action)=>action==='media_jobs'?{jobs:[recoveryRow]}:pending);
  await switched.view.refresh();const raceDom=recoveryDom();switched.view.bind(raceDom.root);raceDom.listeners.inspect();switched.switchAccount();
  resolve(recoveryResponse([{source_root:'/private',source_relative_path:'late.jpg',destination_path:'/Backup',state:'uncertain',configuration_revision:4,staged_copy_present:true,staged_copy_size:8,source_size:8}]));
  await new Promise(done=>setImmediate(done));
  assert.doesNotMatch(switched.view.html(),/late\.jpg|retained copies/);
});
test('a late recovery page cannot appear after the saved job revision changes',async()=>{
  let resolveRecovery;
  const pending=new Promise(done=>{resolveRecovery=done;});
  let job={...recoveryJob};
  const {view}=setup(async(action)=>action==='media_jobs'?{jobs:[{...recoveryRow,job}]}:pending);
  await view.refresh();const dom=recoveryDom();view.bind(dom.root);dom.listeners.inspect();
  job={...job,revision:5};await view.refresh();
  resolveRecovery(recoveryResponse([{source_root:'/private',source_relative_path:'stale.jpg',destination_path:'/Backup',state:'uncertain',configuration_revision:4,staged_copy_present:true,staged_copy_size:8,source_size:8}]));
  await new Promise(done=>setImmediate(done));
  assert.doesNotMatch(view.html(),/stale\.jpg/);
});


const verifiableItem = {origin:'https://cloud.test',space_id:'space-a',source_root:'/private/photos',source_relative_path:'Camera/a.jpg',destination_path:'/Backup/Camera/a.jpg',state:'uncertain',configuration_revision:4,attempt_generation:2,upload_verification_available:true,source_size:12,updated_unix:10,staged_copy_present:true,staged_copy_size:12,stage_generation:2};
async function openVerifiable(view) {
  await view.refresh(); const dom = recoveryDom(); view.bind(dom.root); dom.listeners.inspect(); await new Promise(resolve=>setImmediate(resolve));
}
test('explicit upload verification carries exact retained attempt and never resumes or clears it',async()=>{
  const calls=[];
  const {view}=setup(async(action,args)=>{
    calls.push([action,args]);
    if(action==='media_jobs') return {jobs:[recoveryRow]};
    if(action==='media_job_recovery') return recoveryResponse([verifiableItem]);
    return {job_id:'backup',account_id:'account-a',revision:4,attempt_generation:2,source_relative_path:verifiableItem.source_relative_path,destination_path:verifiableItem.destination_path,status:'matched',recovery_retained:true,backup_resumed:false};
  });
  await openVerifiable(view);
  assert.match(view.html(),/Verify uploaded copy/);
  assert.equal(calls.length,2);
  await view.verifyUploadedCopy(0);
  assert.deepEqual(calls.at(-1),['media_job_verify_upload',{job_id:'backup',expected_account_id:'account-a',expected_revision:4,attempt_generation:2,source_relative_path:verifiableItem.source_relative_path,destination_path:verifiableItem.destination_path}]);
  assert.equal(calls.length,3);
  assert.match(view.html(),/uploaded copy matches/);
  assert.match(view.html(),/Backup has not resumed; retained recovery is still kept/);
  assert.match(view.html(),/Retained copy present/);
});
test('verification refuses legacy, stale revision and running items without making requests',async()=>{
  const calls=[];
  const {view}=setup(async(action)=>{calls.push(action);return action==='media_jobs'?{jobs:[recoveryRow]}:recoveryResponse([verifiableItem]);});
  await openVerifiable(view);
  for(const change of [{upload_verification_available:false},{configuration_revision:3},{attempt_generation:null}]) {
    view.recovery.items=[{...verifiableItem,...change}]; await view.verifyUploadedCopy(0); assert.doesNotMatch(view.html(),/Verify uploaded copy/);
  }
  view.recovery.items=[verifiableItem];view.rows=[{...recoveryRow,status:{state:'running'}}];await view.verifyUploadedCopy(0);
  assert.deepEqual(calls,['media_jobs','media_job_recovery']);
});
test('late verification cannot surface after account or job revision changes',async()=>{
  for(const change of ['account','revision']) {
    let resolve;const pending=new Promise(done=>{resolve=done;});
    const {view,switchAccount}=setup(async(action)=>action==='media_jobs'?{jobs:[recoveryRow]}:action==='media_job_recovery'?recoveryResponse([verifiableItem]):pending);
    await openVerifiable(view); const checking=view.verifyUploadedCopy(0);
    if(change==='account') switchAccount(); else view.rows=[{...recoveryRow,job:{...recoveryJob,revision:5}}];
    resolve({job_id:'backup',account_id:'account-a',revision:4,attempt_generation:2,source_relative_path:verifiableItem.source_relative_path,destination_path:verifiableItem.destination_path,status:'matched',recovery_retained:true,backup_resumed:false});
    await checking; assert.doesNotMatch(view.html(),/uploaded copy matches/);
  }
});
test('mismatched verification response cannot claim a matching copy',async()=>{
  const {view}=setup(async(action)=>action==='media_jobs'?{jobs:[recoveryRow]}:action==='media_job_recovery'?recoveryResponse([verifiableItem]):{job_id:'backup',account_id:'account-a',revision:4,attempt_generation:99,status:'matched',recovery_retained:true,backup_resumed:false});
  await openVerifiable(view);await view.verifyUploadedCopy(0);assert.doesNotMatch(view.html(),/uploaded copy matches/);assert.match(view.html(),/did not match this retained attempt/);
});

test('unsupported upload verification stays hidden and refuses stale or programmatic calls without blocking inspection',async()=>{
  let supported=false; const calls=[];
  const {view}=setup(async(action)=>{calls.push(action);return action==='media_jobs'?{jobs:[recoveryRow]}:recoveryResponse([verifiableItem]);},()=>supported);
  await openVerifiable(view);
  assert.match(view.html(),/Retained copy present/);
  assert.match(view.html(),/Hide retained copies/);
  assert.doesNotMatch(view.html(),/Verify uploaded copy/);
  await view.verifyUploadedCopy(0);
  supported=true; assert.match(view.html(),/Verify uploaded copy/);
  supported=false; await view.verifyUploadedCopy(0);
  assert.deepEqual(calls,['media_jobs','media_job_recovery']);
  assert.match(view.html(),/Retained copy present/);
  assert.doesNotMatch(view.html(),/uploaded copy matches/);
});

test('media empty state distinguishes reachable signed-out agent from unavailable agent', () => {
  let connected = false; let reachable = true;
  const view = new MediaJobsView({key:()=> 'A', connected:()=>connected, reachable:()=>reachable, supported:()=>true, blocked:()=>false, spaces:()=>[], request:async()=>{throw new Error('No requests expected');}, chooseSource:async()=>null, confirm:async()=>true, busy:()=>{}, render:()=>{}});
  assert.match(view.html(), /Sign in to your OpenCloud account to load and manage folder settings/);
  assert.doesNotMatch(view.html(), /Start the Raiun background agent/);
  reachable = false;
  assert.match(view.html(), /Start the Raiun background agent to load folder settings/);
  reachable = true; connected = true;
  assert.match(view.html(), /Refresh to load folder settings/);
});


test('Windows signed-out media refresh skips authenticated listing and discards an older load error; legacy disconnected reads remain', async () => {
  let connected = false; let reachable = true; let calls = 0; let reject;
  const context = {key:()=> 'A', connected:()=>connected, reachable:()=>reachable, supported:()=>true, blocked:()=>false, spaces:()=>[], request:async()=>{calls++;return new Promise((_resolve, fail)=>{reject=fail;});}, chooseSource:async()=>null, confirm:async()=>true, busy:()=>{}, render:()=>{}};
  const view = new MediaJobsView({...context, loadWhileDisconnected:()=>false});
  await view.refresh();
  assert.equal(calls, 0);
  assert.match(view.html(), /Sign in to your OpenCloud account to load and manage folder settings/);
  assert.doesNotMatch(view.html(), /folder sync|background agent|media-warning/);
  connected = true;
  const pending = view.refresh();
  assert.equal(calls, 1, 'connected Windows still loads jobs');
  connected = false;
  await view.refresh();
  reject(new Error('Sign in before using folder sync'));
  await pending;
  assert.doesNotMatch(view.html(), /folder sync|media-warning/);
  assert.match(view.html(), /Sign in to your OpenCloud account/);
  reachable = false;
  assert.match(view.html(), /Start the Raiun background agent to load folder settings/);
  const legacy = new MediaJobsView({...context, request:async()=>{calls++;return {jobs:[]};}});
  reachable = true;
  await legacy.refresh();
  assert.equal(calls, 2, 'omitting the policy retains Linux disconnected listing');
});

test('media folder edits stage locally, then save the frozen revision and account snapshot',async()=>{
  const calls=[];
  const job={id:'job-1',revision:9,account_id:'cloud-account',source_root:'/Camera',space_id:'space-1',destination_root:'/Photos',destination_root_resource_id:'root-1',filter:'all',organization:'preserve_relative_path',filesystem_mtime_utc:false,interval_seconds:3600,enabled:true,exclusions:[]};
  const {view}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_jobs'?{jobs:[{job,status:null,queued:false,active_account:true}]}:{};});
  await view.refresh();
  view.beginSettingsEdit('job-1');
  view.updateSettingsDraft('job-1',{filter:'photos'});
  assert.equal(calls.some(([action])=>action==='media_job_set'),false,'draft changes do not mutate the job');
  await view.saveSettingsEdit('job-1');
  const saved=calls.find(([action])=>action==='media_job_set');
  assert.equal(saved[1].expected_revision,9);
  assert.equal(saved[1].expected_account_id,'cloud-account');
  assert.equal(saved[1].job.filter,'photos');
  assert.equal(saved[1].job.source_root,'/Camera');
  assert.equal(saved[1].job.destination_root,'/Photos');
});
test('cancel discards a media settings draft without a request',async()=>{
  const calls=[];
  const job={id:'job-1',revision:9,account_id:'cloud-account',source_root:'/Camera',space_id:'space-1',destination_root:'/Photos',destination_root_resource_id:'root-1',filter:'all',organization:'preserve_relative_path',filesystem_mtime_utc:false,interval_seconds:3600,enabled:true};
  const {view}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_jobs'?{jobs:[{job,status:null,queued:false,active_account:true}]}:{};});
  await view.refresh();view.beginSettingsEdit('job-1');view.updateSettingsDraft('job-1',{filter:'videos'});
  assert.equal(view.cancelSettingsEdit('job-1'),true);
  assert.equal(calls.some(([action])=>action==='media_job_set'),false);
});
test('stale media settings save keeps the editor error and never retries with a refreshed revision',async()=>{
  const calls=[];let listings=0;
  const original={id:'job-1',revision:9,account_id:'cloud-account',source_root:'/Camera',space_id:'space-1',destination_root:'/Photos',destination_root_resource_id:'root-1',filter:'all',organization:'preserve_relative_path',filesystem_mtime_utc:false,interval_seconds:3600,enabled:true};
  const current={...original,revision:10,filter:'videos'};
  const {view}=setup(async(action,args)=>{calls.push([action,args]);if(action==='media_jobs')return {jobs:[{job:++listings===1?original:current,status:null,queued:false,active_account:true}]};throw new Error('revision conflict');});
  await view.refresh();view.beginSettingsEdit('job-1');view.updateSettingsDraft('job-1',{filter:'photos'});await view.refresh();
  assert.equal(await view.saveSettingsEdit('job-1'),false);
  const saves=calls.filter(([action])=>action==='media_job_set');
  assert.equal(saves.length,1);assert.equal(saves[0][1].expected_revision,9);assert.equal(saves[0][1].job.filter,'photos');
  assert.match(view.html(),/revision conflict/);
});
test('media folder drafts clear on account switch and cannot send to the new account',async()=>{
  const calls=[];
  const job={id:'job-1',revision:9,account_id:'cloud-account',source_root:'/Camera',space_id:'space-1',destination_root:'/Photos',destination_root_resource_id:'root-1',filter:'all',organization:'preserve_relative_path',filesystem_mtime_utc:false,interval_seconds:3600,enabled:true};
  const {view,switchAccount}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_jobs'?{jobs:[{job,status:null,queued:false,active_account:true}]}:{};});
  await view.refresh();view.beginSettingsEdit('job-1');view.updateSettingsDraft('job-1',{filter:'videos'});switchAccount();
  assert.equal(await view.saveSettingsEdit('job-1'),false);
  assert.equal(calls.some(([action])=>action==='media_job_set'),false);
});
