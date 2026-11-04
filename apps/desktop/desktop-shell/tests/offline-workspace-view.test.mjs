import test from 'node:test';
import assert from 'node:assert/strict';
import { offlineHarness } from './helpers/offline-workspace-harness.mjs';

test('ordinary offline view puts files first, with advanced policies closed and storage help elsewhere',()=>{
  const h=offlineHarness(),html=h.render();
  assert.match(html,/Files &amp; folders|Files & folders/);
  assert.match(html,/Notes\.txt/);
  assert.match(html,/This account on this computer/);
  assert.match(html,/<button class="text-button offline-options-toggle"[^>]*aria-expanded="false"/);
  assert.doesNotMatch(html,/<details[^>]* open/);
  assert.doesNotMatch(html,/about every five minutes|Protected edits|Availability options explained/);
  assert.match(html,/data-pin-offline="\/Photos"/);
  assert.match(html,/data-keep-offline-file="\/Notes\.txt"/);
  assert.match(html,/data-set-folder-policy="cloud_only" data-folder-path="\/Photos" data-folder-listing-path="\/"/);
  assert.doesNotMatch(html,/data-action="delete/);
});

test('disclosure preferences are scoped to account and location and cannot open another account details',()=>{
  const h=offlineHarness();
  const html=h.call('offlineDetails','example','Options','content');
  const encoded=html.match(/data-offline-disclosure="([^"]+)"/)[1].replaceAll('&quot;','"');
  h.ui.expanded.add(encoded);
  assert.match(h.call('offlineDetails','example','Options','content'),/ open>/);
  h.state.spaceId='space-b';
  assert.doesNotMatch(h.call('offlineDetails','example','Options','content'),/ open>/);
  h.state.spaceId='space-a';h.state.selectedAccount='other-account';h.state.accountEpoch++;
  assert.doesNotMatch(h.call('offlineDetails','example','Options','content'),/ open>/);
  assert.equal(h.ui.expanded.size,0);
});

test('loading and unavailable storage are not reported as empty or zero and folder actions wait for a current listing',()=>{
  const h=offlineHarness();h.offlineUi.folderListing=null;h.state.pickerEntries=[];
  h.state.status.offline_cache.available=false;
  const html=h.render();
  assert.match(html,/Loading files/);assert.doesNotMatch(html,/This folder is empty|0 B/);
  assert.match(html,/Storage usage unavailable/);
  assert.match(html,/data-pin-offline="\/" disabled/);
});

test('a saved-folder problem remains visible outside the collapsed saved-folder list',()=>{
  const h=offlineHarness();h.offlineUi.pins.set(h.call('offlinePinsKey','space-a'),[{pin_id:'test-pin',root_resource_id:'folder-a',path:'/Photos',state:'unavailable',item_count:2,files_done:2,files_total:2}]);
  const html=h.render();
  assert.match(html,/1 saved folder copy needs review/);
  assert.match(html,/not available offline because the cloud location changed/);
  assert.match(html,/Cloud files stay unchanged/);
  assert.doesNotMatch(html,/No files.*saved/);
});

test('storage view keeps active download navigation and protected-data help, and omits the browser',()=>{
  const h=offlineHarness({view:'storage'});
  h.offlineUi.pin={accountEpoch:1,space_id:'space-a',path:'/Photos',state:'building'};
  const html=h.render();
  assert.match(html,/A folder download is in progress/);assert.match(html,/data-offline-active/);
  assert.match(html,/Protected edits/);assert.match(html,/never deletes the cloud file/);
  assert.doesNotMatch(html,/Notes\.txt/);
  h.state.accountEpoch++;
  assert.doesNotMatch(h.render(),/A folder download is in progress/);
});

test('Windows shows one picker at a time, identifies device-wide usage and exposes work hidden by the selected picker',()=>{
  const h=offlineHarness({windows:true});
  h.fileController.state.job={state:'running'};
  let html=h.render();
  assert.match(html,/This device · all accounts/);
  assert.match(html,/windows-offline-folders-card/);
  assert.doesNotMatch(html,/windows-offline-files-card/);
  assert.match(html,/file download has activity to review/);
  h.ui.windowsKind='files';html=h.render();
  assert.match(html,/windows-offline-files-card/);assert.doesNotMatch(html,/windows-offline-folders-card/);
  h.ui.view='storage';html=h.render();
  assert.match(html,/Shared by all accounts/);assert.match(html,/View download/);
});

test('file rendering escapes filenames and retains stale-versus-verified availability semantics',()=>{
  const h=offlineHarness();const file={...h.state.pickerEntries[1],path:'/<unsafe>.txt'};
  const key=h.call('offlinePolicyKey',file.path);
  h.offlineUi.policies.set(key,'always_offline');h.offlineUi.availabilityStates.set(key,'stale');
  const html=h.call('offlineEntryRow',file);
  assert.match(html,/&lt;unsafe&gt;/);assert.doesNotMatch(html,/<unsafe>/);
  assert.match(html,/previous verified copy is retained/);assert.doesNotMatch(html,/>Verified for offline use</);
});


test('one-click Keep offline uses the existing file path and rejects controls from an older account, listing or login',async()=>{
  const scope={epoch:1,profileId:'synthetic-account',spaceId:'space-a',generation:1,authGeneration:3};
  const noAccount=offlineHarness();
  await noAccount.call('keepOfflineFileFromView','/Notes.txt',{...scope,profileId:null});
  assert.equal(noAccount.keepCalls.length,0);
  const current=offlineHarness();
  await current.call('keepOfflineFileFromView','/Notes.txt',scope);
  assert.deepEqual(current.keepCalls,[{path:'/Notes.txt',policy:'always_offline'}]);
  for(const change of [
    h=>h.state.accountEpoch++, h=>h.state.selectedAccount='other', h=>h.state.spaceId='other-space',
    h=>h.state.pickerGeneration++, h=>h.state.status.auth_generation=2, h=>h.state.accountSwitching=true,
    h=>h.state.page='overview'
  ]){
    const h=offlineHarness();change(h);
    await h.call('keepOfflineFileFromView','/Notes.txt',scope);
    assert.equal(h.keepCalls.length,0);
  }
});


test('Options remains a sibling of the full-width panel when expanded and preserves its stable identity',()=>{
  const h=offlineHarness();
  const closed=h.call('offlineRowOptions','file:/Notes.txt','Options','<select></select>','Notes.txt');
  const key=closed.match(/data-offline-options="([^"]+)"/)[1].replaceAll('&quot;','"');
  h.ui.expanded.add(key);
  const opened=h.call('offlineRowOptions','file:/Notes.txt','Options','<select></select>','Notes.txt');
  assert.match(opened,/aria-expanded="true"/);
  assert.match(opened,/<\/button><div class="offline-options-panel"/);
  assert.doesNotMatch(opened,/<details| hidden/);
  assert.equal(closed.match(/aria-controls="([^"]+)"/)[1],opened.match(/aria-controls="([^"]+)"/)[1]);
  assert.match(closed,/ hidden>/);
  h.state.spaceId='another';
  assert.match(h.call('offlineRowOptions','file:/Notes.txt','Options','content','Notes.txt'),/aria-expanded="false"/);
});


test('saving a cache allowance uses explicit scoped IPC and updates UI only after the matching persisted acknowledgement',async()=>{
 const h=offlineHarness();h.call('offlineStorageForm',false);h.cacheLimitUi.amount='5';h.cacheLimitUi.unit='GiB';
 await h.call('saveCacheLimit',h.cacheLimitUi.scope);
 assert.equal(h.requests.length,1);assert.equal(h.requests[0].action,'cache_quota_set');
 assert.equal(h.requests[0].args.profile_id,'synthetic-account');assert.equal(h.requests[0].args.expected_auth_generation,3);
 assert.equal(h.state.status.offline_cache.quota_bytes,5*1024**3);assert.match(h.cacheLimitUi.notice,/No files were removed/);
});

test('invalid cache allowance and stale account scope cannot send a configuration change',async()=>{
 const h=offlineHarness();h.call('offlineStorageForm',false);const scope=h.cacheLimitUi.scope;
 h.cacheLimitUi.amount='-1';await h.call('saveCacheLimit',scope);assert.equal(h.requests.length,0);assert.match(h.cacheLimitUi.error,/amount/);
 h.cacheLimitUi.amount='5';h.state.accountEpoch++;await h.call('saveCacheLimit',scope);assert.equal(h.requests.length,0);
});

test('quota acknowledgement from an obsolete account is ignored and a wrong acknowledgement cannot report a save',async()=>{
 const h=offlineHarness();h.call('offlineStorageForm',false);h.cacheLimitUi.amount='5';h.cacheLimitUi.unit='GiB';let finish;
 h.setRpc(()=>new Promise(done=>finish=done));const pending=h.call('saveCacheLimit',h.cacheLimitUi.scope);
 h.state.selectedAccount='other';h.state.accountEpoch++;
 finish({profile_id:'synthetic-account',auth_generation:3,quota_bytes:5*1024**3,scope:'account',saved:true,eviction_performed:false});await pending;
 assert.equal(h.state.status.offline_cache.quota_bytes,2000);
 const wrong=offlineHarness();wrong.call('offlineStorageForm',false);wrong.cacheLimitUi.amount='5';wrong.cacheLimitUi.unit='GiB';wrong.setRpc(async()=>({profile_id:'other'}));
 await wrong.call('saveCacheLimit',wrong.cacheLimitUi.scope);assert.equal(wrong.state.status.offline_cache.quota_bytes,2000);assert.match(wrong.cacheLimitUi.error,/Could not confirm/);
});
