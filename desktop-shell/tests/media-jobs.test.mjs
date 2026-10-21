import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import vm from 'node:vm';
const source = await readFile(new URL('../src/media-jobs.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const { MediaJobsView } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
function setup(request) {
  let account = 'A'; let busy = 0;
  const view = new MediaJobsView({key:()=>account,connected:()=>true,reachable:()=>true,supported:()=>true,blocked:()=>busy>0,spaces:()=>[],request,chooseSource:async()=>null,confirm:async()=>true,busy:value=>{busy+=value?1:-1;},render:()=>{}});
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
test('account switch during destination lookup cannot create a job for another account',async()=>{
  let resolve; const lookup=new Promise(done=>{resolve=done;}); const calls=[];
  const {view,switchAccount}=setup(async(action,args)=>{calls.push([action,args]);return action==='media_destination'?lookup:{jobs:[]};});
  view.draft={source:'/Photos',space:'space-a',destination:'/Backups',filter:'photos',organization:'preserve_relative_path',interval:'3600'};
  const pending=view.create();switchAccount();resolve({id:'root-a',space_id:'space-a',path:'/Backups'});await pending;
  assert.equal(calls.some(([action])=>action==='media_job_set'),false);
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


test('actual media preview results name the complete status without mislabeling incomplete or truncated scans', async t => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const tree = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const wanted = new Set(['mediaResults', 'mediaStat', 'mediaPlanRow']);
  const declarations = tree.statements.filter(n => ts.isFunctionDeclaration(n) && n.name && wanted.has(n.name.text));
  assert.equal(declarations.length, wanted.size, 'execute the production result renderer and row/stat helpers');
  const helpers = tree.statements.filter(n => ts.isVariableStatement(n) && n.declarationList.declarations.some(d =>
    ts.isIdentifier(d.name) && ['esc', 'icon', 'svg'].includes(d.name.text)));
  assert.equal(helpers.length, 3, 'use the production escaping and decorative icon markup');
  const compiled = ts.transpileModule(`${helpers.map(n => n.getText(tree)).join('\n')}\n${declarations.map(n => n.getText(tree)).join('\n')}\nglobalThis.renderResults = mediaResults;`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None }
  });
  assert.equal((compiled.diagnostics || []).filter(d => d.category === ts.DiagnosticCategory.Error).length, 0);
  const context = {};
  vm.runInNewContext(compiled.outputText, context, { timeout: 1000 });
  const result = {
    complete: true, truncated: false, warnings: [], warnings_omitted: 0, rows_truncated: false,
    totals: { scanned: 2, sources: 1, planned: 1, filtered: 0, missing_date: 0, collisions: 0, rejected: 0 },
    rows: [{ source_relative_path: 'Camera/fixture.jpg', outcome: { planned: { destination_path: '/Photos/Camera/fixture.jpg' } } }]
  };
  for (const [complete, truncated] of [[true, false], [false, false], [true, true], [false, true]]) {
    await t.test(`complete=${complete}, truncated=${truncated}`, () => {
      const html = context.renderResults({ ...result, complete, truncated });
      const statuses = [...html.matchAll(/<div class="(media-complete|media-warning)" role="status"(?: aria-label="([^"]*)")?>([\s\S]*?)<\/div>/g)];
      assert.equal(statuses.length, 1, 'one semantic scan status accompanies the result');
      const success = complete && !truncated;
      assert.equal(statuses[0][1], success ? 'media-complete' : 'media-warning');
      assert.match(statuses[0][3], success
        ? /<span>Scan completed\. This is a local path preview only\.<\/span>/
        : /<span>Incomplete scan\. Review warnings; this preview may omit files\.<\/span>/);
      assert.doesNotMatch(statuses[0][3], success ? /Incomplete scan/ : /Scan completed/);
      const visibleMessage = statuses[0][3].match(/<span>([^<]*)<\/span>/)[1];
      assert.equal(statuses[0][2], success ? visibleMessage : undefined,
        'the complete accessible name equals its visible message; incomplete/truncated results never retain it');
      assert.ok(html.indexOf('media-summary') < html.indexOf(statuses[0][0]));
      assert.ok(html.indexOf(statuses[0][0]) < html.indexOf('<h2>Preview rows</h2>'));
      assert.match(html, /Scanned entries<\/span><b>2<\/b>/);
      assert.match(html, /Source files<\/span><b>1<\/b>/);
      assert.match(html, /Camera\/fixture\.jpg/);
      assert.match(html, /\/Photos\/Camera\/fixture\.jpg/);
    });
  }
  const limitedRows = context.renderResults({ ...result, rows_truncated: true, totals: { ...result.totals, sources: 2 } });
  assert.match(limitedRows, /class="media-complete" role="status" aria-label="Scan completed\. This is a local path preview only\."/);
  assert.match(limitedRows, /Showing the first 1 of 2 source rows\./, 'row display limits retain their separate warning');
});
