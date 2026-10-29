import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const presentationSource = await readFile(new URL('../src/transfer-presentation.ts', import.meta.url), 'utf8');
const presentation = await import(`data:text/javascript;base64,${Buffer.from(ts.transpileModule(presentationSource, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText).toString('base64')}`);
const page = main.slice(main.indexOf('function transfersPage()'), main.indexOf('function validateVaultEditLatest('));
const card = main.slice(main.indexOf('function transferCard('), main.indexOf('async function loadPendingOfflineWrites('));
const script = ts.transpileModule(page + card, {compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const escape = text => String(text).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
function view(filter, transfers, connected = true) {
  const context = vm.createContext({
    ...presentation,
    state: {transferFilter:filter,transfers,agentReachable:true,status:{connected}},
    featureAvailable:()=>true, connectionMode:()=>connected?'connected':'offline_reconnecting',
    isWindowsAgentStatus:()=>false, pendingOfflineWritesSection:()=>'<div>Separate retained edits</div>',
    vaultAppFeaturesAvailable:()=>false, connectionFailureDetails:()=>'', esc:escape,
    svg:name=>`<span>${name}</span>`, lastPath:path=>path.split('/').at(-1),
    selectedAccountLabel:()=> 'Synthetic account', spaceName:()=> 'Synthetic space', formatBytes:n=>`${n} bytes`
  });
  vm.runInContext(script, context);
  return vm.runInContext('transfersPage()', context);
}
const rows = [
  {id:1,path:'/queued.txt',state:'queued',direction:'upload'},
  {id:2,path:'/checking.txt',state:'verifying',direction:'download'},
  {id:3,path:'/future.txt',state:'future_state',direction:'sideways'},
  {id:4,path:'/cancelled.txt',state:'cancelled',direction:'download'},
  {id:5,path:'/<unsafe>.txt',state:'failed',error:'<script>bad</script>'}
];
test('visible folder-sync filters retain unknown states and keep recovery outside each filter',()=>{
  const active=view('active',rows), attention=view('attention',rows), history=view('history',rows);
  assert.match(active,/Checking cloud copy/);
  assert.doesNotMatch(active,/future\.txt/);
  assert.match(attention,/future\.txt/);
  assert.match(attention,/Status unavailable/);
  assert.match(attention,/Direction unavailable/);
  assert.doesNotMatch(attention,/arrowDown/);
  assert.match(attention,/&lt;unsafe&gt;\.txt/);
  assert.match(attention,/&lt;script&gt;bad&lt;\/script&gt;/);
  assert.match(history,/Cancelled/);
  assert.match(history,/does not mean the cloud copy completed/);
  for(const html of [active,attention,history]) assert.match(html,/Separate retained edits/);
});
test('counts and pressed filter describe actual rows, and disconnects do not present stale counts as current',()=>{
  const html=view('attention',rows);
  assert.match(html,/data-filter="attention" aria-pressed="true">Needs attention<span class="tab-badge">2/);
  assert.doesNotMatch(html,/role="tablist"/);
  assert.doesNotMatch(view('active',rows,false),/tab-badge/);
  assert.match(view('history',[]),/No folder-sync transfer history/);
});
