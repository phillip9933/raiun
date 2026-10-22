import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/provider-capabilities.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { loadProviderSyncData, providerAvailable, providerFeatureAvailable } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('disabled provider skips unsupported sync collection requests', async () => {
  const requests = [];
  const result = await loadProviderSyncData(false, true, async action => {
    requests.push(action);
    throw new Error(`unsupported action: ${action}`);
  });

  assert.deepEqual(result, { pairs: [], transfers: [] });
  assert.deepEqual(requests, []);
  assert.equal(providerAvailable(false), false);
});

test('an omitted capability keeps the existing Linux refresh behavior', async () => {
  const requests = [];
  const result = await loadProviderSyncData(undefined, true, async action => {
    requests.push(action);
    return action === 'pairs' ? [{ id: 'pair-1' }] : [{ id: 'transfer-1' }];
  });

  assert.deepEqual(requests, ['pairs', 'transfers']);
  assert.deepEqual(result, {
    pairs: [{ id: 'pair-1' }],
    transfers: [{ id: 'transfer-1' }]
  });
  assert.equal(providerAvailable(undefined), true);
});

test('feature flags constrain drive capability while omissions retain Linux behavior', () => {
  assert.equal(providerFeatureAvailable(true, false), false);
  assert.equal(providerFeatureAvailable(false, true), false);
  assert.equal(providerFeatureAvailable(true, undefined), true);
  assert.equal(providerFeatureAvailable(undefined, undefined), true);
});
test('drive-only agent skips unsupported pairs/transfers without hiding its provider', async () => {
  const requests=[];
  const data=await loadProviderSyncData(true,true,async action=>{requests.push(action);return [];},false);
  assert.equal(providerAvailable(true),true);
  assert.deepEqual(data,{pairs:[],transfers:[]});
  assert.deepEqual(requests,[]);
});

const mainSource = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const parsed = ts.createSourceFile('main.ts',mainSource,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const names = ['featureAvailable','isWindowsAgentStatus','windowsSignInPending','loadSpaces','savePair','addAccount','switchAccount','toggleSpacePause','queueSpaceSync','disconnectSpaceFolderSync'];
const extracted = parsed.statements.filter(node=>ts.isFunctionDeclaration(node)&&names.includes(node.name?.text)).map(node=>node.getFullText(parsed)).join('\n');
const inert = ts.transpileModule(extracted,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText;
const { default: vm } = await import('node:vm');
test('actual feature callers refuse unsupported operations but still identify enabled Windows sign-in', async () => {
  const status={provider_supported:true,connected:true,profile_label:'This PC',root_configuration:null,authenticating:true,
    folder_sync_supported:false,media_jobs_supported:false,vaults_supported:false,account_switch_supported:false,pause_supported:false};
  const state={status}; const context={state,providerFeatureAvailable,isTauri:()=>false};
  vm.runInNewContext(inert,context);
  assert.equal(context.isWindowsAgentStatus(status),true);
  assert.equal(context.windowsSignInPending(),true);
  for(const name of ['loadSpaces','savePair','addAccount','switchAccount','toggleSpacePause','queueSpaceSync','disconnectSpaceFolderSync']) await context[name]('synthetic');
  // No request/UI dependency was installed: reaching any unsupported body would throw.
  state.status={provider_supported:true};
  for(const field of ['folder_sync_supported','media_jobs_supported','vaults_supported','account_switch_supported','pause_supported']) assert.equal(context.featureAvailable(field),true);
});
