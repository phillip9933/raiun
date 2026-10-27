import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
const source = await readFile(new URL('../src/media-jobs.ts', import.meta.url), 'utf8');
const folderSettingsSource = await readFile(new URL('../src/folder-settings.ts', import.meta.url), 'utf8');
const folderSettingsCompiled = ts.transpileModule(folderSettingsSource, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const folderSettingsUrl = `data:text/javascript;base64,${Buffer.from(folderSettingsCompiled).toString('base64')}`;
const executableSource = source.replace("from './folder-settings'", `from '${folderSettingsUrl}'`);
const compiled = ts.transpileModule(executableSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } });
assert.equal((compiled.diagnostics || []).filter(x => x.category === ts.DiagnosticCategory.Error).length, 0);
const { MediaJobsView } = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputText).toString('base64')}`);
const turn = () => new Promise(resolve => setImmediate(resolve));
async function harness() {
  let resolve, reject; const approval = new Promise((yes, no) => { resolve = yes; reject = no; });
  const model = { key: 'profile-a:7', reachable: true, supported: true, blocked: false, busy: 0,
    rows: [{ job: { id: 'backup-a', revision: 7, account_id: 'subject-a', source_root: '/SyntheticPhotos', destination_root: '/Backup', enabled: true }, status: null, queued: false, active_account: true }] };
  const calls = [], prompts = [];
  const view = new MediaJobsView({
    key: () => model.key, connected: () => true, reachable: () => model.reachable,
    supported: () => model.supported, blocked: () => model.blocked || model.busy > 0,
    spaces: () => [], chooseSource: async () => null, render() {},
    busy: value => { model.busy += value ? 1 : -1; },
    confirm: message => { prompts.push(message); return approval; },
    request: async (action, args) => { calls.push({ action, args: structuredClone(args) }); return action === 'media_jobs' ? { jobs: structuredClone(model.rows) } : { removed: true }; }
  });
  await view.refresh();
  let click;
  const button = { dataset: { mediaRemove: 'backup-a' }, addEventListener: (event, handler) => { assert.equal(event, 'click'); click = handler; } };
  view.bind({ querySelector: () => null, querySelectorAll: selector => selector === '[data-media-toggle],[data-media-run],[data-media-remove]' ? [button] : [] });
  assert.equal(typeof click, 'function', 'exercise the actual bound removal click');
  return { model, view, calls, prompts, click, resolve, reject, mutations: () => calls.filter(x => x.action === 'media_job_remove') };
}
test('actual bound media-remove click waits; false/rejection/truthy do not remove; true removes once', async t => {
  for (const [label, value] of [['Cancel', false], ['OK', true], ['truthy number', 1], ['truthy string', 'yes'], ['truthy object', {}]]) await t.test(label, async () => {
    const h = await harness(); h.click(); await turn(); assert.equal(h.prompts.length, 1); assert.equal(h.mutations().length, 0);
    h.resolve(value); await turn(); await turn();
    assert.equal(h.mutations().length, value === true ? 1 : 0); assert.equal(h.model.busy, 0);
    if (value === true) assert.deepEqual(h.mutations()[0].args, { job_id: 'backup-a', expected_revision: 7, expected_account_id: 'subject-a' });
  });
  const h = await harness(); h.click(); h.reject(new Error('synthetic dialog unavailable')); await turn();
  assert.equal(h.mutations().length, 0); assert.match(h.view.html(), /synthetic dialog unavailable/); assert.equal(h.model.busy, 0);
});
test('pending media approval rejects stale account, reset, revision and replacement identity', async t => {
  const changes = [
    ['account', async h => { h.model.key = 'profile-b:8'; }],
    ['view reset', async h => { h.view.reset(); }],
    ['job revision', async h => { h.model.rows[0].job.revision++; await h.view.refresh(); }],
    ['replacement job', async h => { h.model.rows[0].job.id = 'different-job'; await h.view.refresh(); }],
    ['replacement owner', async h => { h.model.rows[0].job.account_id = 'different-subject'; await h.view.refresh(); }],
    ['removed job', async h => { h.model.rows = []; await h.view.refresh(); }]
  ];
  for (const [name, change] of changes) await t.test(name, async () => {
    const h = await harness(); h.click(); assert.equal(h.mutations().length, 0); await change(h); h.resolve(true); await turn();
    assert.equal(h.mutations().length, 0); assert.equal(h.model.busy, 0);
  });
});
test('approval cannot remove a newly active job or bypass reachability/support/busy fences', async t => {
  const changes = [
    ['queued', async h => { h.model.rows[0].queued = true; await h.view.refresh(); }],
    ['running', async h => { h.model.rows[0].status = { state: 'running', uploaded: 0, unchanged: 0, waiting_for_stability: 0, conflicts: 0, needs_attention: 0 }; await h.view.refresh(); }],
    ['unreachable', async h => { h.model.reachable = false; }],
    ['unsupported', async h => { h.model.supported = false; }],
    ['blocked', async h => { h.model.blocked = true; }]
  ];
  for (const [name, change] of changes) await t.test(name, async () => {
    const h = await harness(); h.click(); await change(h); h.resolve(true); await turn(); assert.equal(h.mutations().length, 0);
  });
});
test('media confirmation uses the shared account helper rather than the global override', async () => {
  const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
  const tree = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let routed = false;
  const visit = n => { if (ts.isPropertyAssignment(n) && n.name.getText(tree) === 'confirm' && ts.isIdentifier(n.initializer) && n.initializer.text === 'confirmAccountAction') routed = true; ts.forEachChild(n, visit); };
  visit(tree); assert.ok(routed);
  const mediaTree = ts.createSourceFile('media-jobs.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const calls = []; const scan = n => { if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'confirm') calls.push(n); ts.forEachChild(n, scan); }; scan(mediaTree);
  assert.equal(calls.length, 0);
});
