import { test } from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';

const source = await import('node:fs/promises').then(fs => fs.readFile(new URL('../src/folder-workspace.ts', import.meta.url), 'utf8'));
const compiled = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const { folderCreationRoute, folderWorkspaceSpaceIds } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('shared folder choices route to existing pair modes or the media import API', () => {
  assert.deepEqual(folderCreationRoute('both_ways', 'review'), {kind:'pair',mode:'two_way'});
  assert.deepEqual(folderCreationRoute('to_cloud', 'update_safe'), {kind:'pair',mode:'upload_only'});
  assert.deepEqual(folderCreationRoute('from_cloud', 'review'), {kind:'pair',mode:'download_only'});
  assert.deepEqual(folderCreationRoute('to_cloud', 'review'), {kind:'media_import'});
});

test('shared Space list retains separate pair and media import identities', () => {
  const pairs = [{id:'pair-42',space_id:'space-team'}];
  const imports = [{id:'job-91',revision:8,space_id:'space-personal'}];
  const spaces = [{id:'space-team',personal:false},{id:'space-personal',personal:true}];
  assert.deepEqual(folderWorkspaceSpaceIds(pairs.map(item=>item.space_id),imports.map(item=>item.space_id),spaces),['space-personal','space-team']);
});
