import { test } from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../src/folder-settings.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ES2022}}).outputText;
const { createPairSettingsDraft, discardPairSettingsDraft, normalizeFolderExclusion, pairSettingsUpdateRequest, persistedFolderPair, validateFolderExclusions } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('file type rules normalize extensions while path patterns retain Android glob semantics', () => {
  assert.deepEqual(normalizeFolderExclusion('file_type', 'tmp'), {rule:{kind:'file_type',pattern:'*.tmp'}});
  assert.deepEqual(normalizeFolderExclusion('file_type', '.tar.gz'), {rule:{kind:'file_type',pattern:'*.tar.gz'}});
  assert.deepEqual(normalizeFolderExclusion('file_type', '*.jpg'), {rule:{kind:'file_type',pattern:'*.jpg'}});
  for (const pattern of ['Camera/**/Thumbs.db', 'Drafts/*.txt', 'Generated/']) {
    assert.deepEqual(normalizeFolderExclusion('path', pattern), {rule:{kind:'path',pattern}});
  }
});

test('unsafe paths, malformed file types, duplicates, and bounded rule sets are rejected', () => {
  for (const pattern of ['/absolute', '../escape', 'Drafts/../secret', 'a\\b', 'empty//part']) {
    assert.ok(normalizeFolderExclusion('path', pattern).error, pattern);
  }
  assert.ok(normalizeFolderExclusion('file_type', 'dir/*.tmp').error);
  assert.ok(normalizeFolderExclusion('file_type', '*tmp').error);
  assert.equal(validateFolderExclusions([{kind:'file_type',pattern:'*.tmp'},{kind:'file_type',pattern:'*.tmp'}]), 'That exclusion rule is already listed.');
  assert.ok(validateFolderExclusions(Array.from({length:101},(_,index)=>({kind:'path',pattern:`rule-${index}`}))));
  assert.ok(validateFolderExclusions([{kind:'path',pattern:'a'.repeat(255)},{kind:'path',pattern:'b'.repeat(255)}].flatMap(rule=>Array(17).fill(rule))));
});

test('CAS snapshot preserves legacy exclusions and strips non-persisted fields', () => {
  const pair = persistedFolderPair({
    id:'pair-1',local_path:'/home/user/Photos',space_id:'space-7',vault:null,remote_path:'/Photos',mode:'upload_only',
    excluded_paths:['Old literal/Thumbs.db','legacy.glob'],content_filter:'videos',exclusions:[{kind:'file_type',pattern:'*.tmp'}],
    runtime_root:'/not-persisted',worker_revision:19
  });
  assert.deepEqual(pair,{
    id:'pair-1',local_path:'/home/user/Photos',space_id:'space-7',vault:null,remote_path:'/Photos',mode:'upload_only',
    excluded_paths:['Old literal/Thumbs.db','legacy.glob'],content_filter:'videos',exclusions:[{kind:'file_type',pattern:'*.tmp'}]
  });
});

test('pair settings drafts freeze the opened CAS snapshot, stage edits, and cancel without retaining a draft',()=>{
  const original={id:'pair-a',local_path:'/camera',space_id:'space-a',vault:null,remote_path:'/Photos',mode:'two_way',excluded_paths:['legacy/Keep.db'],content_filter:'all',exclusions:[],runtime_root:'/ignored'};
  const draft=createPairSettingsDraft(original,'profile-a',12,8);
  draft.mode='upload_only';draft.content_filter='photos';draft.exclusions.push({kind:'file_type',pattern:'*.tmp'});
  original.mode='download_only';original.content_filter='videos';original.excluded_paths.push('new-background-rule');
  const request=pairSettingsUpdateRequest('pair-a',draft);
  assert.equal(request.expected_auth_generation,8);
  assert.deepEqual(request.expected_pair,{id:'pair-a',local_path:'/camera',space_id:'space-a',vault:null,remote_path:'/Photos',mode:'two_way',excluded_paths:['legacy/Keep.db'],content_filter:'all',exclusions:[]});
  assert.equal(request.mode,'upload_only');assert.equal(request.content_filter,'photos');
  assert.deepEqual(request.exclusions,[{kind:'file_type',pattern:'*.tmp'}]);
  const editors=new Map([['pair-a',draft]]);
  assert.equal(discardPairSettingsDraft(editors,'pair-a'),true);
  assert.equal(editors.has('pair-a'),false);
});
