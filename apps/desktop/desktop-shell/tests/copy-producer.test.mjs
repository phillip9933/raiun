import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/copy-producer.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const {
  copyProducerContextKey,
  copyProducerContextMatches,
  validateCopyProducerStart,
  validateCopyProducerStatus,
  copyProducerStartErrorMessage,
  copyProducerStatusMessage
} = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

const context = () => ({
  profileId: 'profile-test',
  accountEpoch: 7,
  authGeneration: 11,
  flowGeneration: 2,
  source: {
    spaceId: 'space-source',
    rootResourceId: 'root-source',
    resourceId: 'file-source',
    version: 'etag-source-1',
    path: 'Documents/original.txt'
  },
  destination: {
    spaceId: 'space-destination',
    rootResourceId: 'root-destination',
    parentResourceId: 'folder-destination',
    parentVersion: 'etag-folder-4',
    targetPath: 'Copies/original.txt'
  }
});

const status = (extra = {}) => ({
  job_id: 'copy-job-1',
  auth_generation: 11,
  state: 'running',
  cancel_requested: false,
  ...extra
});

test('producer context fences profile, account, auth, source and destination identities and versions', () => {
  const expected = context();
  assert.equal(copyProducerContextMatches(expected, context()), true);
  for (const changed of [
    (c) => { c.profileId = 'other-profile'; },
    (c) => { c.accountEpoch += 1; },
    (c) => { c.authGeneration += 1; },
    (c) => { c.flowGeneration += 1; },
    (c) => { c.source.spaceId = 'other-space'; },
    (c) => { c.source.rootResourceId = 'other-root'; },
    (c) => { c.source.resourceId = 'other-file'; },
    (c) => { c.source.version = 'etag-source-2'; },
    (c) => { c.source.path = 'Documents/renamed.txt'; },
    (c) => { c.destination.spaceId = 'other-space'; },
    (c) => { c.destination.rootResourceId = 'other-root'; },
    (c) => { c.destination.parentResourceId = 'other-folder'; },
    (c) => { c.destination.parentVersion = 'etag-folder-5'; },
    (c) => { c.destination.targetPath = 'Copies/other.txt'; }
  ]) {
    const current = context();
    changed(current);
    assert.equal(copyProducerContextMatches(expected, current), false);
  }
  assert.notEqual(copyProducerContextKey(expected), copyProducerContextKey({
    ...expected,
    destination: { ...expected.destination, targetPath: 'Copies/other.txt' }
  }));
  assert.notEqual(copyProducerContextKey(expected), copyProducerContextKey({
    ...expected,
    source: { ...expected.source, path: 'Documents/original.txt\u0000etag-source-1' }
  }));
  for (const malformed of [
    { ...expected, accountEpoch: -1 },
    { ...expected, accountEpoch: Number.MAX_SAFE_INTEGER + 1 },
    { ...expected, authGeneration: -1 },
    { ...expected, authGeneration: Number.POSITIVE_INFINITY },
    { ...expected, flowGeneration: -1 },
    { ...expected, profileId: '' },
    { ...expected, source: { ...expected.source, resourceId: '' } },
    { ...expected, source: undefined },
    { ...expected, destination: { ...expected.destination, targetPath: undefined } }
  ]) assert.equal(copyProducerContextMatches(expected, malformed), false);
  assert.throws(() => copyProducerContextKey({ ...expected, authGeneration: Number.NaN }));
});

test('producer start accepts only the fixed accepted/error union', () => {
  assert.deepEqual(validateCopyProducerStart({ accepted: true, job_id: 'copy-job-1' }), {
    accepted: true, job_id: 'copy-job-1'
  });
  assert.deepEqual(validateCopyProducerStart({ accepted: false, error: 'scope_changed' }), {
    accepted: false, error: 'scope_changed'
  });
  for (const invalid of [
    { accepted: true, job_id: '' },
    { accepted: true, job_id: 'bad\njob' },
    { accepted: true, job_id: 'x'.repeat(257) },
    { accepted: false, error: 'raw backend error' },
    { accepted: false, error: 'locked', job_id: 'copy-job-1' },
    { accepted: true, job_id: 'copy-job-1', source_path: 'private/path' },
    null,
    []
  ]) assert.throws(() => validateCopyProducerStart(invalid));
  assert.match(copyProducerStartErrorMessage('offline'), /original file stays in place/i);
  assert.match(copyProducerStartErrorMessage('locked'), /both locations/i);
  assert.match(copyProducerStartErrorMessage('busy'), /another file operation/i);
});

test('producer status accepts genuine binding pairs and rejects stale or malformed replies', () => {
  const unbound = status();
  assert.deepEqual(validateCopyProducerStatus(unbound, 'copy-job-1', 11), unbound);

  const bound = status({ write_id: 'a'.repeat(32), revision: 3 });
  assert.deepEqual(validateCopyProducerStatus(bound, 'copy-job-1', 11), bound);

  const copied = status({ state: 'copied', write_id: 'b'.repeat(32), revision: 9 });
  assert.deepEqual(validateCopyProducerStatus(copied, 'copy-job-1', 11), copied);
  assert.match(copyProducerStatusMessage(copied), /original file remains in place/i);

  for (const invalid of [
    status({ job_id: 'other-job' }),
    status({ auth_generation: 12 }),
    status({ auth_generation: -1 }),
    status({ auth_generation: Number.MAX_SAFE_INTEGER + 1 }),
    status({ state: 'uploading' }),
    status({ cancel_requested: 0 }),
    status({ write_id: 'a'.repeat(32) }),
    status({ revision: 3 }),
    status({ write_id: 'A'.repeat(32), revision: 3 }),
    status({ write_id: 'a'.repeat(31), revision: 3 }),
    status({ write_id: 'a'.repeat(32), revision: 0 }),
    status({ write_id: 'a'.repeat(32), revision: Number.MAX_SAFE_INTEGER + 1 }),
    status({ state: 'copied' }),
    status({ state: 'copied', write_id: 'a'.repeat(32), revision: 1, path: 'private/path' }),
    status({ state: 'needs_review', reason: 'unexpected-field' })
  ]) assert.throws(() => validateCopyProducerStatus(invalid, 'copy-job-1', 11));
  for (const invalidExpected of [
    ['', 11],
    ['bad\njob', 11],
    ['copy-job-1', -1],
    ['copy-job-1', Number.POSITIVE_INFINITY]
  ]) assert.throws(() => validateCopyProducerStatus(unbound, ...invalidExpected));

  assert.match(copyProducerStatusMessage(status({ state: 'needs_review' })), /check saved edits/i);
  assert.match(copyProducerStatusMessage(status({ state: 'cancelled' })), /original file remains in place/i);
});
