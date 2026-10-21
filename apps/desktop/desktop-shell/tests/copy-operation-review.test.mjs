import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/copy-operation-review.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { copyOperationReviewMessage, isReviewOnlyCopyOperation, copyVerifyContextMatches, copyVerifyRowKey, claimCopyVerify, releaseCopyVerify, validateCopyVerifyStart, validateCopyVerifyStatus, copyVerifyStartErrorMessage, copyVerifyStatusMessage } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

const copyRow = (state) => ({
  write_id: 'a'.repeat(32),
  revision: 1,
  retry_generation: 0,
  operation: 'copy_file',
  state,
  needs_attention: true,
  attention_reason: 'copy_file_requires_review',
  retry_state: null,
  can_retry_interrupted_create: false,
  path: '/synthetic-copy.txt',
  bytes: 32
});

test('mixed pending operations accept an explicitly review-only copy row', () => {
  const rows = [
    { ...copyRow('building') },
    { ...copyRow('queued') },
    { ...copyRow('pending') },
    { ...copyRow('uncertain') },
    { ...copyRow('conflict') },
    { ...copyRow('queued'), operation: 'create_file', needs_attention: false, attention_reason: null }
  ];
  assert.equal(rows.every(isReviewOnlyCopyOperation), true);
  assert.match(copyOperationReviewMessage(), /automatic retry is disabled/i);
  assert.match(copyOperationReviewMessage(), /source was kept/i);
});

test('copy rows cannot advertise generic retry or omit explicit review status', () => {
  for (const invalid of [
    { ...copyRow('uncertain'), can_retry_interrupted_create: true },
    { ...copyRow('uncertain'), retry_state: 'attempting' },
    { ...copyRow('queued'), needs_attention: false },
    { ...copyRow('conflict'), attention_reason: null },
    { ...copyRow('internal') }
  ]) {
    assert.equal(isReviewOnlyCopyOperation(invalid), false);
  }
});


test('copy verification context is fenced to account, exact scope, operation revision, and auth generation', () => {
  const context = { profileId: 'profile-a', accountEpoch: 4, spaceId: 'space-a', rootResourceId: 'root-a', writeId: 'b'.repeat(32), revision: 7, authGeneration: 19 };
  assert.equal(copyVerifyContextMatches(context, { ...context }), true);
  for (const changed of [
    { profileId: 'profile-b' }, { accountEpoch: 5 }, { spaceId: 'space-b' }, { rootResourceId: 'root-b' },
    { writeId: 'c'.repeat(32) }, { revision: 8 }, { authGeneration: 20 }
  ]) assert.equal(copyVerifyContextMatches(context, { ...context, ...changed }), false);
  assert.notEqual(copyVerifyRowKey(context), copyVerifyRowKey({ ...context, revision: 8 }));
  const active = new Set();
  assert.equal(claimCopyVerify(context, active), true);
  assert.equal(claimCopyVerify(context, active), false, 'duplicate trigger for the same exact row is rejected');
  releaseCopyVerify(context, active);
  assert.equal(claimCopyVerify(context, active), true);
});

test('copy verification start accepts only the fixed response union', () => {
  assert.deepEqual(validateCopyVerifyStart({ accepted: true, job_id: 'verify-job-1' }), { accepted: true, job_id: 'verify-job-1' });
  assert.deepEqual(validateCopyVerifyStart({ accepted: false, error: 'missing_source' }), { accepted: false, error: 'missing_source' });
  for (const invalid of [
    { accepted: true, job_id: '' }, { accepted: true, job_id: 'bad\njob' },
    { accepted: false, error: 'arbitrary backend text' }, { accepted: false, error: 'offline', job_id: 'unexpected' },
    { accepted: true, job_id: 'valid', error: 'offline' }, { accepted: true, job_id: 'valid', data: { path: '/private' } }, null
  ]) assert.throws(() => validateCopyVerifyStart(invalid));
  assert.match(copyVerifyStartErrorMessage('locked'), /unlock/i);
  assert.match(copyVerifyStartErrorMessage('offline'), /connect/i);
  assert.match(copyVerifyStartErrorMessage('missing_source'), /source is missing/i);
});

test('copy verification status rejects stale job or generation and maps fixed review outcomes', () => {
  const verified = { job_id: 'job-1', auth_generation: 19, state: 'verified', cancel_requested: false };
  assert.deepEqual(validateCopyVerifyStatus(verified, 'job-1', 19), verified);
  const review = validateCopyVerifyStatus({ job_id: 'job-1', auth_generation: 19, state: 'needs_review', cancel_requested: false, reason: 'source_changed' }, 'job-1', 19);
  assert.match(copyVerifyStatusMessage(review), /source changed/i);
  assert.throws(() => validateCopyVerifyStatus(verified, 'job-2', 19));
  assert.throws(() => validateCopyVerifyStatus(verified, 'job-1', 20));
  for (const invalid of [
    { ...verified, state: 'needs_review' },
    { ...verified, reason: 'source_changed' },
    { ...verified, state: 'needs_review', reason: 'raw server path' },
    { ...verified, cancel_requested: 'false' },
    { ...verified, result: { path: '/private' } }
  ]) assert.throws(() => validateCopyVerifyStatus(invalid, 'job-1', 19));
});
