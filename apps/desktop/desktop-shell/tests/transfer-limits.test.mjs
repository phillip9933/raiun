import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/transfer-limits.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { parseTransferLimitsReply, parseTransferRateDraft, formatTransferRate } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('transfer limits parse the account-bound backend contract', () => {
  assert.deepEqual(parseTransferLimitsReply({
    limits: { upload_bytes_per_second: 8192, download_bytes_per_second: null },
    account_id: 'account-a', revision: 3, apply_immediately: true
  }), {
    limits: { upload_bytes_per_second: 8192, download_bytes_per_second: null },
    account_id: 'account-a', revision: 3, apply_immediately: true
  });
  assert.throws(() => parseTransferLimitsReply({ limits: { upload_bytes_per_second: 0, download_bytes_per_second: null }, account_id: null, revision: 1, apply_immediately: false }));
  assert.throws(() => parseTransferLimitsReply({ limits: { upload_bytes_per_second: 2 ** 40 + 1, download_bytes_per_second: null }, account_id: null, revision: 1, apply_immediately: false }));
  assert.throws(() => parseTransferLimitsReply({ limits: {}, account_id: null, revision: 0, apply_immediately: false }));
});

test('KiB/s drafts convert precisely to integer bytes per second', () => {
  assert.deepEqual(parseTransferRateDraft('8'), { ok: true, bytesPerSecond: 8192 });
  assert.deepEqual(parseTransferRateDraft('1.5'), { ok: true, bytesPerSecond: 1536 });
  assert.deepEqual(parseTransferRateDraft(''), { ok: true, bytesPerSecond: null });
  assert.deepEqual(parseTransferRateDraft('   '), { ok: true, bytesPerSecond: null });
  for (const value of ['0', '-2', '1.0001', 'Infinity', '1e3', String(2 ** 30 + 1)]) {
    assert.equal(parseTransferRateDraft(value).ok, false, `accepted ${value}`);
  }
});

test('backend rates round-trip through a stable KiB/s editor value', () => {
  for (const bytes of [1, 1024, 1536, 8192, 2 ** 40]) {
    const draft = formatTransferRate(bytes);
    const parsed = parseTransferRateDraft(draft);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.bytesPerSecond, bytes);
  }
  assert.equal(formatTransferRate(null), '');
});
