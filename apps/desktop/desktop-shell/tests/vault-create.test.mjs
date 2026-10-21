import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/vault-create.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { completeVaultCreate, finishVaultCreateAttempt } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);

test('successful vault creation closes the dialog and renders the success message', () => {
  const state = {
    vaultBinding: null,
    remotePath: '/old',
    pickerOpen: true,
    pickerFolderName: 'Vault',
    vaultDialog: { loading: true },
    vaultGeneration: 4,
    vaultWritable: false,
    message: ''
  };
  let renders = 0;

  completeVaultCreate(state, { root_path: '/Vault.vault', root_resource_id: 'root-id' }, 'Drive ready.', () => {
    renders++;
    assert.equal(state.vaultDialog, null);
    assert.equal(state.vaultGeneration, 5);
    assert.equal(state.message, 'Encrypted folder created and unlocked. Drive ready.');
  });

  assert.deepEqual(state.vaultBinding, { root_path: '/Vault.vault', root_resource_id: 'root-id' });
  assert.equal(state.remotePath, '/');
  assert.equal(state.pickerOpen, false);
  assert.equal(state.pickerFolderName, '');
  assert.equal(state.vaultWritable, true);
  assert.equal(renders, 1);
});

test('vault-create failure cleanup clears loading and renders', () => {
  const flow = { loading: true };
  let renders = 0;

  finishVaultCreateAttempt(flow, () => { renders++; });

  assert.equal(flow.loading, false);
  assert.equal(renders, 1);
});
