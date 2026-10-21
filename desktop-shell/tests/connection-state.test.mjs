import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('../src/connection-state.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
}).outputText;
const { connectionMode } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

test('a restored offline namespace is not presented as a new sign-in state', () => {
  assert.equal(connectionMode(true, { connected: false, offline_namespace: true }), 'offline_reconnecting');
});

test('a live connection takes precedence over stale offline namespace metadata', () => {
  assert.equal(connectionMode(true, { connected: true, offline_namespace: true }), 'connected');
});

test('an ordinary disconnected account still gets the sign-in state', () => {
  assert.equal(connectionMode(true, { connected: false, offline_namespace: false }), 'sign_in');
  assert.equal(connectionMode(true, { connected: false }), 'sign_in');
});

test('an unreachable agent takes precedence over account state', () => {
  assert.equal(connectionMode(false, { connected: false, offline_namespace: true }), 'unavailable');
});
