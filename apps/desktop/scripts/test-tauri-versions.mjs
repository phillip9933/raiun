import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { assertTauriVersionParity } from './check-tauri-versions.mjs';
const cargo = version => `[[package]]\nname = "tauri"\nversion = "${version}"\n`;
const npm = version => ({ packages: { 'node_modules/@tauri-apps/api': { version } } });
test('actual locked Rust and frontend Tauri versions package together', () => {
  assertTauriVersionParity(readFileSync(new URL('../desktop-shell/src-tauri/Cargo.lock', import.meta.url), 'utf8'), JSON.parse(readFileSync(new URL('../desktop-shell/package-lock.json', import.meta.url), 'utf8')));
});
test('observed 2.12 Rust and 2.11 frontend failure is rejected before compilation', () => {
  assert.throws(() => assertTauriVersionParity(cargo('2.12.5'), npm('2.11.1')), /matching Rust\/frontend/);
  assert.deepEqual(assertTauriVersionParity(cargo('2.12.5'), npm('2.12.4')), { rust: '2.12.5', api: '2.12.4' });
});
test('missing or ambiguous lock versions are refused', () => {
  assert.throws(() => assertTauriVersionParity(cargo('2.12.5'), npm(undefined)));
  assert.throws(() => assertTauriVersionParity(cargo('2.12.5') + cargo('2.12.5'), npm('2.12.4')));
});
