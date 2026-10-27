#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export function assertTauriVersionParity(cargoLock, npmLock) {
  const packages = cargoLock.split(/^\[\[package\]\]\s*$/m);
  const tauri = packages.filter(block => /^name = "tauri"$/m.test(block));
  if (tauri.length !== 1) throw new Error('Expected one locked Rust tauri package');
  const rust = /^version = "([^"]+)"$/m.exec(tauri[0])?.[1];
  const api = npmLock.packages?.['node_modules/@tauri-apps/api']?.version;
  const minor = version => /^(\d+)\.(\d+)\.\d+(?:[-+].*)?$/.exec(version ?? '')?.slice(1, 3).join('.');
  if (!minor(rust) || !minor(api) || minor(rust) !== minor(api)) {
    throw new Error(`Tauri packaging requires matching Rust/frontend major.minor versions (Rust ${rust}, frontend ${api})`);
  }
  return { rust, api };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    const versions = assertTauriVersionParity(
      readFileSync(resolve(root, 'desktop-shell/src-tauri/Cargo.lock'), 'utf8'),
      JSON.parse(readFileSync(resolve(root, 'desktop-shell/package-lock.json'), 'utf8')),
    );
    console.log(`Tauri version preflight passed: Rust ${versions.rust}, frontend ${versions.api}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
