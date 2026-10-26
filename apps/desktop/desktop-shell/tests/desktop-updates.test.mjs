import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import ts from 'typescript';

const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const rust = await readFile(new URL('../src-tauri/src/desktop_updates.rs', import.meta.url), 'utf8');
const policy = await readFile(new URL('../src-tauri/src/desktop_updates_policy.rs', import.meta.url), 'utf8');
const shell = await readFile(new URL('../src-tauri/src/main.rs', import.meta.url), 'utf8');
const config = JSON.parse(await readFile(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
const releaseConfig = JSON.parse(await readFile(new URL('../src-tauri/tauri.updater-release.conf.json', import.meta.url), 'utf8'));

test('updates are checked automatically but download and install require explicit actions', () => {
  assert.match(main, /void refreshDesktopUpdate\(false\)/);
  assert.match(main, /setInterval\(\(\) => \{ if \(isTauri\(\)\) void refreshDesktopUpdate\(false\); \}, 60 \* 60 \* 1000\)/);
  assert.match(policy, /automatic_checks_are_daily_and_manual_checks_bypass_preference/);
  assert.match(main, /data-action="download-desktop-update"/);
  assert.match(main, /data-action="install-desktop-update"/);
  assert.match(main, /invoke<DesktopUpdateStatus>\('download_desktop_update', \{ expectedTag \}\)/);
  assert.match(main, /invoke\('install_desktop_update'\)/);
  assert.doesNotMatch(main, /invoke\('download_and_install'/);
  assert.doesNotMatch(main, /invoke\('install',\s*\{/);
});

test('Later dismisses only the exact release tag, while notes are rendered as escaped plain text', () => {
  assert.match(main, /invoke<DesktopUpdateStatus>\('dismiss_desktop_update', \{ tag \}\)/);
  assert.match(main, /<pre>\$\{esc\(update\.notes\)\}<\/pre>/);
  assert.match(main, /invoke\('open_desktop_release', \{ tag \}\)/);
});

test('backend pins GitHub release metadata, signed manifests, trusted redirects, and bounded package bytes', () => {
  assert.match(policy, /https:\/\/api\.github\.com\/repos\/phillip9933\/raiun\/releases\?per_page=100&page=1/);
  assert.match(rust, /desktop-update\.json/);
  assert.match(rust, /update\.verify\(&package_bytes\)/);
  assert.match(rust, /MAX_PACKAGE_BYTES: usize = 512 \* 1024 \* 1024/);
  assert.match(rust, /github-releases\.githubusercontent\.com/);
  assert.match(rust, /option_env!\("RAIUN_DESKTOP_UPDATE_PUBKEY"\)/);
  assert.doesNotMatch(rust, /RAIUN_DESKTOP_UPDATE_PRIVATE_KEY/);
});

test('installation preserves the normal shutdown and owned-process exit gate before invoking Tauri install', () => {
  const installStart = shell.indexOf('async fn install_desktop_update(');
  const installEnd = shell.indexOf('\n#[cfg(target_os = "linux")]', installStart);
  const install = shell.slice(installStart, installEnd);
  assert.ok(installStart >= 0 && installEnd > installStart);
  assert.ok(install.indexOf('desktop_updates::begin_install(&install_app)') < install.indexOf('cached_for_install(&install_app)'));
  assert.ok(install.indexOf('lock_transition()') < install.indexOf('cached_for_install(&install_app)'));
  assert.ok(install.indexOf('begin_agent_update_shutdown()') < install.indexOf('tray_action("shutdown"'));
  assert.ok(install.indexOf('wait_for_agent_socket_removal()?') < install.indexOf('update.install(bytes)'));
  assert.ok(install.indexOf('wait_for_owned_agent_exit(&install_app, true)?') < install.indexOf('update.install(bytes)'));
  assert.match(shell, /wait_for_owned_agent_exit\(&app, false\)\?/);
  assert.match(install, /clear_agent_shutdown_after_failure\(\)/);
  assert.doesNotMatch(install, /app\.exit\(/);
});

test('Tauri requires a version-bound signature and prohibits downgrade installation', () => {
  assert.equal(config.bundle.createUpdaterArtifacts, false);
  assert.equal(releaseConfig.bundle.createUpdaterArtifacts, true);
  assert.equal(config.plugins.updater.requireSignedVersion, true);
  assert.equal(config.plugins.updater.allowDowngrades, false);
  assert.equal(config.plugins.updater.dangerousInsecureTransportProtocol, false);
  assert.equal(config.plugins.updater.dangerousAcceptInvalidCerts, false);
  assert.equal(config.plugins.updater.dangerousAcceptInvalidHostnames, false);
});

test('Later hides the matching notification but leaves manual settings controls for that release', () => {
  const parsed = ts.createSourceFile('main.ts', main, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const names = new Set(['desktopUpdateNotificationVisible', 'desktopUpdateManualControls']);
  const declarations = parsed.statements.filter(node =>
    (ts.isFunctionDeclaration(node) && names.has(node.name?.text))
      || (ts.isVariableStatement(node) && node.declarationList.declarations.some(declaration => declaration.name.getText(parsed) === 'esc')),
  ).map(node => node.getFullText(parsed)).join('\n');
  const compiled = ts.transpileModule(declarations, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText;
  const context = vm.createContext({});
  vm.runInContext(compiled, context);

  const dismissed = {
    state: 'dismissed', version: '1.2.3', tag: 'desktop-v1.2.3', dismissed_tag: 'desktop-v1.2.3',
    release_url: 'https://github.com/phillip9933/raiun/releases/tag/desktop-v1.2.3', notes: 'A helpful fix', key_configured: true,
  };
  assert.equal(context.desktopUpdateNotificationVisible(dismissed), false);
  const settingsControls = context.desktopUpdateManualControls(dismissed, false);
  assert.match(settingsControls, /Version 1\.2\.3/);
  assert.match(settingsControls, /Download update/);
  assert.match(settingsControls, /A helpful fix/);
  assert.match(settingsControls, /data-action="later-desktop-update"/);

  const newer = { ...dismissed, state: 'available', tag: 'desktop-v1.2.4', version: '1.2.4' };
  assert.equal(context.desktopUpdateNotificationVisible(newer), true);
});
