import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const main = await readFile(new URL('../src/main.ts', import.meta.url), 'utf8');
const styles = await readFile(new URL('../src/style.css', import.meta.url), 'utf8');

test('offline and encrypted files are first-class workspaces with their existing controls', () => {
  assert.match(main, /\['offline', 'Offline files', 'download'\]/);
  assert.match(main, /\['encrypted', 'Encrypted files', 'lock'\]/);
  assert.match(main, /function offlineWorkspacePage\(\)/);
  assert.match(main, /windowsOfflineFilesCard\(\).*windowsOfflineFoldersCard\(\)/s);
  assert.match(main, /offlinePickerBody\(selectedSpace\)/);
  assert.match(main, /function encryptedWorkspacePage\(\) \{ return encryptedAccessModal\(true\); \}/);
  assert.match(main, /data-action="refresh-cached-vault-roots"/);
  assert.match(main, /data-action="browse-cached-vault-root"/);
  assert.match(main, /data-action="browse-encrypted-space"/);
  assert.match(main, /Your vault password is not saved unless you choose “Remember on this device\.”/);
  assert.match(main, /operating system’s protected credential store for this account and vault/);
});

test('sync folders and media backups share one workspace while keeping separate modes', () => {
  assert.match(main, /\['folders', 'Sync workspace', 'folders'\]/);
  assert.match(main, /data-sync-section="folders">Synced folders/);
  assert.match(main, /data-sync-section="media">Media backups/);
  assert.match(main, /syncSection === 'folders'\s*\? foldersPage\(\)\s*:/);
  assert.match(main, /mode === 'upload_only'/);
  assert.match(main, /mode === 'download_only'/);
  assert.doesNotMatch(main, /\['media', 'Media backups'/);
});

test('workspace navigation uses guarded loaders and avoids replacing identical refresh markup', () => {
  assert.match(main, /if \(page === 'offline'\) \{ leaveWorkspacePage\(page\); void openOfflineFiles\(\); return; \}/);
  assert.match(main, /if \(page === 'encrypted'\) \{ leaveWorkspacePage\(page\); void openEncryptedAccess\(\); return; \}/);
  assert.match(main, /if \(!isCurrentAccount\(epoch\) \|\| !state\.pickerOpen \|\| state\.pickerPurpose !== 'offline'\) return;/);
  assert.match(main, /if \(!isCurrentAccount\(epoch\) \|\| !state\.vaultAccessOpen\) return;/);
  assert.match(main, /if \(markup !== lastRenderedMarkup\) \{\s*app\.innerHTML = markup;/);
  assert.match(main, /main\.scrollTop = previousMainScroll/);
  assert.match(main, /replacement\.focus\(\{ preventScroll: true \}\)/);
  assert.doesNotMatch(main, /data-action="manage-windows-offline-files"/);
  assert.match(styles, /\.workspace-tabs/);
  assert.match(styles, /\.offline-workspace-browser/);
  assert.match(styles, /\.encrypted-workspace/);
});

test('changed passive-refresh markup restores stable button focus only in the same account epoch', () => {
  assert.match(main, /const stableButtonFocusKeys = \['action', 'page', 'syncSection'/);
  assert.match(main, /focusedButton\.accountEpoch === state\.accountEpoch && focusedButton\.profileId === state\.selectedAccount/);
  assert.match(main, /replacement\.focus\(\{ preventScroll: true \}\)/);
  assert.match(main, /if \(markup !== lastRenderedMarkup\) \{\s*app\.innerHTML = markup;/);
});
