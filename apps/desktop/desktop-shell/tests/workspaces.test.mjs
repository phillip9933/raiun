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

test('folder workspace combines sync settings and media imports without separate navigation', () => {
  assert.match(main, /\['folders', 'Folders', 'folders'\]/);
  assert.doesNotMatch(main, /data-sync-section=/);
  assert.match(main, /groups\.map\(group => spacePairGroup\(group\.spaceId, group\.pairs\)\)/);
  assert.match(main, /mediaJobs\.rowsForSpace\(spaceId\)/);
  assert.match(main, /mode === 'upload_only'/);
  assert.match(main, /mode === 'download_only'/);
  assert.match(main, /folderCreationRoute\(state\.folderDirection, state\.existingCopyHandling\)/);
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
  assert.match(main, /const stableButtonFocusKeys = \['action', 'page'/);
  assert.match(main, /focusedButton\.accountEpoch === state\.accountEpoch && focusedButton\.profileId === state\.selectedAccount/);
  assert.match(main, /replacement\.focus\(\{ preventScroll: true \}\)/);
  assert.match(main, /if \(markup !== lastRenderedMarkup\) \{\s*app\.innerHTML = markup;/);
});
