export type VaultCreateResult = {
  root_path: string;
  root_resource_id: string;
  vault_mount_ready?: boolean;
  vault_mount_writable?: boolean;
};

export type VaultCreateCompletionState = {
  vaultBinding: VaultCreateResult | null;
  remotePath: string;
  pickerOpen: boolean;
  pickerFolderName: string;
  vaultDialog: unknown;
  vaultGeneration: number;
  vaultWritable: boolean;
  message: string;
};

export function completeVaultCreate(
  state: VaultCreateCompletionState,
  created: VaultCreateResult,
  accessMessage: string,
  render: () => void,
  native = false
): void {
  if (native && created.vault_mount_ready !== true) throw new Error('The encrypted folder was created, but its Windows drive route is not ready.');
  state.vaultBinding = native ? null : { root_path: created.root_path, root_resource_id: created.root_resource_id };
  state.remotePath = '/';
  state.pickerOpen = false;
  state.pickerFolderName = '';
  state.vaultDialog = null;
  state.vaultGeneration++;
  state.vaultWritable = native ? created.vault_mount_writable === true : true;
  state.message = `Encrypted folder created and unlocked. ${accessMessage}`;
  render();
}

export function finishVaultCreateAttempt(
  flow: { loading: boolean },
  render: () => void
): void {
  flow.loading = false;
  render();
}
