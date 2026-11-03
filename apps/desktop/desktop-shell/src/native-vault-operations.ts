export type NativeVaultOperation = 'create_file' | 'create_folder' | 'save_in_place' | 'replace_file' | 'rename_file' | 'move_file' | 'rename_folder' | 'move_folder' | 'delete_file' | 'delete_empty_folder';
const known: readonly NativeVaultOperation[] = ['create_file', 'create_folder', 'save_in_place', 'replace_file', 'rename_file', 'move_file', 'rename_folder', 'move_folder', 'delete_file', 'delete_empty_folder'];
export function nativeVaultOperations(value: unknown): NativeVaultOperation[] {
  if (!Array.isArray(value) || value.length > known.length || value.some(item => typeof item !== 'string' || !known.includes(item as NativeVaultOperation)) || new Set(value).size !== value.length) return [];
  return known.filter(operation => value.includes(operation));
}
export function nativeVaultOperationMessage(operations: readonly NativeVaultOperation[]): string {
  const has = (operation: NativeVaultOperation) => operations.includes(operation);
  const actions: string[] = [];
  if (has('create_file')) actions.push('add files');
  if (has('create_folder')) actions.push('create folders');
  if (has('save_in_place')) actions.push('save files in place');
  if (has('replace_file')) actions.push('save with supported replacement-style editors');
  if (has('rename_file')) actions.push('rename clean files');
  if (has('move_file')) actions.push('move clean files within this vault');
  if (has('rename_folder')) actions.push('rename clean folders');
  if (has('move_folder')) actions.push('move clean folders within this vault');
  if (has('delete_file')) actions.push('delete clean files');
  if (has('delete_empty_folder')) actions.push('delete empty folders');
  if (!actions.length) return 'This encrypted location is currently read-only in the Windows drive.';
  const list = actions.length === 1 ? actions[0] : `${actions.slice(0, -1).join(', ')} and ${actions[actions.length - 1]}`;
  return `While connected, you can ${list} through the Windows drive. File creation and supported saves accept files up to 1 GiB. Existing read-only files remain read-only.`;
}
