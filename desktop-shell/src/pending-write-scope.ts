export type PendingWriteScopeItem = {
  space_id: string;
  root_resource_id?: string | null;
};

export type PendingOfflineWrite = PendingWriteScopeItem & {
  space_label?: string | null;
  write_id: string;
  path: string;
  state: 'pending' | 'conflict';
  bytes: number;
  created_at_unix: number;
};

export type PendingOfflineWritesPage = {
  auth_generation: number | null;
  account_scope: string | null;
  items: PendingOfflineWrite[];
  next_after: string | null;
  pending_count: number;
  conflict_count: number;
  truncated: boolean;
};

export function pendingWritePageIsValid(value: unknown): PendingOfflineWritesPage {
  if (!value || typeof value !== 'object') throw new Error('The agent returned an invalid saved-edit list.');
  const page = value as Record<string, unknown>;
  if (!Array.isArray(page.items) || !Number.isSafeInteger(page.pending_count) || (page.pending_count as number) < 0 || !Number.isSafeInteger(page.conflict_count) || (page.conflict_count as number) < 0) throw new Error('The agent returned an invalid saved-edit list.');
  if (page.auth_generation != null && (!Number.isSafeInteger(page.auth_generation) || Number(page.auth_generation) < 0)) throw new Error('The agent returned an invalid saved-edit generation.');
  if (page.account_scope != null && (typeof page.account_scope !== 'string' || !/^[0-9a-f]{64}$/.test(page.account_scope))) throw new Error('The agent returned an invalid saved-edit account scope.');
  const items = page.items.slice(0, 100).filter((item: unknown) => {
    if (!item || typeof item !== 'object') return false;
    const row = item as Record<string, unknown>;
    const root = row.root_resource_id;
    return typeof row.space_id === 'string' && row.space_id.length > 0 && row.space_id.length <= 1024 &&
      (root == null || (typeof root === 'string' && root.trim().length > 0 && root.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(root))) &&
      typeof row.write_id === 'string' && row.write_id.length > 0 && row.write_id.length <= 512 &&
      typeof row.path === 'string' && row.path.startsWith('/') &&
      (row.state === 'pending' || row.state === 'conflict') &&
      Number.isSafeInteger(row.bytes) && (row.bytes as number) >= 0 &&
      Number.isSafeInteger(row.created_at_unix);
  });
  if (items.length !== page.items.length) throw new Error('The agent returned an invalid saved-edit entry.');
  const normalizedItems = items.map((item: Record<string, unknown>) => ({
    ...item,
    root_resource_id: typeof item.root_resource_id === 'string' ? item.root_resource_id : null
  })) as PendingOfflineWrite[];
  return {
    auth_generation: typeof page.auth_generation === 'number' ? page.auth_generation : null,
    account_scope: typeof page.account_scope === 'string' ? page.account_scope : null,
    items: normalizedItems,
    pending_count: page.pending_count as number,
    conflict_count: page.conflict_count as number,
    next_after: typeof page.next_after === 'string' && page.next_after.length <= 4096 ? page.next_after : null,
    truncated: page.truncated === true
  };
}

export function pendingWriteRootId(item: PendingWriteScopeItem): string | null {
  const value = item.root_resource_id;
  return typeof value === 'string' && value.length > 0 ? value : null;
}

export function pendingWriteScopeKey(item: PendingWriteScopeItem): string {
  return JSON.stringify([item.space_id, pendingWriteRootId(item)]);
}

export function groupPendingWritesByScope<T extends PendingWriteScopeItem>(items: T[]): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = pendingWriteScopeKey(item);
    groups.set(key, [...(groups.get(key) || []), item]);
  }
  return groups;
}

export function togglePendingWriteDisclosure(expandedScopes: Set<string>, scopeKey: string, currentScopeKeys: Set<string>): boolean {
  if (!currentScopeKeys.has(scopeKey)) return false;
  if (expandedScopes.has(scopeKey)) expandedScopes.delete(scopeKey);
  else expandedScopes.add(scopeKey);
  return true;
}

export function savedRootDisclosure(
  rootResourceId: string | null,
  scopeKey: string,
  regionId: string,
  expanded: boolean,
  escape: (value: string) => string
): string {
  const content = expanded
    ? rootResourceId ? `<code>${escape(rootResourceId)}</code>` : '<span>Saved root unavailable</span>'
    : '';
  return `<button type="button" class="small-action quiet pending-write-root-toggle" data-action="toggle-saved-write-root" data-scope-key="${escape(scopeKey)}" aria-expanded="${expanded}" aria-controls="${escape(regionId)}">Saved location identity</button><div class="pending-write-root-region" id="${escape(regionId)}"${expanded ? '' : ' hidden'}>${content}</div>`;
}
