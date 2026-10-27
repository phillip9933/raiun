export type FolderContentFilter = 'all' | 'photos' | 'videos';
export type FolderExclusionKind = 'file_type' | 'path';
export type FolderExclusion = { kind: FolderExclusionKind; pattern: string };
export type PersistedFolderPair = {
  id: string;
  local_path: string;
  space_id: string;
  vault: { root_path: string; root_resource_id: string } | null;
  remote_path: string;
  mode: 'two_way' | 'upload_only' | 'download_only';
  excluded_paths: string[];
  content_filter: FolderContentFilter;
  exclusions: FolderExclusion[];
};

export function normalizeFolderExclusion(kind: FolderExclusionKind, rawPattern: string): { rule?: FolderExclusion; error?: string } {
  const input = rawPattern.trim();
  if (!input) return { error: 'Enter a file type or a relative folder path.' };
  const pattern = kind === 'file_type'
    ? normalizeFileTypePattern(input)
    : input;
  if (!pattern) return { error: 'Enter a file type such as .tmp, or use a path pattern.' };
  if (pattern.length > 255) return { error: 'Each exclusion must be 255 characters or fewer.' };
  if (pattern.startsWith('/') || pattern.includes('\\') || /[\u0000-\u001f\u007f-\u009f]/.test(pattern)) {
    return { error: 'Use a relative pattern with forward slashes and no control characters.' };
  }
  const pathParts = pattern.split('/');
  const trailingDirectoryMarker = kind === 'path' && pattern.endsWith('/');
  const parts = trailingDirectoryMarker ? pathParts.slice(0, -1) : pathParts;
  if (parts.some(part => !part || part === '.' || part === '..')) {
    return { error: 'Use a relative pattern without empty, “.”, or “..” path parts.' };
  }
  if (kind === 'file_type' && (pattern.includes('/') || !/^\*\.[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(pattern))) {
    return { error: 'Use a file extension such as .tmp or .tar.gz.' };
  }
  return { rule: { kind, pattern } };
}

function normalizeFileTypePattern(input: string): string | null {
  const extension = input.startsWith('*.') ? input.slice(2) : input.startsWith('.') ? input.slice(1) : input;
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(extension)) return null;
  return `*.${extension}`;
}

export function validateFolderExclusions(rules: FolderExclusion[]): string | null {
  if (rules.length > 100) return 'A folder can have at most 100 exclusion rules.';
  let total = 0;
  const seen = new Set<string>();
  for (const rule of rules) {
    const normalized = normalizeFolderExclusion(rule.kind, rule.pattern);
    if (!normalized.rule || normalized.rule.pattern !== rule.pattern) return normalized.error || 'Review the exclusion rule format.';
    const key = `${rule.kind}\u0000${rule.pattern}`;
    if (seen.has(key)) return 'That exclusion rule is already listed.';
    seen.add(key);
    total += rule.pattern.length;
  }
  if (total > 8192) return 'The combined exclusion rules cannot exceed 8 KiB.';
  return null;
}

/** Return only persisted pair keys for the expected snapshot in pair_update CAS. */
export function persistedFolderPair(pair: Partial<PersistedFolderPair> & Record<string, unknown>): PersistedFolderPair {
  return {
    id: String(pair.id || ''),
    local_path: String(pair.local_path || ''),
    space_id: String(pair.space_id || ''),
    vault: pair.vault && typeof pair.vault === 'object'
      ? { root_path: String((pair.vault as {root_path?: unknown}).root_path || ''), root_resource_id: String((pair.vault as {root_resource_id?: unknown}).root_resource_id || '') }
      : null,
    remote_path: String(pair.remote_path || ''),
    mode: pair.mode === 'upload_only' || pair.mode === 'download_only' ? pair.mode : 'two_way',
    excluded_paths: Array.isArray(pair.excluded_paths) ? [...pair.excluded_paths] : [],
    content_filter: pair.content_filter === 'photos' || pair.content_filter === 'videos' ? pair.content_filter : 'all',
    exclusions: Array.isArray(pair.exclusions) ? pair.exclusions.map(rule => ({ kind: rule.kind, pattern: rule.pattern })) : []
  };
}

export type PairSettingsDraft = {
  snapshot: PersistedFolderPair;
  mode: PersistedFolderPair['mode'];
  content_filter: FolderContentFilter;
  exclusions: FolderExclusion[];
  excluded_paths: string[];
  accountEpoch: number;
  profileId: string;
  authGeneration: number;
};

export function createPairSettingsDraft(pair: Partial<PersistedFolderPair> & Record<string, unknown>, profileId: string, accountEpoch: number, authGeneration: number): PairSettingsDraft {
  const snapshot = persistedFolderPair(pair);
  return { snapshot, mode: snapshot.mode, content_filter: snapshot.content_filter, exclusions: snapshot.exclusions.map(rule => ({...rule})), excluded_paths: [...snapshot.excluded_paths], profileId, accountEpoch, authGeneration };
}

export function pairSettingsUpdateRequest(pairId: string, draft: PairSettingsDraft) {
  return { id: pairId, expected_pair: draft.snapshot, expected_auth_generation: draft.authGeneration,
    mode: draft.mode, content_filter: draft.content_filter, exclusions: draft.exclusions.map(rule => ({...rule})), excluded_paths: [...draft.excluded_paths] };
}

export function discardPairSettingsDraft(drafts: Map<string, PairSettingsDraft>, pairId: string): boolean {
  return drafts.delete(pairId);
}
