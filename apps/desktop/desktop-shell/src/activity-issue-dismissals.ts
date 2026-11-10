// Activity preferences only. This module never changes transfer history or files.
export type ActivityIssueRecord = {
  id: number;
  updated_at?: number | null;
  space_id?: string | null;
  state?: string | null;
  operation?: string | null;
  direction?: string | null;
  origin?: string | null;
};
const STORAGE_KEY = 'raiun.activity-issue-dismissals.v1';
const MAX_ENTRIES = 500;
const MAX_STORAGE_LENGTH = 600_000;
const SESSION_NOTICE = 'Dismissals are remembered only for this session because local preferences could not be saved.';
const token = (value: unknown): value is string | null | undefined => value == null || typeof value === 'string' && /^[a-zA-Z0-9_]{1,64}$/.test(value);

// Awaiting authentication and unknown states may still represent live work.
// Only identified, inactive attention records can be dismissed.
export function activityIssueRecordKey(record: ActivityIssueRecord): string | null {
  if (typeof record.state !== 'string') return null;
  const state = record.state.trim().toLowerCase();
  if (!state || !['failed', 'conflict', 'needs_review'].includes(state)
    || !Number.isSafeInteger(record.id) || record.id < 0
    || !Number.isSafeInteger(record.updated_at) || (record.updated_at ?? -1) < 0
    || !(record.space_id == null || typeof record.space_id === 'string' && record.space_id.length <= 512)
    || !token(record.operation) || !token(record.direction) || !token(record.origin)) return null;
  // No filename, path, message or error text is included.
  const key = JSON.stringify([record.id, record.updated_at, record.space_id ?? null, record.state, record.operation ?? null, record.direction ?? null, record.origin ?? null]);
  return key.length <= 1100 ? key : null;
}
function validRecordKey(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 1100) return false;
  try {
    const fields = JSON.parse(value);
    if (!Array.isArray(fields) || fields.length !== 7) return false;
    return activityIssueRecordKey({ id: fields[0], updated_at: fields[1], space_id: fields[2], state: fields[3], operation: fields[4], direction: fields[5], origin: fields[6] }) === value;
  } catch { return false; }
}
type Entry = [scope: string, record: string];
export class ActivityIssueDismissals {
  private identity: string | null = null;
  private scope: string | null = null;
  private generation = 0;
  private entries: Entry[] = [];
  private loaded = false;
  private storageWritable = true;
  notice = '';
  constructor(private readonly storage: () => Pick<Storage, 'getItem' | 'setItem'>, private readonly changed: () => void) {}

  selectScope(identity: string | null): void {
    if (identity === this.identity) return;
    this.identity = identity;
    this.scope = null;
    const generation = ++this.generation;
    if (identity === null) return;
    // The exact profile/server/cloud-root tuple is hashed before persistence.
    void this.scopeDigest(identity).then(scope => {
      if (this.generation !== generation || this.identity !== identity) return;
      this.load();
      this.scope = scope;
      this.changed();
    });
  }
  private async scopeDigest(identity: string): Promise<string> {
    try {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity));
      return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
    } catch {
      this.storageWritable = false;
      this.notice = SESSION_NOTICE;
      return `session:${identity}`;
    }
  }
  matchesScope(identity: string | null): boolean { return identity !== null && identity === this.identity && this.scope !== null; }
  has(key: string | null): boolean { return key !== null && this.scope !== null && this.entries.some(entry => entry[0] === this.scope && entry[1] === key); }
  set(key: string, dismissed: boolean): void {
    if (this.scope === null || !validRecordKey(key)) return;
    this.entries = this.entries.filter(entry => entry[0] !== this.scope || entry[1] !== key);
    if (dismissed) this.entries.push([this.scope, key]);
    this.entries = this.entries.slice(-MAX_ENTRIES);
    this.persist();
  }
  restoreScope(): void {
    if (this.scope === null) return;
    this.entries = this.entries.filter(entry => entry[0] !== this.scope);
    this.persist();
  }
  private load(): void {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const raw = this.storage().getItem(STORAGE_KEY);
      if (raw === null) return;
      if (raw.length > MAX_STORAGE_LENGTH) throw new Error('Invalid preference size');
      const value = JSON.parse(raw);
      if (!value || value.version !== 1 || !Array.isArray(value.entries) || value.entries.length > MAX_ENTRIES
        || !value.entries.every((entry: unknown) => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === 'string' && /^[0-9a-f]{64}$/.test(entry[0]) && validRecordKey(entry[1]))) throw new Error('Invalid preferences');
      this.entries = value.entries;
    } catch {
      this.storageWritable = false;
      this.notice = SESSION_NOTICE;
    }
  }
  private persist(): void {
    if (!this.storageWritable) return;
    try {
      const raw = JSON.stringify({ version: 1, entries: this.entries });
      if (raw.length > MAX_STORAGE_LENGTH) throw new Error('Preference limit');
      this.storage().setItem(STORAGE_KEY, raw);
    } catch {
      this.storageWritable = false;
      this.notice = SESSION_NOTICE;
    }
  }
}
