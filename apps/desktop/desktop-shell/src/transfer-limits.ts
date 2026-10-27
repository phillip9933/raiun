export type TransferLimits = {
  upload_bytes_per_second: number | null;
  download_bytes_per_second: number | null;
};

export type TransferLimitsReply = {
  limits: TransferLimits;
  account_id: string | null;
  revision: number;
  apply_immediately: boolean;
  scope_token?: string;
};

const MAX_BYTES_PER_SECOND = 2 ** 40;
const BYTES_PER_KIB = 1024;

function checkedRate(value: unknown): number | null {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || Number(value) <= 0 || Number(value) > MAX_BYTES_PER_SECOND) {
    throw new Error('The agent returned invalid transfer limits.');
  }
  return Number(value);
}

export function parseTransferLimitsReply(value: unknown, requireScopeToken = false): TransferLimitsReply {
  if (!value || typeof value !== 'object') throw new Error('Transfer limits are unavailable.');
  const row = value as Record<string, unknown>;
  if (!row.limits || typeof row.limits !== 'object' ||
      !(row.account_id === null || typeof row.account_id === 'string') ||
      !Number.isSafeInteger(row.revision) || Number(row.revision) < 1 ||
      typeof row.apply_immediately !== 'boolean' ||
      (row.scope_token !== undefined && !(row.scope_token === null && row.account_id === null) &&
        (typeof row.scope_token !== 'string' || row.scope_token.length !== 64 || !/^[0-9a-f]{64}$/u.test(row.scope_token))) ||
      (requireScopeToken && row.account_id !== null &&
        (typeof row.account_id !== 'string' || !row.account_id || typeof row.scope_token !== 'string'))) {
    throw new Error('Transfer limits are unavailable.');
  }
  const limits = row.limits as Record<string, unknown>;
  return {
    limits: {
      upload_bytes_per_second: checkedRate(limits.upload_bytes_per_second),
      download_bytes_per_second: checkedRate(limits.download_bytes_per_second),
    },
    account_id: row.account_id as string | null,
    revision: Number(row.revision),
    apply_immediately: row.apply_immediately,
    ...(typeof row.scope_token === 'string' ? { scope_token: row.scope_token } : {}),
  };
}

export function parseTransferRateDraft(value: string): { ok: true; bytesPerSecond: number | null } | { ok: false; error: string } {
  const trimmed = value.trim();
  if (!trimmed) return { ok: true, bytesPerSecond: null };
  if (!/^\d+(?:\.\d{1,3})?$/u.test(trimmed)) return { ok: false, error: 'Enter a positive KiB/s value, or leave blank for unlimited.' };
  const kib = Number(trimmed);
  const bytesPerSecond = Math.round(kib * BYTES_PER_KIB);
  if (!Number.isFinite(kib) || kib <= 0 || !Number.isSafeInteger(bytesPerSecond) || bytesPerSecond > MAX_BYTES_PER_SECOND) {
    return { ok: false, error: 'Enter a positive KiB/s value within the supported limit.' };
  }
  return { ok: true, bytesPerSecond };
}

export function formatTransferRate(bytesPerSecond: number | null): string {
  if (bytesPerSecond === null) return '';
  return (bytesPerSecond / BYTES_PER_KIB).toFixed(3).replace(/(?:\.0+|(?:(\.\d*?)0+))$/u, '$1');
}
