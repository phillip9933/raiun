export type ProxyMode = 'system' | 'direct' | 'explicit';
export type ProxyConfig =
  | { mode: 'system' }
  | { mode: 'direct' }
  | { mode: 'explicit'; url: string };

export type ProxySettingsReply = {
  proxy: ProxyConfig;
  account_id: string | null;
  revision: number;
  apply_requires_reconnect: true;
};

export function parseProxySettings(value: unknown): ProxySettingsReply {
  if (!value || typeof value !== 'object') throw new Error('Proxy settings are unavailable.');
  const row = value as Record<string, unknown>;
  const proxy = parseProxyConfig(row.proxy);
  if (!(row.account_id === null || typeof row.account_id === 'string') ||
      !Number.isSafeInteger(row.revision) || Number(row.revision) < 1 ||
      row.apply_requires_reconnect !== true) {
    throw new Error('Proxy settings are unavailable.');
  }
  return { proxy, account_id: row.account_id as string | null, revision: Number(row.revision), apply_requires_reconnect: true };
}

export function parseProxyConfig(value: unknown): ProxyConfig {
  if (!value || typeof value !== 'object') throw new Error('The agent returned invalid proxy settings.');
  const row = value as Record<string, unknown>;
  if (row.mode === 'system') return { mode: 'system' };
  if (row.mode === 'direct') return { mode: 'direct' };
  if (row.mode === 'explicit' && typeof row.url === 'string') {
    const checked = validateProxyDraft('explicit', row.url);
    if (checked.ok) return checked.config;
  }
  throw new Error('The agent returned invalid proxy settings.');
}

export function validateProxyDraft(mode: ProxyMode, url: string): { ok: true; config: ProxyConfig } | { ok: false; error: string } {
  if (mode === 'system') return { ok: true, config: { mode: 'system' } };
  if (mode === 'direct') return { ok: true, config: { mode: 'direct' } };
  const value = url.trim();
  if (!value || value.length > 2048 || /[\s\u0000-\u001f\u007f]/u.test(value)) {
    return { ok: false, error: 'Enter an HTTP or HTTPS proxy address without credentials or extra URL parts.' };
  }
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password ||
        !['', '/'].includes(parsed.pathname) || parsed.search || parsed.hash || /[@?#]/u.test(value)) {
      return { ok: false, error: 'Enter an HTTP or HTTPS proxy address without credentials or extra URL parts.' };
    }
    return { ok: true, config: { mode: 'explicit', url: parsed.origin } };
  } catch {
    return { ok: false, error: 'Enter a valid HTTP or HTTPS proxy address.' };
  }
}

export function proxyEditorEnabled(input: {
  reachable: boolean;
  connected: boolean;
  offlineNamespace: boolean;
  authenticating: boolean;
  saving: boolean;
}): boolean {
  return input.reachable && !input.connected && !input.offlineNamespace && !input.authenticating && !input.saving;
}
