export type AppearanceTheme = 'system' | 'light' | 'dark';
export type AccentName = 'ocean' | 'teal' | 'violet' | 'rose' | 'amber' | 'indigo' | 'forest' | 'plum';
export type AppearanceSettings = { theme: AppearanceTheme; accent: AccentName };

export const DEFAULT_APPEARANCE: AppearanceSettings = { theme: 'system', accent: 'ocean' };
export const ACCENT_COLORS: Record<AccentName, string> = {
  ocean: '#00677f',
  teal: '#267a68',
  violet: '#7057a5',
  rose: '#a94f6d',
  amber: '#9a6416',
  indigo: '#345b9e',
  forest: '#34634d',
  plum: '#843e75'
};

const PREFIX = 'raiun.ui-preferences.v1:';
const THEME_KEY = `${PREFIX}theme`;
const themes = new Set<AppearanceTheme>(['system', 'light', 'dark']);
const accents = new Set<AccentName>(Object.keys(ACCENT_COLORS) as AccentName[]);
let sessionTheme: AppearanceTheme | null = null;
const sessionAccents = new Map<string, AccentName>();

export function appearanceStorageKey(profileId: string): string | null {
  return profileId ? `${PREFIX}${encodeURIComponent(profileId)}` : null;
}

export function themeStorageKey(): string {
  return THEME_KEY;
}

function readTheme(storage: Pick<Storage, 'getItem'>): AppearanceTheme {
  if (sessionTheme) return sessionTheme;
  try {
    const value = storage.getItem(THEME_KEY);
    return themes.has(value as AppearanceTheme) ? value as AppearanceTheme : DEFAULT_APPEARANCE.theme;
  } catch {
    return DEFAULT_APPEARANCE.theme;
  }
}

function readAccent(storage: Pick<Storage, 'getItem'>, profileId: string): AccentName {
  const key = appearanceStorageKey(profileId);
  if (!key) return DEFAULT_APPEARANCE.accent;
  const sessionValue = sessionAccents.get(key);
  if (sessionValue) return sessionValue;
  try {
    const value: unknown = JSON.parse(storage.getItem(key) || 'null');
    if (!value || typeof value !== 'object') return DEFAULT_APPEARANCE.accent;
    const record = value as Record<string, unknown>;
    return accents.has(record.accent as AccentName) ? record.accent as AccentName : DEFAULT_APPEARANCE.accent;
  } catch {
    return DEFAULT_APPEARANCE.accent;
  }
}

export function readAppearance(storage: Pick<Storage, 'getItem'>, profileId: string): AppearanceSettings {
  return { theme: readTheme(storage), accent: readAccent(storage, profileId) };
}

export function writeAppearance(
  storage: Pick<Storage, 'getItem' | 'setItem'>,
  profileId: string,
  update: Partial<AppearanceSettings>
): AppearanceSettings {
  const theme = themes.has(update.theme as AppearanceTheme) ? update.theme as AppearanceTheme : readTheme(storage);
  const key = appearanceStorageKey(profileId);
  const accent = key && accents.has(update.accent as AccentName)
    ? update.accent as AccentName
    : key ? readAccent(storage, profileId) : DEFAULT_APPEARANCE.accent;

  if (themes.has(update.theme as AppearanceTheme)) {
    sessionTheme = theme;
    try { storage.setItem(THEME_KEY, theme); } catch { /* The global theme remains usable for this session. */ }
  }
  if (key && accents.has(update.accent as AccentName)) {
    sessionAccents.set(key, accent);
    try { storage.setItem(key, JSON.stringify({ accent })); } catch { /* This account color remains usable for this session. */ }
  }
  return { theme, accent };
}

export function mountControlState(
  providerSupported: boolean,
  connected: boolean,
  mounted: boolean,
  busy: boolean
) {
  const available = providerSupported && connected && !busy;
  return { mountDisabled: !available || mounted, unmountDisabled: !available || !mounted };
}
