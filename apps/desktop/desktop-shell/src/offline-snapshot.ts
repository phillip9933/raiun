export function offlineCopyStoredSizeLabel(bytes: number, formatBytes: (bytes: number) => string): string | null {
  if (!Number.isSafeInteger(bytes) || bytes < 0) return null;
  return `${formatBytes(bytes)} stored`;
}
