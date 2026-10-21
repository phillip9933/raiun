export type WindowsPortabilityWarning =
  | 'unsupported_character'
  | 'trailing_dot_or_space'
  | 'reserved_device_name'
  | 'case_collision'
  | 'component_too_long';

const warningCopy: Record<WindowsPortabilityWarning, string> = {
  unsupported_character: 'contains a character Windows does not allow',
  trailing_dot_or_space: 'ends with a dot or space',
  reserved_device_name: 'uses a Windows reserved device name',
  case_collision: 'differs only by letter case from another item',
  component_too_long: 'exceeds the usual Windows filename component length',
};

const allowedWarnings = new Set<string>(Object.keys(warningCopy));

/** Fixed warning text for existing cloud names; never treats these as sync errors. */
export function windowsPortabilityLabel(warnings: unknown): string | null {
  if (!Array.isArray(warnings)) return null;
  const categories = [...new Set(warnings.filter(
    (warning): warning is WindowsPortabilityWarning =>
      typeof warning === 'string' && allowedWarnings.has(warning),
  ))];
  if (categories.length === 0) return null;
  return `May not work on Windows: ${categories.map(warning => warningCopy[warning]).join('; ')}. The existing name is unchanged.`;
}
