export type GuestRole = { id: string; name: string };
export type GuestPermission = { id: string; email: string; roles: string[]; expiration_date_time: string | null };
export type GuestPermissionList = { profile_id: string; auth_generation: number; available: boolean; item_id: string; guests: GuestPermission[]; roles: GuestRole[] };
const html = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
const guestIcon = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M16 20v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 18.5V20m6-9a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm5-6.5a3.5 3.5 0 0 1 0 6.8m2 3.2h.5a3.5 3.5 0 0 1 3.5 3.5V20"/></svg>';

export function guestAccessMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error ?? '');
  if (/403|forbidden|denied/i.test(message)) return 'Server denied guest access.';
  if (/capabilit|unavailable|unsupported/i.test(message)) return 'Guest invitations are unavailable on this server.';
  return message || 'Could not load guest access.';
}

export function guestExpiryInput(value: string | null): string {
  if (!value) return '';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

export function guestExpiryValue(value: string): string | null {
  if (!value.trim()) return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

export type GuestEditDraft = { roleId: string; expiry: string };
export type GuestMutationScope = { page: string; category: string; profileId: string; accountEpoch: number; generation: number; spaceId: string; path: string; itemId: string; authGeneration: number };
export function guestMutationScopeIsCurrent(expected: GuestMutationScope, current: GuestMutationScope): boolean {
  return expected.page === current.page && expected.category === current.category && expected.profileId === current.profileId &&
    expected.accountEpoch === current.accountEpoch && expected.generation === current.generation && expected.spaceId === current.spaceId &&
    expected.path === current.path && expected.itemId === current.itemId && expected.authGeneration === current.authGeneration;
}
export function pickerUsesModal(pickerOpen: boolean, purpose: string, page: string): boolean {
  return pickerOpen && purpose !== 'guest' && !(page === 'offline' && purpose === 'offline');
}
export function guestAccessMarkup(data: GuestPermissionList | null, busy: boolean, error: string, path: string, roleId: string, expiry: string, email = '', editDrafts: Record<string, GuestEditDraft> = {}): string {
  if (!data) return `<section class="settings-card guest-access-card"><div class="settings-heading"><span class="settings-icon">${guestIcon}</span><div><h2>Guest access</h2><p>Choose a file or folder in an unencrypted Space to invite people by email and manage guest access.</p></div></div>${error ? `<p class="guest-error" role="alert">${html(error)}</p>` : ''}</section>`;
  if (!data.available) return `<section class="settings-card guest-access-card"><div class="settings-heading"><span class="settings-icon">${guestIcon}</span><div><h2>Guest access</h2><p>${html(path)}</p></div></div><p class="guest-unavailable" role="status">Guest invitations are unavailable for this item or server.</p></section>`;
  const roles = data.roles.map(role => `<option value="${html(role.id)}" ${role.id === roleId ? 'selected' : ''}>${html(role.name)}</option>`).join('');
  const roleNames = new Map(data.roles.map(role => [role.id, role.name]));
  return `<section class="settings-card guest-access-card"><div class="settings-heading"><span class="settings-icon">${guestIcon}</span><div><h2>Guest access</h2><p>Manage invitations for <b>${html(path)}</b>. Guests can access this item through an emailed invitation.</p></div><button class="button subtle" data-action="guest-refresh" ${busy ? 'disabled' : ''}>Refresh</button></div>${error ? `<p class="guest-error" role="alert">${html(error)}</p>` : ''}<form class="guest-invite-form" data-guest-form><label class="field-label" for="guest-email">Email address</label><input id="guest-email" type="email" required autocomplete="email" placeholder="person@example.com" value="${html(email)}" ${busy ? 'disabled' : ''}><label class="field-label" for="guest-role">Permission</label><select id="guest-role" ${busy ? 'disabled' : ''}>${roles}</select><label class="field-label" for="guest-expiry">Expiration (optional)</label><input id="guest-expiry" type="datetime-local" value="${html(expiry)}" ${busy ? 'disabled' : ''}><button class="button primary" data-action="guest-invite" ${busy || !data.roles.length ? 'disabled' : ''}>${busy ? 'Working…' : 'Send invitation'}</button><small>Sending creates an invitation and emails the recipient.</small></form><div class="guest-list">${data.guests.length ? data.guests.map(guest => { const draft = editDrafts[guest.id]; const selectedRole = draft?.roleId || guest.roles[0] || ''; const selectedExpiry = draft?.expiry ?? guestExpiryInput(guest.expiration_date_time); const roleLabel = guest.roles.map(id => roleNames.get(id) || 'Unknown permission').join(', '); return `<article class="guest-row"><div><b>${html(guest.email)}</b><small>${html(roleLabel)}${guest.expiration_date_time ? ` · Expires ${html(new Date(guest.expiration_date_time).toLocaleString())}` : ''}</small><div class="guest-edit"><select aria-label="Permission for ${html(guest.email)}" data-guest-role-id="${html(guest.id)}" ${busy ? 'disabled' : ''}>${data.roles.map(role => `<option value="${html(role.id)}" ${role.id === selectedRole ? 'selected' : ''}>${html(role.name)}</option>`).join('')}</select><input aria-label="Expiration for ${html(guest.email)}" type="datetime-local" value="${html(selectedExpiry)}" data-guest-expiry-id="${html(guest.id)}" ${busy ? 'disabled' : ''}><button class="button subtle" data-action="guest-update" data-permission-id="${html(guest.id)}" ${busy ? 'disabled' : ''}>Save</button></div></div><button class="button subtle danger" data-action="guest-revoke" data-permission-id="${html(guest.id)}" ${busy ? 'disabled' : ''}>Revoke</button></article>`; }).join('') : '<p class="guest-empty">No guest invitations for this item.</p>'}</div></section>`;
}
