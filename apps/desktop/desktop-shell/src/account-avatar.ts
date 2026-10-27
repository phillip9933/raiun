export type AccountAvatarReply = { profile_id?: unknown; auth_generation?: unknown; data_url?: unknown };
export type AccountAvatarTicket = { profileId: string; authGeneration: number; accountEpoch: number; ticket: number };

export function accountAvatarCacheKey(profileId: string, authGeneration: number): string {
  return `${profileId}:${authGeneration}`;
}

export function validatedAccountAvatar(reply: AccountAvatarReply, profileId: string, authGeneration: number): string | null {
  if (reply.profile_id !== profileId || reply.auth_generation !== authGeneration) return null;
  const value = reply.data_url;
  if (typeof value !== 'string' || value.length > 700 * 1024) return null;
  return /^data:image\/(?:png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/.test(value) ? value : null;
}

/** Bounded in-memory cache and independent request tickets for registered profiles. */
export class AccountAvatarCache {
  private images = new Map<string, string | null>();
  private pending = new Map<string, AccountAvatarTicket>();
  private nextTicket = 0;
  constructor(private readonly maxProfiles = 16) {}

  get(profileId: string, authGeneration: number): string | null | undefined {
    return this.images.get(accountAvatarCacheKey(profileId, authGeneration));
  }

  begin(profileId: string, authGeneration: number, accountEpoch: number): AccountAvatarTicket | null {
    const key = accountAvatarCacheKey(profileId, authGeneration);
    if (this.images.has(key) || this.pending.has(key) || this.images.size + this.pending.size >= this.maxProfiles) return null;
    const ticket = ++this.nextTicket;
    const request = { profileId, authGeneration, accountEpoch, ticket };
    this.pending.set(key, request);
    return request;
  }

  cancelPendingExceptEpoch(accountEpoch: number) {
    for (const [key, request] of this.pending) {
      if (request.accountEpoch === accountEpoch) continue;
      this.pending.delete(key);
    }
  }

  keepCurrentGeneration(profileId: string, authGeneration: number) {
    const prefix = `${profileId}:`;
    for (const key of this.images.keys()) if (key.startsWith(prefix) && key !== accountAvatarCacheKey(profileId, authGeneration)) this.images.delete(key);
    for (const [key, request] of this.pending) {
      if (!key.startsWith(prefix) || key === accountAvatarCacheKey(profileId, authGeneration)) continue;
      this.pending.delete(key);
    }
  }

  complete(ticket: AccountAvatarTicket, reply: AccountAvatarReply | null, currentEpoch: number, listedAuthGeneration: number | undefined, stillListed: boolean): boolean {
    const key = accountAvatarCacheKey(ticket.profileId, ticket.authGeneration);
    const current = this.pending.get(key);
    if (!current || current.ticket !== ticket.ticket || current.accountEpoch !== ticket.accountEpoch) return false;
    this.pending.delete(key);
    if (currentEpoch !== ticket.accountEpoch || !stillListed || listedAuthGeneration !== ticket.authGeneration) return false;
    this.images.set(key, reply ? validatedAccountAvatar(reply, ticket.profileId, ticket.authGeneration) : null);
    while (this.images.size > this.maxProfiles) this.images.delete(this.images.keys().next().value!);
    return true;
  }

  clearProfile(profileId: string) {
    const prefix = `${profileId}:`;
    for (const key of this.images.keys()) if (key.startsWith(prefix)) this.images.delete(key);
    for (const [key, request] of this.pending) {
      if (!key.startsWith(prefix)) continue;
      this.pending.delete(key);
    }
  }

  clearPending() {
    this.cancelPendingExceptEpoch(-1);
  }
}
