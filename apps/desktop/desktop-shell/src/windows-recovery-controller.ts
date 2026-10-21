import {
  validateWindowsRecoveryPage,
  windowsRecoveryEligibility,
  WINDOWS_RECOVERY_PAGE_LIMIT,
  type WindowsRecoveryAgentStatus,
  type WindowsRecoveryEligibility,
  type WindowsRecoveryPage,
  type WindowsRecoveryPageExpectation
} from './windows-recovery';

export type WindowsRecoveryContext = {
  accountEpoch: number;
  profileId: 'default';
  server: string | null;
  clientId: string | null;
  cloudRoot: string | null;
  authGeneration: number;
  recoveryScopeToken: string;
};

export type WindowsRecoveryControllerState = {
  page: WindowsRecoveryPage | null;
  loading: boolean;
  error: string;
};

export type WindowsRecoveryRequest = (action: string, args: Record<string, unknown>) => Promise<unknown>;

export function windowsRecoveryContextKey(context: WindowsRecoveryContext): string {
  return JSON.stringify([
    context.accountEpoch,
    context.profileId,
    context.server,
    context.clientId,
    context.cloudRoot,
    context.authGeneration,
    context.recoveryScopeToken
  ]);
}

export class WindowsRecoveryController {
  readonly state: WindowsRecoveryControllerState = { page: null, loading: false, error: '' };
  private activeKey: string | null = null;
  private requestSequence = 0;

  setContext(context: WindowsRecoveryContext | null): void {
    const nextKey = context ? windowsRecoveryContextKey(context) : null;
    if (nextKey === this.activeKey) return;
    this.activeKey = nextKey;
    this.requestSequence += 1;
    this.state.page = null;
    this.state.loading = false;
    this.state.error = '';
  }

  async load(
    context: WindowsRecoveryContext,
    request: WindowsRecoveryRequest,
    isCurrentContext: () => boolean
  ): Promise<void> {
    this.setContext(context);
    const key = windowsRecoveryContextKey(context);
    const sequence = ++this.requestSequence;
    const isCurrent = () => this.activeKey === key && this.requestSequence === sequence && isCurrentContext();
    this.state.loading = true;
    this.state.page = null;
    this.state.error = '';

    try {
      const value = await request('windows_recovery_list', {
        profile_id: context.profileId,
        expected_generation: context.authGeneration,
        expected_recovery_scope_token: context.recoveryScopeToken,
        limit: WINDOWS_RECOVERY_PAGE_LIMIT
      });
      const expected: WindowsRecoveryPageExpectation = {
        profileId: context.profileId,
        authGeneration: context.authGeneration,
        recoveryScopeToken: context.recoveryScopeToken
      };
      const page = validateWindowsRecoveryPage(value, expected);
      if (isCurrent()) this.state.page = page;
    } catch (error) {
      if (isCurrent()) {
        this.state.error = error instanceof Error && error.message
          ? error.message
          : 'Windows saved edits could not be checked.';
      }
    } finally {
      const sameRequest = this.activeKey === key && this.requestSequence === sequence;
      if (sameRequest && !isCurrentContext()) {
        this.setContext(null);
      } else if (sameRequest) {
        this.state.loading = false;
      }
    }
  }
}

export function eligibleWindowsRecoveryContext(
  agentReachable: boolean,
  selectedProfileId: string | null,
  status: WindowsRecoveryAgentStatus | null,
  identity: { accountEpoch: number; server: string | null; clientId: string | null; cloudRoot: string | null }
): { eligibility: WindowsRecoveryEligibility; context: WindowsRecoveryContext | null } {
  const eligibility = windowsRecoveryEligibility(agentReachable, selectedProfileId, status);
  if (!eligibility.available || selectedProfileId !== 'default') return { eligibility, context: null };
  return {
    eligibility,
    context: {
      accountEpoch: identity.accountEpoch,
      profileId: 'default',
      server: identity.server,
      clientId: identity.clientId,
      cloudRoot: identity.cloudRoot,
      authGeneration: eligibility.authGeneration,
      recoveryScopeToken: eligibility.recoveryScopeToken
    }
  };
}
