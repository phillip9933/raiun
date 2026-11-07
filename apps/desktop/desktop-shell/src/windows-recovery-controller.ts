import {
  validateWindowsRecoveryPage,
  validateWindowsRecoveryRetryResult,
  validateWindowsRecoveryCloudCheckResult,
  windowsRecoveryEligibility,
  WINDOWS_RECOVERY_PAGE_LIMIT,
  type WindowsRecoveryAgentStatus,
  type WindowsRecoveryEligibility,
  type WindowsRecoveryPage,
  type WindowsRecoveryRetryResult,
  type WindowsRecoveryCloudCheckResult,
  type WindowsRecoveryPageExpectation
} from './windows-recovery';

export type WindowsRecoveryContext = {
  accountEpoch: number;
  profileId: string;
  server: string | null;
  clientId: string | null;
  cloudRoot: string | null;
  authGeneration: number;
  recoveryScopeToken: string;
  cloudCheckSupported?: boolean;
};

export type WindowsRecoveryControllerState = {
  page: WindowsRecoveryPage | null;
  loading: boolean;
  error: string;
  retrying: boolean;
  retryResult: WindowsRecoveryRetryResult | null;
  checking: boolean;
  checkingRecordId: string | null;
  cloudCheckResult: WindowsRecoveryCloudCheckResult | null;
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
    context.recoveryScopeToken,
    context.cloudCheckSupported === true
  ]);
}

export class WindowsRecoveryController {
  readonly state: WindowsRecoveryControllerState = {
    page: null, loading: false, error: '', retrying: false, retryResult: null,
    checking: false, checkingRecordId: null, cloudCheckResult: null
  };
  private activeKey: string | null = null;
  private requestSequence = 0;
  private mutationInFlight = false;

  setContext(context: WindowsRecoveryContext | null): void {
    const nextKey = context ? windowsRecoveryContextKey(context) : null;
    if (nextKey === this.activeKey) return;
    this.activeKey = nextKey;
    this.requestSequence += 1;
    this.state.page = null;
    this.state.loading = false;
    this.state.error = '';
    this.state.retrying = false;
    this.state.retryResult = null;
    this.state.checking = false;
    this.state.checkingRecordId = null;
    this.state.cloudCheckResult = null;
  }

  async load(
    context: WindowsRecoveryContext,
    request: WindowsRecoveryRequest,
    isCurrentContext: () => boolean
  ): Promise<void> {
    if (this.mutationInFlight || this.state.checking || this.state.retrying) return;
    this.setContext(context);
    const key = windowsRecoveryContextKey(context);
    const sequence = ++this.requestSequence;
    const isCurrent = () => this.activeKey === key && this.requestSequence === sequence && isCurrentContext();
    this.state.loading = true;
    this.state.page = null;
    this.state.error = '';
    this.state.cloudCheckResult = null;

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

  async retry(
    context: WindowsRecoveryContext,
    recordId: string,
    generation: number,
    retrySupported: boolean,
    request: WindowsRecoveryRequest,
    confirm: () => Promise<boolean>,
    isCurrentContext: () => boolean
  ): Promise<void> {
    if (this.mutationInFlight || this.state.loading || this.state.checking || retrySupported !== true || !isCurrentContext()) return;
    const key = windowsRecoveryContextKey(context);
    const page = this.state.page;
    if (this.activeKey !== key || !page ||
        !page.items.some(item => item.record_id === recordId && item.generation === generation)) return;
    const sequence = this.requestSequence;
    const current = () => this.activeKey === key && this.requestSequence === sequence &&
      this.state.page === page && isCurrentContext();
    this.mutationInFlight = true;
    this.state.retrying = true;
    this.state.retryResult = null;
    this.state.cloudCheckResult = null;
    this.state.error = '';
    try {
      if (await confirm() !== true || !current()) return;
      const value = await request('windows_recovery_retry', {
        profile_id: context.profileId,
        expected_generation: context.authGeneration,
        expected_recovery_scope_token: context.recoveryScopeToken,
        record_id: recordId,
        generation
      });
      const result = validateWindowsRecoveryRetryResult(value, {
        profileId: context.profileId,
        authGeneration: context.authGeneration,
        recoveryScopeToken: context.recoveryScopeToken
      });
      if (!current()) return;
      this.state.retryResult = result;
      this.state.retrying = false;
      this.mutationInFlight = false;
      await this.load(context, request, isCurrentContext);
    } catch {
      if (current()) {
        this.state.error = 'Retry outcome could not be confirmed. The original saved edit is retained; refresh before trying again.';
        this.state.page = null;
      }
    } finally {
      this.mutationInFlight = false;
      if (this.activeKey === key && !isCurrentContext()) this.setContext(null);
      if (this.activeKey === key) this.state.retrying = false;
    }
  }

  async checkCloudCopy(
    context: WindowsRecoveryContext,
    recordId: string,
    generation: number,
    checkSupported: boolean,
    request: WindowsRecoveryRequest,
    isCurrentContext: () => boolean
  ): Promise<void> {
    if (this.mutationInFlight || this.state.loading || this.state.retrying || this.state.checking ||
        checkSupported !== true || context.cloudCheckSupported !== true || !isCurrentContext()) return;
    const key = windowsRecoveryContextKey(context);
    const page = this.state.page;
    const item = page?.items.find(candidate => candidate.record_id === recordId && candidate.generation === generation);
    if (this.activeKey !== key || !page || !item) return;
    const sequence = this.requestSequence;
    const current = () => this.activeKey === key && this.requestSequence === sequence &&
      this.state.page === page && isCurrentContext();
    this.mutationInFlight = true;
    this.state.checking = true;
    this.state.checkingRecordId = recordId;
    this.state.cloudCheckResult = null;
    this.state.retryResult = null;
    this.state.error = '';
    try {
      const value = await request('windows_recovery_check_cloud', {
        profile_id: context.profileId,
        expected_generation: context.authGeneration,
        expected_recovery_scope_token: context.recoveryScopeToken,
        record_id: recordId,
        generation
      });
      const result = validateWindowsRecoveryCloudCheckResult(value, {
        profileId: context.profileId,
        authGeneration: context.authGeneration,
        recoveryScopeToken: context.recoveryScopeToken,
        recordId, generation, bytes: item.bytes
      });
      if (current()) this.state.cloudCheckResult = result;
    } catch {
      if (current()) this.state.error = 'The cloud copy could not be checked. Your saved copy is kept and Windows sync status is unchanged.';
    } finally {
      this.mutationInFlight = false;
      if (this.activeKey === key && !isCurrentContext()) this.setContext(null);
      if (this.activeKey === key) {
        this.state.checking = false;
        this.state.checkingRecordId = null;
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
  if (!eligibility.available) return { eligibility, context: null };
  return {
    eligibility,
    context: {
      accountEpoch: identity.accountEpoch,
      profileId: eligibility.profileId,
      server: identity.server,
      clientId: identity.clientId,
      cloudRoot: identity.cloudRoot,
      authGeneration: eligibility.authGeneration,
      recoveryScopeToken: eligibility.recoveryScopeToken,
      ...(status?.windows_recovery_cloud_check_supported === true ? { cloudCheckSupported: true } : {})
    }
  };
}
