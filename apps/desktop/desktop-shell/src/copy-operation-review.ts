type ReviewFields = {
  operation?: unknown;
  state?: unknown;
  needs_attention?: unknown;
  attention_reason?: unknown;
  retry_state?: unknown;
  can_retry_interrupted_create?: unknown;
};

const reviewableCopyStates = new Set(['building', 'queued', 'pending', 'uncertain', 'conflict']);

/**
 * Copy rows cannot use the generic create retry path: an uncertain remote
 * outcome requires verification, and legacy rows may lack a source binding.
 * Accept only an explicit review-only
 * status and reject any response that advertises copy retry eligibility.
 */
export function isReviewOnlyCopyOperation(value: ReviewFields): boolean {
  if (value.operation !== 'copy_file') return true;
  return typeof value.state === 'string' && reviewableCopyStates.has(value.state) &&
    value.needs_attention === true &&
    value.attention_reason === 'copy_file_requires_review' &&
    value.retry_state == null &&
    value.can_retry_interrupted_create === false;
}

export function copyOperationReviewMessage(): string {
  return 'This copy needs review. Its source was kept, and automatic retry is disabled. Use Check copy to review the source and destination. Older operations may still need manual review.';
}


export type CopyVerifyError =
  | 'stale_generation'
  | 'locked'
  | 'offline'
  | 'missing_source'
  | 'scope_changed'
  | 'busy'
  | 'unavailable';
export type CopyVerifyState = 'queued' | 'running' | 'verified' | 'needs_review' | 'cancelled' | 'failed';
export type CopyVerifyReason =
  | 'legacy_binding_unavailable'
  | 'never_attempted'
  | 'source_scope_mismatch'
  | 'source_changed'
  | 'destination_changed'
  | 'content_mismatch'
  | 'authentication_generation_changed'
  | 'verification_unavailable';
export type CopyVerifyBinding = {
  profileId: string;
  accountEpoch: number;
  spaceId: string;
  rootResourceId: string;
  writeId: string;
  revision: number;
  authGeneration: number;
};
export type CopyVerifyStart = { accepted: true; job_id: string } | { accepted: false; error: CopyVerifyError };
export type CopyVerifyStatus = {
  job_id: string;
  auth_generation: number;
  state: CopyVerifyState;
  cancel_requested: boolean;
  reason?: CopyVerifyReason;
};

const copyVerifyErrors = new Set<CopyVerifyError>([
  'stale_generation', 'locked', 'offline', 'missing_source', 'scope_changed', 'busy', 'unavailable'
]);
const copyVerifyStates = new Set<CopyVerifyState>([
  'queued', 'running', 'verified', 'needs_review', 'cancelled', 'failed'
]);
const copyVerifyReasons = new Set<CopyVerifyReason>([
  'legacy_binding_unavailable', 'never_attempted', 'source_scope_mismatch', 'source_changed',
  'destination_changed', 'content_mismatch', 'authentication_generation_changed', 'verification_unavailable'
]);

export function copyVerifyRowKey(binding: CopyVerifyBinding): string {
  return [binding.profileId, binding.accountEpoch, binding.spaceId, binding.rootResourceId,
    binding.writeId, binding.revision, binding.authGeneration].join('\u0000');
}

export function copyVerifyContextMatches(expected: CopyVerifyBinding, current: CopyVerifyBinding): boolean {
  return expected.profileId === current.profileId && expected.accountEpoch === current.accountEpoch &&
    expected.spaceId === current.spaceId && expected.rootResourceId === current.rootResourceId &&
    expected.writeId === current.writeId && expected.revision === current.revision &&
    expected.authGeneration === current.authGeneration;
}

export function claimCopyVerify(binding: CopyVerifyBinding, active: Set<string>): boolean {
  const key = copyVerifyRowKey(binding);
  if (active.has(key)) return false;
  active.add(key);
  return true;
}

export function releaseCopyVerify(binding: CopyVerifyBinding, active: Set<string>): void {
  active.delete(copyVerifyRowKey(binding));
}

export function validateCopyVerifyStart(value: unknown): CopyVerifyStart {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('The agent returned an invalid copy verification response.');
  const response = value as { accepted?: unknown; job_id?: unknown; error?: unknown };
  const keys = Object.keys(response).sort().join(',');
  if (response.accepted === true && keys === 'accepted,job_id' && typeof response.job_id === 'string' && response.job_id.length > 0 &&
      response.job_id.length <= 256 && !/[\u0000-\u001f\u007f]/.test(response.job_id)) {
    return { accepted: true, job_id: response.job_id };
  }
  if (response.accepted === false && keys === 'accepted,error' && typeof response.error === 'string' && copyVerifyErrors.has(response.error as CopyVerifyError)) {
    return { accepted: false, error: response.error as CopyVerifyError };
  }
  throw new Error('The agent returned an invalid copy verification response.');
}

export function validateCopyVerifyStatus(value: unknown, expectedJobId: string, expectedGeneration: number): CopyVerifyStatus {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('The agent returned an invalid copy verification status.');
  const status = value as { job_id?: unknown; auth_generation?: unknown; state?: unknown; cancel_requested?: unknown; reason?: unknown };
  const keys = Object.keys(status).sort().join(',');
  const expectedKeys = status.state === 'needs_review'
    ? 'auth_generation,cancel_requested,job_id,reason,state'
    : 'auth_generation,cancel_requested,job_id,state';
  if (keys !== expectedKeys || status.job_id !== expectedJobId || !Number.isSafeInteger(status.auth_generation) ||
      status.auth_generation !== expectedGeneration || typeof status.state !== 'string' ||
      !copyVerifyStates.has(status.state as CopyVerifyState) || typeof status.cancel_requested !== 'boolean') {
    throw new Error('The agent returned an invalid copy verification status.');
  }
  if (status.state === 'needs_review') {
    if (typeof status.reason !== 'string' || !copyVerifyReasons.has(status.reason as CopyVerifyReason)) {
      throw new Error('The agent returned an invalid copy verification status.');
    }
  } else if (status.reason != null) {
    throw new Error('The agent returned an invalid copy verification status.');
  }
  return status as CopyVerifyStatus;
}

export function copyVerifyStartErrorMessage(error: CopyVerifyError): string {
  switch (error) {
    case 'stale_generation': return 'This operation changed while you were reviewing it. Refresh the list before checking again.';
    case 'locked': return 'Unlock this encrypted location before verifying the copy.';
    case 'offline': return 'Connect to OpenCloud before verifying the copy. The local source remains saved.';
    case 'missing_source': return 'The saved source is missing. Raiun kept the operation for review and did not upload it.';
    case 'scope_changed': return 'The account or encrypted location changed. Refresh the operation list before checking again.';
    case 'busy': return 'A verification is already running for this operation.';
    case 'unavailable': return 'Copy verification is unavailable right now. Raiun kept the saved operation.';
  }
}

export function copyVerifyStatusMessage(status: CopyVerifyStatus): string {
  if (status.state === 'verified') return 'The copy is verified. Raiun cleared only the exact saved operation; it did not delete the source.';
  if (status.state === 'cancelled') return 'Copy verification stopped. Raiun did not retry the copy or delete its source.';
  if (status.state === 'failed') return 'Copy verification could not finish. Raiun kept the saved operation; refresh before checking again.';
  if (status.state !== 'needs_review') return status.cancel_requested ? 'Stopping copy verification…' : 'Checking the saved copy…';
  switch (status.reason) {
    case 'legacy_binding_unavailable': return 'The original source binding is unavailable. Raiun kept the operation for manual review.';
    case 'never_attempted': return 'This copy was never sent. Raiun kept it for review and did not start an upload.';
    case 'source_scope_mismatch': return 'The original source belongs to a different account or location. Raiun kept it for review.';
    case 'source_changed': return 'The original source changed. Raiun kept the copy for review and did not upload it.';
    case 'destination_changed': return 'The cloud destination changed. Raiun kept the copy and did not replace the destination.';
    case 'content_mismatch': return 'The destination content does not match this saved copy. Raiun kept it for review.';
    case 'authentication_generation_changed': return 'The account session changed during verification. Refresh the operation status.';
    case 'verification_unavailable': return 'Raiun could not verify this copy. It kept the operation for review.';
    default: throw new Error('The agent returned an invalid copy verification status.');
  }
}
