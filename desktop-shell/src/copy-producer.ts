export type CopyProducerError =
  | 'stale_generation'
  | 'offline'
  | 'scope_changed'
  | 'locked'
  | 'busy'
  | 'unavailable';

export type CopyProducerState = 'queued' | 'running' | 'copied' | 'cancelled' | 'failed' | 'needs_review';

export type CopyProducerStart = { accepted: true; job_id: string } | { accepted: false; error: CopyProducerError };

export type CopyProducerStatus = {
  job_id: string;
  auth_generation: number;
  state: CopyProducerState;
  cancel_requested: boolean;
  write_id?: string;
  revision?: number;
};

export type CopyProducerSourceExpectation = {
  spaceId: string;
  rootResourceId: string;
  resourceId: string;
  version: string;
  path: string;
};

export type CopyProducerDestinationExpectation = {
  spaceId: string;
  rootResourceId: string;
  parentResourceId: string;
  parentVersion: string;
  targetPath: string;
};

/** Everything whose change makes a producer reply stale, including both sides of the copy. */
export type CopyProducerContext = {
  profileId: string;
  accountEpoch: number;
  authGeneration: number;
  flowGeneration: number;
  source: CopyProducerSourceExpectation;
  destination: CopyProducerDestinationExpectation;
};

const errors = new Set<CopyProducerError>([
  'stale_generation', 'offline', 'scope_changed', 'locked', 'busy', 'unavailable'
]);
const states = new Set<CopyProducerState>(['queued', 'running', 'copied', 'cancelled', 'failed', 'needs_review']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validJobId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
}

function validContext(context: CopyProducerContext): boolean {
  if (!isRecord(context) || !isRecord(context.source) || !isRecord(context.destination)) return false;
  const strings = [
    context.profileId,
    context.source.spaceId,
    context.source.rootResourceId,
    context.source.resourceId,
    context.source.version,
    context.source.path,
    context.destination.spaceId,
    context.destination.rootResourceId,
    context.destination.parentResourceId,
    context.destination.parentVersion,
    context.destination.targetPath
  ];
  return Number.isSafeInteger(context.accountEpoch) && context.accountEpoch >= 0 &&
    Number.isSafeInteger(context.authGeneration) && context.authGeneration >= 0 &&
    Number.isSafeInteger(context.flowGeneration) && context.flowGeneration >= 0 &&
    strings.every((value) => typeof value === 'string' && value.length > 0);
}

export function copyProducerContextKey(context: CopyProducerContext): string {
  if (!validContext(context)) throw new Error('The copy context is invalid.');
  return JSON.stringify([
    context.profileId,
    context.accountEpoch,
    context.authGeneration,
    context.flowGeneration,
    context.source.spaceId,
    context.source.rootResourceId,
    context.source.resourceId,
    context.source.version,
    context.source.path,
    context.destination.spaceId,
    context.destination.rootResourceId,
    context.destination.parentResourceId,
    context.destination.parentVersion,
    context.destination.targetPath
  ]);
}

export function copyProducerContextMatches(expected: CopyProducerContext, current: CopyProducerContext): boolean {
  if (!validContext(expected) || !validContext(current)) return false;
  return copyProducerContextKey(expected) === copyProducerContextKey(current);
}

export function validateCopyProducerStart(value: unknown): CopyProducerStart {
  if (!isRecord(value)) throw new Error('The agent returned an invalid copy response.');
  const keys = Object.keys(value).sort().join(',');
  if (value.accepted === true && keys === 'accepted,job_id' && validJobId(value.job_id)) {
    return { accepted: true, job_id: value.job_id };
  }
  if (value.accepted === false && keys === 'accepted,error' && typeof value.error === 'string' && errors.has(value.error as CopyProducerError)) {
    return { accepted: false, error: value.error as CopyProducerError };
  }
  throw new Error('The agent returned an invalid copy response.');
}

export function validateCopyProducerStatus(
  value: unknown,
  expectedJobId: string,
  expectedGeneration: number
): CopyProducerStatus {
  if (!isRecord(value)) throw new Error('The agent returned an invalid copy status.');
  const baseKeys = 'auth_generation,cancel_requested,job_id,state';
  const keys = Object.keys(value).sort().join(',');
  const hasWriteId = Object.hasOwn(value, 'write_id');
  const hasRevision = Object.hasOwn(value, 'revision');
  const hasBinding = hasWriteId && hasRevision;
  const expectedKeys = hasBinding ? 'auth_generation,cancel_requested,job_id,revision,state,write_id' : baseKeys;
  if (keys !== expectedKeys || !validJobId(expectedJobId) || value.job_id !== expectedJobId ||
      !Number.isSafeInteger(expectedGeneration) || expectedGeneration < 0 ||
      !Number.isSafeInteger(value.auth_generation) || (value.auth_generation as number) < 0 || value.auth_generation !== expectedGeneration ||
      typeof value.state !== 'string' || !states.has(value.state as CopyProducerState) ||
      typeof value.cancel_requested !== 'boolean') {
    throw new Error('The agent returned an invalid copy status.');
  }
  if (value.state === 'copied' && !hasBinding) throw new Error('The agent returned an invalid copy status.');
  if (hasBinding && (typeof value.write_id !== 'string' || !/^[0-9a-f]{32}$/.test(value.write_id) ||
      !Number.isSafeInteger(value.revision) || (value.revision as number) <= 0)) {
    throw new Error('The agent returned an invalid copy status.');
  }
  return value as CopyProducerStatus;
}

export function copyProducerStartErrorMessage(error: CopyProducerError): string {
  switch (error) {
    case 'stale_generation': return 'Your account session changed. Refresh the locations before starting this copy.';
    case 'offline': return 'Connect to OpenCloud before starting this copy. The original file stays in place.';
    case 'scope_changed': return 'The source or destination changed. Refresh both locations before trying again.';
    case 'locked': return 'Unlock both locations before starting this copy.';
    case 'busy': return 'Another file operation is running. Wait for it to finish.';
    case 'unavailable': return 'Copy is unavailable right now. The original file stays in place.';
  }
}

export function copyProducerStatusMessage(status: CopyProducerStatus): string {
  switch (status.state) {
    case 'queued': return status.cancel_requested ? 'Stopping the copy…' : 'Preparing the copy…';
    case 'running': return status.cancel_requested ? 'Stopping the copy…' : 'Copying the file…';
    case 'copied': return 'Copy complete. The original file remains in place.';
    case 'cancelled': return 'Copy stopped. The original file remains in place.';
    case 'failed': return 'The copy could not finish. The original file remains in place.';
    case 'needs_review': return 'This copy needs review. The original file remains in place; check saved edits before trying again.';
  }
}
