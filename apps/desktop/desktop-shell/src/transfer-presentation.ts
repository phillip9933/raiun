export type TransferTab = 'active' | 'attention' | 'history';
export type TransferTone = 'neutral' | 'info' | 'success' | 'warning' | 'danger';
export type TransferDirection = 'upload' | 'download' | 'folder_create' | 'delete' | 'rename' | 'cloud_check' | 'cache_read' | 'cloud_activity' | 'unknown';

type Presentation = {
  tab: TransferTab;
  label: string;
  help: string;
  tone: TransferTone;
  direction: TransferDirection;
};

const ACTIVE_STATES: Record<string, Omit<Presentation, 'direction'>> = {
  queued: { tab: 'active', label: 'Queued', help: 'Waiting for a transfer slot.', tone: 'neutral' },
  running: { tab: 'active', label: 'In progress', help: 'Transfer is running.', tone: 'info' },
  retry_wait: { tab: 'active', label: 'Retrying soon', help: 'Raiun will retry when it is safe to continue.', tone: 'warning' },
  verifying: { tab: 'active', label: 'Checking cloud copy', help: 'The transfer is still being checked; it is not complete yet.', tone: 'info' },
  paused: { tab: 'active', label: 'Paused', help: 'Transfer is paused and can be resumed when ready.', tone: 'neutral' }
};

const ATTENTION_STATES: Record<string, Omit<Presentation, 'direction'>> = {
  failed: { tab: 'attention', label: 'Recorded issue', help: 'A failed operation is recorded here. This may be historical; Saved uploads and edits shows local files that still need review.', tone: 'danger' },
  conflict: { tab: 'attention', label: 'Needs review', help: 'This operation recorded a conflict. Review the saved files and current cloud copy before continuing.', tone: 'warning' },
  needs_review: { tab: 'attention', label: 'Needs review', help: 'The cloud check found a missing or different copy. The saved local file remains for review; it was not resent or replaced.', tone: 'warning' },
  awaiting_authentication: { tab: 'attention', label: 'Sign-in needed', help: 'This record notes that sign-in was needed. Reconnect if this account still needs it.', tone: 'warning' }
};

const HISTORY_STATES: Record<string, Omit<Presentation, 'direction'>> = {
  completed: { tab: 'history', label: 'Completed', help: 'Transfer completed and was verified.', tone: 'success' },
  cancelled: { tab: 'history', label: 'Cancelled', help: 'Transfer was cancelled; this does not mean the cloud copy completed.', tone: 'neutral' }
};

function normalized(value: string | null | undefined): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function parseDirection(value: string | null | undefined, operation?: string | null): TransferDirection {
  const action = normalized(operation);
  if (action === 'cache_read') return 'cache_read';
  if (['mkdir', 'create_folder', 'create_directory', 'folder_create'].includes(action)) return 'folder_create';
  if (action === 'delete' || action === 'remove') return 'delete';
  if (action === 'rename' || action === 'move') return 'rename';
  if (['verify_upload', 'verify', 'verification', 'cloud_check'].includes(action)) return 'cloud_check';
  const direction = normalized(value);
  if (direction === 'upload' || direction === 'up') return 'upload';
  if (direction === 'download' || direction === 'down') return 'download';
  if (['cloud', 'metadata', 'cloud_activity'].includes(direction)) return 'cloud_activity';
  return 'unknown';
}

export function transferPresentation(state?: string | null, direction?: string | null, operation?: string | null): Presentation {
  const key = normalized(state);
  const states = [ACTIVE_STATES, ATTENTION_STATES, HISTORY_STATES];
  const known = states.find(table => Object.hasOwn(table, key))?.[key];
  if (known) return { ...known, direction: parseDirection(direction, operation) };
  return {
    tab: 'attention',
    label: 'Status unavailable',
    help: 'Refresh the transfer list. If the status remains unavailable, check for a Raiun update.',
    tone: 'warning',
    direction: parseDirection(direction, operation)
  };
}

const TAB_SUMMARIES: Record<TransferTab, { label: string; description: string; emptyTitle: string; emptyHelp: string }> = {
  active: {
    label: 'Active',
    description: 'Provider operations that are queued, running, paused, retrying, or being checked.',
    emptyTitle: 'No active provider operations',
    emptyHelp: 'New folder-sync and cloud-file operations will appear here.'
  },
  attention: {
    label: 'Recent issues',
    description: 'Recent provider records with a failure, conflict, sign-in request, or unknown status. A recorded issue may already be resolved.',
    emptyTitle: 'No recent provider issues',
    emptyHelp: 'Recent issues will appear here. Saved uploads and edits shows local files that still need review.'
  },
  history: {
    label: 'Recent activity',
    description: 'Recent completed or cancelled provider activity.',
    emptyTitle: 'No recent provider activity',
    emptyHelp: 'Recent completed and cancelled provider operations will appear here. Saved edits and recovery records are listed separately.'
  }
};

export function transferTabSummary(tab: TransferTab): { label: string; description: string; emptyTitle: string; emptyHelp: string } {
  return { ...TAB_SUMMARIES[tab] };
}

export function transferCounts(items: { state?: string | null; direction?: string | null }[]): Record<TransferTab, number> {
  const counts: Record<TransferTab, number> = { active: 0, attention: 0, history: 0 };
  for (const item of items) counts[transferPresentation(item.state, item.direction).tab] += 1;
  return counts;
}
