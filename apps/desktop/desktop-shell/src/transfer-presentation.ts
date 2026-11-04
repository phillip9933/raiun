export type TransferTab = 'active' | 'attention' | 'history';
export type TransferTone = 'neutral' | 'info' | 'success' | 'warning' | 'danger';
export type TransferDirection = 'upload' | 'download' | 'unknown';

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
  failed: { tab: 'attention', label: 'Failed', help: 'Review the error before trying again.', tone: 'danger' },
  conflict: { tab: 'attention', label: 'Conflict', help: 'Review the conflicting copy before continuing.', tone: 'warning' },
  awaiting_authentication: { tab: 'attention', label: 'Sign-in needed', help: 'Sign in to continue this transfer.', tone: 'warning' }
};

const HISTORY_STATES: Record<string, Omit<Presentation, 'direction'>> = {
  completed: { tab: 'history', label: 'Completed', help: 'Transfer completed and was verified.', tone: 'success' },
  cancelled: { tab: 'history', label: 'Cancelled', help: 'Transfer was cancelled; this does not mean the cloud copy completed.', tone: 'neutral' }
};

function normalized(value: string | null | undefined): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function parseDirection(value: string | null | undefined): TransferDirection {
  const direction = normalized(value);
  if (direction === 'upload' || direction === 'up') return 'upload';
  if (direction === 'download' || direction === 'down') return 'download';
  return 'unknown';
}

export function transferPresentation(state?: string | null, direction?: string | null): Presentation {
  const key = normalized(state);
  const states = [ACTIVE_STATES, ATTENTION_STATES, HISTORY_STATES];
  const known = states.find(table => Object.hasOwn(table, key))?.[key];
  if (known) return { ...known, direction: parseDirection(direction) };
  return {
    tab: 'attention',
    label: 'Status unavailable',
    help: 'Refresh the transfer list. If the status remains unavailable, check for a Raiun update.',
    tone: 'warning',
    direction: parseDirection(direction)
  };
}

const TAB_SUMMARIES: Record<TransferTab, { label: string; description: string; emptyTitle: string; emptyHelp: string }> = {
  active: {
    label: 'Current & paused',
    description: 'Transfers that are queued, running, paused, retrying, or being checked.',
    emptyTitle: 'No current or paused folder-sync transfers',
    emptyHelp: 'New folder-sync transfers will appear here.'
  },
  attention: {
    label: 'Needs attention',
    description: 'Transfers with an error, conflict, sign-in request, or unavailable status.',
    emptyTitle: 'No folder-sync transfers need attention',
    emptyHelp: 'Folder-sync transfers that need review will appear here.'
  },
  history: {
    label: 'History',
    description: 'Completed or cancelled folder-sync transfers.',
    emptyTitle: 'No folder-sync transfer history',
    emptyHelp: 'Completed and cancelled folder-sync transfers will appear here. Saved edits and recovery records are listed separately.'
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
