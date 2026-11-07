type ActivityText = { title: string; detail: string };
type ObjectValue = Record<string, unknown>;

function object(value: unknown): ObjectValue | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as ObjectValue : null;
}
function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
function duration(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

// This describes observed owned creation work, never remaining-file totals,
// file contents, upload success or the completion of a file-manager copy.
export function windowsDriveActivityText(value: unknown): ActivityText {
  const unavailable = {
    title: 'Drive upload activity unavailable',
    detail: 'The agent has no current activity observation for this drive. Pending files and cloud completion remain unconfirmed.',
  };
  const outer = object(value);
  if (!outer || outer.state !== 'observed' || !count(outer.observation_age_ms)
    || typeof outer.owner_step_in_progress !== 'boolean') return unavailable;
  const activity = object(outer.activity);
  if (!activity || typeof activity.held !== 'boolean' || !Array.isArray(activity.lanes)
    || activity.lanes.length > 4 || !count(activity.waiting_batches)
    || !count(activity.queued_hints) || !count(activity.cursor_remaining)
    || !count(activity.pending_files)) return unavailable;
  let files = 0;
  let folders = 0;
  let other = 0;
  let held = 0;
  const phases = { prepare: 0, send: 0, refresh: 0 };
  let oldest: number | null = null;
  for (const raw of activity.lanes) {
    const lane = object(raw);
    if (!lane || typeof lane.active !== 'boolean' || typeof lane.held !== 'boolean'
      || typeof lane.kind !== 'string' || !['file', 'directory', 'other'].includes(lane.kind)
      || typeof lane.phase !== 'string' || !['prepare', 'send', 'refresh', 'unknown'].includes(lane.phase)
      || (lane.age_since_accepted_ms !== null && !count(lane.age_since_accepted_ms))) return unavailable;
    if (!lane.active) continue;
    if (lane.held) { held++; continue; }
    if (lane.kind === 'file') files++;
    else if (lane.kind === 'directory') folders++;
    else other++;
    if (lane.phase === 'prepare' || lane.phase === 'send' || lane.phase === 'refresh') phases[lane.phase]++;
    if (count(lane.age_since_accepted_ms)) oldest = Math.max(oldest ?? 0, lane.age_since_accepted_ms);
  }
  const total = files + folders + other;
  const parts: string[] = [];
  if (total) parts.push(`Last observed: ${files} file, ${folders} folder${other ? ` and ${other} other` : ''} operations.`);
  else if (activity.waiting_batches || activity.queued_hints || activity.cursor_remaining || activity.pending_files) {
    parts.push('Drive changes were waiting to be processed at the last observation.');
  } else parts.push('No active file uploads or folder creation were reported in the last observation.');
  if (held) parts.push(`Retained operations needing review: ${held}.`);
  if (phases.prepare) parts.push(`Preparing: ${phases.prepare}.`);
  if (phases.send) parts.push(`Sending and checking uploads: ${phases.send}.`);
  if (phases.refresh) parts.push(`Refreshing uploaded files: ${phases.refresh}.`);
  if (outer.owner_step_in_progress) parts.push('The agent was processing a drive update.');
  if (oldest !== null) parts.push(`Oldest accepted task: ${duration(oldest)}, including waiting.`);
  parts.push(`Observed ${duration(outer.observation_age_ms)} ago. Remaining files and cloud completion are unconfirmed.`);
  return { title: activity.held || held ? 'Drive creation needs attention' : 'Drive upload and folder activity', detail: parts.join(' ') };
}
