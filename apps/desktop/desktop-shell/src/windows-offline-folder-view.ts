import type {
  WindowsOfflineFolderControllerState,
  WindowsOfflineFolderJob,
  WindowsOfflineFolderRow
} from './windows-offline-folder';

export type WindowsOfflineFolderViewProps = {
  folderRows: readonly WindowsOfflineFolderRow[];
  currentSelection: WindowsOfflineFolderRow | null;
  knownJobRow: WindowsOfflineFolderRow | null;
  loading: boolean;
  error: string;
  loaded: boolean;
  nextCursor: string | null;
  unavailableRows: number;
  actionsAvailable: boolean;
  intentMessage: string | null;
  controller: WindowsOfflineFolderControllerState;
  canSave: boolean;
  canResume: boolean;
  canRefresh: boolean;
  resumePinId?: string | null;
  refreshActivePinId?: string | null;
  refreshStagingPinId?: string | null;
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character]!);
}

function key(row: WindowsOfflineFolderRow): string {
  return JSON.stringify({
    space_id: row.spaceId,
    root_resource_id: row.rootResourceId,
    path: row.path,
    resource_id: row.resourceId
  });
}

function sameRow(left: WindowsOfflineFolderRow | null, right: WindowsOfflineFolderRow): boolean {
  return left !== null && key(left) === key(right);
}

function folderName(path: string): string {
  return path === '/' ? 'Drive root' : path.split('/').filter(Boolean).at(-1) ?? path;
}

function jobMessage(job: WindowsOfflineFolderJob): string {
  switch (job.state) {
    case 'prepared': return 'Folder job is prepared. Start it to continue.';
    case 'running': return job.cancel_requested ? 'Stopping the folder download…' : 'Saving this folder for offline use…';
    case 'complete': return 'This folder is saved for offline use.';
    case 'cancelled': return 'The folder download was cancelled. Any verified files remain saved.';
    case 'failed': return 'The folder download could not finish. Verified files remain available; use an available saved-folder action to continue.';
    case 'recovery_required': return 'This folder download needs recovery. Keep the files and review recovery before retrying.';
  }
}

function progressText(job: WindowsOfflineFolderControllerState['job']): string {
  if (!job?.folder) return '';
  const folder = job.folder;
  if (folder.state === 'ready') return `${folder.ready_content_count} of ${folder.required_content_count} files verified.`;
  if (folder.state === 'building') return `${folder.ready_content_count} of ${folder.required_content_count} files verified so far.`;
  if (folder.state === 'stale') return 'The saved folder listing changed. Refresh it before continuing.';
  return 'This saved folder snapshot is no longer available.';
}

export function renderWindowsOfflineFolderPanel(props: WindowsOfflineFolderViewProps): string {
  const { controller, currentSelection, actionsAvailable } = props;
  const busy = props.loading || controller.loading;
  const uncertain = controller.admissionUncertain;
  const active = controller.job?.state === 'running' || controller.job?.state === 'prepared';
  const listLocked = active || uncertain;
  const startDisabled = !actionsAvailable || busy || uncertain || active;
  const rows = props.loaded
    ? props.folderRows.length
      ? `<div class="windows-offline-folder-list">${props.folderRows.map((row) => {
          const selected = sameRow(currentSelection, row);
          const encoded = escapeHtml(key(row));
          return `<button class="remote-entry ${selected ? 'selected' : ''}" data-windows-offline-folder-row="${encoded}" aria-pressed="${selected}" ${busy || listLocked ? 'disabled' : ''}><span>${escapeHtml(row.spaceLabel)} · ${escapeHtml(folderName(row.path))}</span><small>${escapeHtml(row.path)}</small></button>`;
        }).join('')}</div>`
      : '<div class="recovery-empty" role="status">No folders were returned in this listing.</div>'
    : '';
  const job = controller.job;
  const knownJobRow = props.knownJobRow;
  const knownJobMatchesSelection = knownJobRow != null && currentSelection !== null &&
    key(knownJobRow) === key(currentSelection);
  const jobMatchesSelection = Boolean(job?.folder && currentSelection &&
    job.folder.root_resource_id === currentSelection.resourceId && job.folder.path === currentSelection.path);
  const terminalActionAllowed = job?.state === 'complete' || job?.state === 'cancelled' || job?.state === 'failed';
  const canUseTerminalRole = Boolean(terminalActionAllowed && !uncertain && knownJobMatchesSelection);
  const roleActions = `${props.canResume && props.resumePinId ? `<button class="button subtle" data-action="resume-windows-offline-folder" data-pin-id="${escapeHtml(props.resumePinId)}" ${startDisabled ? 'disabled' : ''}>Continue saved folder</button>` : ''}${props.canRefresh && props.refreshActivePinId ? `<button class="button subtle" data-action="refresh-windows-offline-folder" data-pin-id="${escapeHtml(props.refreshActivePinId)}" data-staging-pin-id="${escapeHtml(props.refreshStagingPinId ?? '')}" ${startDisabled ? 'disabled' : ''}>Refresh saved folder</button>` : ''}`;
  const jobDetail = job
    ? `<div class="windows-offline-folder-job"><b>${knownJobRow ? `${escapeHtml(knownJobRow.spaceLabel)} · ` : ''}${job.folder ? escapeHtml(folderName(job.folder.path)) : knownJobRow ? escapeHtml(folderName(knownJobRow.path)) : 'Folder download'}</b>${knownJobRow ? `<small>${escapeHtml(knownJobRow.path)}</small>` : job.folder ? `<small>${escapeHtml(job.folder.path)}</small>` : ''}<p role="status" aria-live="polite">${escapeHtml(jobMessage(job))} ${escapeHtml(progressText(job))}</p>${knownJobMatchesSelection && props.intentMessage ? `<p class="recovery-hint" role="status">${escapeHtml(props.intentMessage)}</p>` : ''}<div class="button-group">${active ? `<button class="button subtle" data-action="poll-windows-offline-folder" ${!actionsAvailable || busy ? 'disabled' : ''}>Check folder status</button><button class="button subtle" data-action="cancel-windows-offline-folder" ${!actionsAvailable || busy ? 'disabled' : ''}>Cancel folder download</button>` : ''}${canUseTerminalRole ? roleActions : ''}</div>${uncertain ? '<small role="status">The request may still be running. Check or cancel this folder job before starting another.</small>' : ''}</div>`
    : '';
  const detail = job && !jobMatchesSelection
    ? jobDetail
    : currentSelection
    ? `<div class="windows-offline-folder-detail"><div><b>${escapeHtml(currentSelection.spaceLabel)} · ${escapeHtml(folderName(currentSelection.path))}</b><small>${escapeHtml(currentSelection.path)}</small></div>${controller.error ? `<div class="recovery-warning" role="alert">${escapeHtml(controller.error)}</div>` : ''}${jobDetail || '<p role="status">Choose an action to save this folder and its listed files offline.</p>'}${!job && props.intentMessage ? `<p class="recovery-hint" role="status">${escapeHtml(props.intentMessage)}</p>` : ''}${!job ? `<div class="button-group"><button class="button primary" data-action="start-windows-offline-folder" ${startDisabled || !props.canSave ? 'disabled' : ''}>${busy ? 'Preparing…' : 'Save folder offline'}</button>${roleActions}</div>` : ''}</div>`
    : jobDetail;

  return `<section class="settings-card windows-offline-folders-card"><div class="settings-heading"><span class="settings-icon" aria-hidden="true">📁</span><div><h2>Save folders offline</h2><p>Choose an already listed folder. Its files are checked before they are saved.</p></div></div><div class="settings-row"><div><b>Available folders</b><small>Folders from this account’s Windows drive.</small></div><div class="button-group"><button class="button subtle" data-action="refresh-windows-offline-folders" ${!actionsAvailable || busy || listLocked ? 'disabled' : ''}>${busy ? 'Loading…' : props.loaded ? 'Refresh folders' : 'Load folders'}</button><button class="button subtle" data-action="more-windows-offline-folders" ${!actionsAvailable || busy || listLocked || !props.nextCursor ? 'disabled' : ''}>Load next page</button></div></div>${props.error ? `<div class="recovery-warning" role="alert">${escapeHtml(props.error)}</div>` : ''}${props.unavailableRows ? `<p class="recovery-hint" role="status">${props.unavailableRows} folders could not be shown. Refresh to check again.</p>` : ''}${rows}${detail}</section>`;
}
