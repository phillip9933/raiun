export type FolderDirection = 'both_ways' | 'to_cloud' | 'from_cloud';
export type ExistingCopyHandling = 'update_safe' | 'review';
export type FolderCreationRoute = { kind: 'pair'; mode: 'two_way' | 'upload_only' | 'download_only' } | { kind: 'media_import' };

export function folderCreationRoute(direction: FolderDirection, handling: ExistingCopyHandling): FolderCreationRoute {
  if (direction === 'to_cloud' && handling === 'review') return { kind: 'media_import' };
  return { kind: 'pair', mode: direction === 'both_ways' ? 'two_way' : direction === 'to_cloud' ? 'upload_only' : 'download_only' };
}

export function folderWorkspaceSpaceIds(pairSpaceIds: string[], importSpaceIds: string[], spaces: Array<{ id: string; personal: boolean }>): string[] {
  const used = new Set([...pairSpaceIds, ...importSpaceIds]);
  return [
    ...spaces.filter(space => space.personal && used.has(space.id)).map(space => space.id),
    ...spaces.filter(space => !space.personal && used.has(space.id)).map(space => space.id),
    ...[...used].filter(id => !spaces.some(space => space.id === id))
  ];
}
