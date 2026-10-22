export function providerAvailable(providerSupported: boolean | undefined): boolean {
  return providerSupported !== false;
}

/** Feature omissions preserve older agents; explicit false never widens a provider. */
export function providerFeatureAvailable(providerSupported: boolean | undefined, featureSupported: boolean | undefined): boolean {
  return providerAvailable(providerSupported) && featureSupported !== false;
}

/** Load sync data only when the agent advertises its filesystem provider. */
export async function loadProviderSyncData<TPair, TTransfer>(
  providerSupported: boolean | undefined,
  connected: boolean,
  request: (action: string) => Promise<unknown>,
  folderSyncSupported?: boolean,
): Promise<{ pairs: TPair[]; transfers: TTransfer[] }> {
  if (!providerFeatureAvailable(providerSupported, folderSyncSupported)) return { pairs: [], transfers: [] };

  const pairsPromise = request('pairs') as Promise<TPair[]>;
  if (!connected) return { pairs: await pairsPromise, transfers: [] };
  const [pairs, transfers] = await Promise.all([
    pairsPromise,
    request('transfers') as Promise<TTransfer[]>,
  ]);
  return { pairs, transfers };
}
