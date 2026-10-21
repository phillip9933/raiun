export function providerAvailable(providerSupported: boolean | undefined): boolean {
  return providerSupported !== false;
}

/** Load sync data only when the agent advertises its filesystem provider. */
export async function loadProviderSyncData<TPair, TTransfer>(
  providerSupported: boolean | undefined,
  connected: boolean,
  request: (action: string) => Promise<unknown>,
): Promise<{ pairs: TPair[]; transfers: TTransfer[] }> {
  if (!providerAvailable(providerSupported)) return { pairs: [], transfers: [] };

  const pairsPromise = request('pairs') as Promise<TPair[]>;
  if (!connected) return { pairs: await pairsPromise, transfers: [] };
  const [pairs, transfers] = await Promise.all([
    pairsPromise,
    request('transfers') as Promise<TTransfer[]>,
  ]);
  return { pairs, transfers };
}
