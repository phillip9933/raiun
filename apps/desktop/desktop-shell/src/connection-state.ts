export type ConnectionStatus = {
  connected?: boolean;
  offline_namespace?: boolean;
  /** Retained Windows sign-in awaiting refresh; does not grant offline file access. */
  offline?: boolean;
};

export type ConnectionMode = 'unavailable' | 'connected' | 'offline_reconnecting' | 'sign_in';

export function connectionMode(reachable: boolean, status: ConnectionStatus | null | undefined): ConnectionMode {
  if (!reachable) return 'unavailable';
  if (status?.connected === true) return 'connected';
  if (status?.offline_namespace === true || status?.offline === true) return 'offline_reconnecting';
  return 'sign_in';
}
