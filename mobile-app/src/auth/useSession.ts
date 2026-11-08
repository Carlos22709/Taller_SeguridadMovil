import { useSyncExternalStore } from 'react';

import { session, type SessionState } from './session';

export function useSession(): SessionState {
  return useSyncExternalStore(session.subscribe, session.getState, session.getState);
}
