import type React from 'react';
import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { ghost } from '../ghost';
import type { SessionInfo } from '../types';

const STORAGE_KEY = 'ghostid_userId';

interface SessionContextValue {
  session: SessionInfo | null;
  restoring: boolean;
  persistedUserId: string | null;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [restoring, setRestoring] = useState(true);
  const [persistedUserId, setPersistedUserId] = useState<string | null>(
    () => localStorage.getItem(STORAGE_KEY)
  );
  const restored = useRef(false);

  useEffect(() => {
    if (session) {
      localStorage.setItem(STORAGE_KEY, session.userId);
      setPersistedUserId(session.userId);
    } else if (!restoring) {
      localStorage.removeItem(STORAGE_KEY);
      setPersistedUserId(null);
    }
  }, [session, restoring]);

  useEffect(() => {
    if (restored.current) {
      return;
    }
    restored.current = true;

    ghost.onSessionChange(setSession);

    async function restore() {
      try {
        await ghost.restoreSession();
      } catch {
        // no session to restore
      } finally {
        setRestoring(false);
      }
    }
    void restore();
  }, []);

  return (
    <SessionContext.Provider value={{ session, restoring, persistedUserId }}>
      {children}
    </SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) {
    throw new Error('useSession must be used within SessionProvider');
  }
  return ctx;
}
