import type React from 'react';
import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { ghost } from '../ghost';
import type { SessionInfo } from '../types';

interface SessionContextValue {
  session: SessionInfo | null;
  restoring: boolean;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [restoring, setRestoring] = useState(true);
  const restored = useRef(false);

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
    <SessionContext.Provider value={{ session, restoring }}>{children}</SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) {
    throw new Error('useSession must be used within SessionProvider');
  }
  return ctx;
}
