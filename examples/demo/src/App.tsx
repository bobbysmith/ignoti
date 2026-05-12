import { useEffect, useRef, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Landing } from './components/Landing';
import { ghost } from './ghost';
import { Account } from './pages/Account';
import { Demo } from './pages/Demo';
import type { SessionInfo } from './types';

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [restoring, setRestoring] = useState(true);
  const restored = useRef(false);

  useEffect(() => {
    if (restored.current) {
      return;
    }
    restored.current = true;

    async function restore() {
      try {
        await ghost.restoreSession();
        setSession(ghost.getSession());
      } catch {
        // no session to restore
      } finally {
        setRestoring(false);
      }
    }
    void restore();
  }, []);

  if (restoring) {
    return (
      <div className="container">
        <p>-</p>
      </div>
    );
  }

  function handleSession(s: SessionInfo) {
    setSession(s);
  }

  function handleLogout() {
    setSession(null);
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          path="/demo"
          element={
            session ? <Navigate to="/demo/account" replace /> : <Demo onSession={handleSession} />
          }
        />
        <Route
          path="/demo/account"
          element={
            session ? (
              <Account session={session} onLogout={handleLogout} />
            ) : (
              <Navigate to="/demo" replace />
            )
          }
        />
      </Routes>
    </BrowserRouter>
  );
}
