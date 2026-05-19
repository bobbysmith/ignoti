import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Landing } from './components/Landing';
import { useSession } from './context/session';
import { Account } from './pages/Account';
import { Demo } from './pages/Demo';

export function App() {
  const { session, restoring, persistedUserId } = useSession();

  if (restoring) {
    return (
      <div className="container">
        <p>{persistedUserId ? `welcome back ${persistedUserId}` : '-'}</p>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route
          path="/demo"
          element={session ? <Navigate to="/demo/account" replace /> : <Demo />}
        />
        <Route
          path="/demo/account"
          element={session ? <Account /> : <Navigate to="/demo" replace />}
        />
      </Routes>
    </BrowserRouter>
  );
}
