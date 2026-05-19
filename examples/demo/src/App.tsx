import { lazy, Suspense } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import apiReferenceMd from '../../../docs/api-reference.md?raw';
import gettingStartedMd from '../../../docs/getting-started.md?raw';
import privacyMd from '../../../docs/privacy.md?raw';
import securityMd from '../../../docs/security.md?raw';
import threatModelMd from '../../../docs/threat-model.md?raw';
import { Landing } from './components/Landing';
import { useSession } from './context/session';
import { Account } from './pages/Account';
import { Demo } from './pages/Demo';

const DocPage = lazy(() => import('./pages/DocPage').then(m => ({ default: m.DocPage })));
const NotFound = lazy(() => import('./pages/NotFound').then(m => ({ default: m.NotFound })));

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
      <Suspense fallback={null}>
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
          <Route
            path="/docs/getting-started"
            element={
              <DocPage title="getting started" slug="getting-started" content={gettingStartedMd} />
            }
          />
          <Route
            path="/docs/security"
            element={<DocPage title="security" slug="security" content={securityMd} />}
          />
          <Route
            path="/docs/privacy"
            element={<DocPage title="privacy" slug="privacy" content={privacyMd} />}
          />
          <Route
            path="/docs/threat-model"
            element={<DocPage title="threat model" slug="threat-model" content={threatModelMd} />}
          />
          <Route
            path="/docs/api-reference"
            element={
              <DocPage title="api reference" slug="api-reference" content={apiReferenceMd} />
            }
          />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
