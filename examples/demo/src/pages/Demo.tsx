import { useState } from 'react';
import { AuthForm } from '../components/AuthForm';
import { AuthModal } from '../components/AuthModal';
import { Header } from '../components/Header';
import type { AuthView } from '../types';

function modalTitle(view: AuthView): string {
  if (view === 'login') {
    return 'sign in';
  }
  if (view === 'recover') {
    return 'recover';
  }
  return 'sign up';
}

export function Demo() {
  const [authView, setAuthView] = useState<AuthView | null>(null);

  return (
    <>
      <Header slug="demo" />

      <main className="app-main app-main--centered">
        <div className="flyer">
          <h1 className="flyer-title">GHOST</h1>
          <button type="button" onClick={() => setAuthView('signup')}>
            → enter
          </button>
        </div>
      </main>

      {authView && (
        <AuthModal title={modalTitle(authView)} onClose={() => setAuthView(null)}>
          <AuthForm view={authView} onSession={() => {}} onSwitchView={setAuthView} />
        </AuthModal>
      )}
    </>
  );
}
