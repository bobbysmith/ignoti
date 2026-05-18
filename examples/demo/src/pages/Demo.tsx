import { useState } from 'react';
import { AuthForm } from '../components/AuthForm';
import { AuthModal } from '../components/AuthModal';
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
      <header className="app-header">
        <span className="app-header-logo">ghostid://rave</span>
        <div className="app-header-actions">
          <button type="button" className="link-btn" onClick={() => setAuthView('login')}>
            sign in
          </button>
        </div>
      </header>

      <main className="app-main app-main--centered">
        <div className="flyer">
          <h1 className="flyer-title">GHOST RAVE</h1>
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
