import { useRef, useState } from 'react';
import type { SessionInfo } from '@/types';
import { ghost } from '../ghost';
import type { AuthView } from '../types';
import { MnemonicView } from './MnemonicView';

export function AuthForm({
  view,
  onSession,
  onSwitchView,
}: {
  view: AuthView;
  onSession: (s: SessionInfo) => void;
  onSwitchView: (v: AuthView) => void;
}) {
  const mnemonicRef = useRef<HTMLInputElement>(null);
  const [newMnemonic, setNewMnemonic] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLogin() {
    setLoading(true);
    setError(null);
    try {
      const s = await ghost.login();
      onSession(s);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function handleSignup() {
    setLoading(true);
    setError(null);
    try {
      const result = await ghost.createIdentity();
      setNewMnemonic(result.mnemonic);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function handleRecover() {
    setLoading(true);
    setError(null);
    try {
      await ghost.recoverIdentity(mnemonicRef.current?.value ?? '');
      const s = await ghost.login();
      onSession(s);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  if (view === 'login') {
    return (
      <>
        <p>Authenticate with your passkey.</p>
        <button type="button" onClick={handleLogin} disabled={loading}>
          {loading ? 'authenticating...' : '→ sign in with passkey'}
        </button>
        <p className="modal-footer">
          no account?{' '}
          <button type="button" className="link-btn" onClick={() => onSwitchView('signup')}>
            sign up
          </button>
          {' · '}
          <button type="button" className="link-btn" onClick={() => onSwitchView('recover')}>
            recover account
          </button>
        </p>
        {error && <p>error: {error}</p>}
      </>
    );
  }

  if (view === 'signup') {
    if (newMnemonic) {
      return (
        <MnemonicView
          mnemonic={newMnemonic}
          onContinue={() => {
            setNewMnemonic(null);
            void handleLogin();
          }}
        />
      );
    }
    return (
      <>
        <p>Create a new identity. A passkey will be registered on this device.</p>
        <button type="button" onClick={handleSignup} disabled={loading}>
          {loading ? 'creating...' : '→ create identity'}
        </button>
        <p className="modal-footer">
          already have an account?{' '}
          <button type="button" className="link-btn" onClick={() => onSwitchView('login')}>
            sign in
          </button>
        </p>
        {error && <p>error: {error}</p>}
      </>
    );
  }

  return (
    <>
      <p>Enter your 12-word recovery phrase to register this device.</p>
      <input ref={mnemonicRef} placeholder="word1 word2 word3 ..." style={{ width: '100%' }} />
      <br />
      <br />
      <button type="button" onClick={handleRecover} disabled={loading}>
        {loading ? 'recovering...' : '→ recover identity'}
      </button>
      <p className="modal-footer">
        <button type="button" className="link-btn" onClick={() => onSwitchView('login')}>
          back to sign in
        </button>
      </p>
      {error && <p>error: {error}</p>}
    </>
  );
}
