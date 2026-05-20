import { useEffect, useRef, useState } from 'react';
import { Header } from '../components/Header';
import { useSession } from '../context/session';
import { ghost } from '../ghost';

export function Account() {
  const { session } = useSession();
  const [devices, setDevices] = useState<Awaited<ReturnType<typeof ghost.getDevices>> | null>(null);
  const [sessions, setSessions] = useState<Awaited<ReturnType<typeof ghost.getSessions>> | null>(
    null
  );
  const [loggingOut, setLoggingOut] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<{
    deviceId: string;
    credentialId: string;
  } | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const mnemonicRef = useRef<HTMLInputElement>(null);
  const [signedHeaders, setSignedHeaders] = useState<Record<string, string> | null>(null);

  useEffect(() => {
    ghost
      .getDevices()
      .then(setDevices)
      .catch(() => {});
    ghost
      .getSessions()
      .then(setSessions)
      .catch(() => {});
  }, []);

  if (!session) {
    return null;
  }

  async function handleRevokeSession(sessionId: string) {
    const currentSession = session;
    if (!currentSession) return;
    setSessionError(null);
    try {
      await ghost.revokeSession(sessionId);
      if (sessionId === currentSession.sessionId) {
        return;
      }
      ghost
        .getSessions()
        .then(setSessions)
        .catch(() => {});
    } catch (e) {
      setSessionError((e as Error).message);
    }
  }

  async function handleRevokeDevice() {
    if (!revokeTarget) return;
    const mnemonic = mnemonicRef.current?.value ?? '';
    setDeviceError(null);
    try {
      await ghost.revokeDevice(
        revokeTarget.deviceId,
        mnemonic,
        session?.userId ?? '',
        revokeTarget.credentialId
      );
      setRevokeTarget(null);
      ghost
        .getDevices()
        .then(setDevices)
        .catch(() => {});
    } catch (e) {
      setDeviceError((e as Error).message);
    }
  }

  async function handleLogout() {
    setLoggingOut(true);
    try {
      await ghost.logout();
    } finally {
      setLoggingOut(false);
    }
  }

  async function handleSignRequest() {
    try {
      const headers = await ghost.getSessionHeaders('GET', '/api/my-app/feed');
      setSignedHeaders(headers);
    } catch {
      setSignedHeaders(null);
    }
  }

  return (
    <>
      <Header slug="demo" />

      <main className="app-main">
        <div
          className="dashboard-section"
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}
        >
          <button
            type="button"
            className="link-btn"
            onClick={handleLogout}
            disabled={loggingOut}
            style={{ marginLeft: 'auto' }}
          >
            {loggingOut ? 'leaving...' : '→ leave'}
          </button>
        </div>
        <div className="dashboard-section">
          <h2>session</h2>
          <table>
            <tbody>
              <tr>
                <td>user</td>
                <td>{session.userId}</td>
              </tr>
              <tr>
                <td>session</td>
                <td>{session.sessionId}</td>
              </tr>
              <tr>
                <td>device</td>
                <td>{session.deviceId}</td>
              </tr>
              <tr>
                <td>expires</td>
                <td>{new Date(session.expiresAt).toLocaleString()}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="dashboard-section">
          <h2>session signing</h2>
          <p>
            Call <code>getSessionHeaders</code> to authenticate requests from your app to your own
            backend. GhostID&apos;s server middleware validates the resulting headers.
          </p>
          <button type="button" onClick={handleSignRequest}>
            → sign GET /api/my-app/feed
          </button>
          {signedHeaders && (
            <pre style={{ marginTop: '1rem', overflowX: 'auto' }}>
              {JSON.stringify(signedHeaders, null, 2)}
            </pre>
          )}
        </div>

        <div className="dashboard-section">
          <h2>devices</h2>
          {deviceError && <p style={{ color: 'var(--error-color)' }}>error: {deviceError}</p>}
          {devices === null ? (
            <p>loading...</p>
          ) : devices.length === 0 ? (
            <p>none</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>name</th>
                  <th>registered</th>
                  <th>last used</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {devices.map(d => (
                  <>
                    <tr key={d.id}>
                      <td>{d.deviceName ?? 'unnamed'}</td>
                      <td>{new Date(d.createdAt).toLocaleString()}</td>
                      <td>{d.lastUsedAt ? new Date(d.lastUsedAt).toLocaleString() : '—'}</td>
                      <td>
                        <button
                          type="button"
                          onClick={() =>
                            setRevokeTarget(
                              revokeTarget?.deviceId === d.id
                                ? null
                                : { deviceId: d.id, credentialId: d.credentialId }
                            )
                          }
                        >
                          {revokeTarget?.deviceId === d.id ? 'cancel' : 'revoke'}
                        </button>
                      </td>
                    </tr>
                    {revokeTarget?.deviceId === d.id && (
                      <tr key={`${d.id}-revoke`}>
                        <td colSpan={4}>
                          <input
                            ref={mnemonicRef}
                            placeholder="enter recovery phrase to confirm"
                            style={{ width: '100%' }}
                          />
                          <button type="button" onClick={handleRevokeDevice}>
                            → confirm revoke
                          </button>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="dashboard-section">
          <h2>sessions</h2>
          {sessionError && <p style={{ color: 'var(--error-color)' }}>error: {sessionError}</p>}
          {sessions === null ? (
            <p>loading...</p>
          ) : sessions.length === 0 ? (
            <p>none</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>session</th>
                  <th>created</th>
                  <th>expires</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => (
                  <tr key={s.id}>
                    <td>
                      {s.id.slice(0, 8)}…{s.isCurrent ? ' (this)' : ''}
                    </td>
                    <td>{new Date(s.createdAt).toLocaleString()}</td>
                    <td>{new Date(s.expiresAt).toLocaleString()}</td>
                    <td>
                      <button type="button" onClick={() => handleRevokeSession(s.id)}>
                        revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </main>
    </>
  );
}
