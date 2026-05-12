import { Link } from 'react-router-dom';

function LandingPage() {
  return (
    <>
      <hr />

      <section>
        <h2>sign in. leave nothing behind.</h2>
        <p>Three layers of identity, each with a different lifetime and threat model:</p>
        <pre>{`┌─────────────────────────────────────────────────┐
│  root key       BIP39 mnemonic + Ed25519        │
│                 offline, recovery only          │
├─────────────────────────────────────────────────┤
│  device key     WebAuthn passkey                │
│                 registered per device           │
├─────────────────────────────────────────────────┤
│  session key    ephemeral Ed25519 (WebCrypto)   │
│                 lives in memory, signs requests │
└─────────────────────────────────────────────────┘`}</pre>
        <p>
          To create an identity you generate a 12-word mnemonic. From it we derive a root keypair
          that's never sent to the server whole, only the public key is registered. You then
          register a passkey on your device. From that point on, your passkey is your daily auth.
          The mnemonic stays offline and is only needed to add a new device or recover access.
        </p>
        <p>
          On login, the server issues a challenge. Your passkey signs it. The server verifies, then
          the SDK generates a fresh ephemeral keypair for the session. Every subsequent request is
          signed with that ephemeral key, the private key bytes never leave the WebCrypto subsystem.
        </p>
      </section>

      <hr />

      <section>
        <h2>no email. no name. no trace.</h2>
        <table>
          <thead>
            <tr>
              <th>stored</th>
              <th>not stored</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>root public key</td>
              <td>your name</td>
            </tr>
            <tr>
              <td>WebAuthn credential ID</td>
              <td>your email</td>
            </tr>
            <tr>
              <td>session metadata (expiry, device)</td>
              <td>your phone number</td>
            </tr>
            <tr>
              <td>last used timestamps</td>
              <td>your IP address (linked to you)</td>
            </tr>
            <tr>
              <td></td>
              <td>any PII whatsoever</td>
            </tr>
          </tbody>
        </table>
        <p>
          The server knows a public key exists and that someone with the matching private key
          authenticated. It cannot tell you who that someone is.
        </p>
      </section>

      <hr />

      <section>
        <h2>how it stays that way.</h2>
        <ul>
          <li>
            <strong>Non-extractable private keys.</strong> Session and root private keys are
            imported as WebCrypto <code>CryptoKey</code> objects with{' '}
            <code>extractable: false</code>. The raw bytes never enter the JS heap. XSS can trigger
            a signature but cannot steal the key.
          </li>
          <li>
            <strong>Per-request signed proofs.</strong> Every authenticated request carries a signed
            payload binding the HTTP method, path, timestamp, and a UUID nonce. The server rejects
            replays, expired timestamps, and reused nonces.
          </li>
          <li>
            <strong>HttpOnly session cookie.</strong> The session ID lives in an httpOnly, Secure,
            SameSite=Strict cookie. JavaScript cannot read it. Combined with the non-extractable
            session key, XSS gets neither half needed to forge a request.
          </li>
          <li>
            <strong>Account enumeration protection.</strong> The recovery endpoint returns identical
            responses and takes identical time whether or not a root public key exists. An attacker
            cannot probe for registered users.
          </li>
          <li>
            <strong>Root JWS binding.</strong> Device registration, recovery, and revocation require
            a signed JWS from the root key. A stolen passkey alone cannot register new devices or
            revoke existing ones without the mnemonic.
          </li>
        </ul>
      </section>

      <hr />

      <section>
        <h2>you own it.</h2>
        <p>
          You deploy the server. You own the database. No third party sees your users, issues your
          tokens, or can revoke access. One Docker command gets you running:
        </p>
        <pre>docker compose up</pre>
        <p>Postgres + the GhostID server. Point your SDK at it and you're done.</p>
      </section>
    </>
  );
}

export function Landing() {
  return (
    <div className="container">
      <section>
        <h1>GhostID</h1>
        <p>Your users are not profiles, they're ghosts.</p>
        <p>
          <Link to="/demo">→ try it</Link>
        </p>
      </section>
      <LandingPage />
    </div>
  );
}
