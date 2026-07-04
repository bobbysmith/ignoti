# GhostID Threat Model

This document defines what GhostID protects against, what it explicitly does **not** protect against, and the assumptions the design relies on. Anyone evaluating, integrating, or auditing GhostID should read this first.

> Status: living document. Updates require a PR with reviewer sign-off.

## 1. System overview

GhostID is a free, open-source, self-hosted authentication platform - a privacy-first alternative to Sign in with Google/Apple. Builders deploy a pre-built backend server they own and control, and integrate the client SDK into their app. Their users get passkey-based auth without surrendering their identity to any third party.

GhostID uses a self-sovereign identity protocol with three layers:

- **Root identity** - Ed25519 keypair derived from a 12-word BIP39 mnemonic. Used only for account recovery and 
  high-stakes operations, ex. revoking devices. Never stored.
- **Device identity** - A WebAuthn passkey bound to the user agent's authenticator (TPM, Secure Enclave, hardware 
  key). Used for daily login.
- **Session identity** - Ephemeral Ed25519 keypair generated in memory at login. Signs all subsequent API requests 
  until expiry.

The backend stores only opaque public keys, opaque IDs (UUIDs), single-use challenges, and session metadata. It 
never sees the mnemonic, root private key, passkey private key, session private key, IP-to-identity mapping, 
or device fingerprint - and collects no PII (no email, phone number, or real-world identifier) by design.

## 2. Assets we are protecting

`userId` is a random UUID generated server-side at registration - it is not the public key. Using the public
key as the identifier would allow any observer with the `userId` to trivially confirm which public key it
corresponds to, collapsing the pseudonymity layer. The UUID breaks that link: the root public key is stored
in the DB but is never echoed back to clients or included in tokens.

| Asset                     | Where it lives                          | Confidentiality           | Integrity | Availability                |
|---------------------------|-----------------------------------------|---------------------------|-----------|-----------------------------|
| Mnemonic phrase           | User's head / paper / password manager  | Critical                  | Critical  | High (loss = account loss)  |
| Root private key          | Derived in memory only, wiped after use | Critical                  | Critical  | N/A (re-derivable)          |
| Passkey private key       | Authenticator's secure enclave          | Critical (hardware-bound) | Critical  | Medium (per-device)         |
| Session private key       | Browser memory only, wiped on logout    | High                      | High      | Low (re-creatable on login) |
| Session token (cookie)    | httpOnly browser cookie                 | High                      | N/A       | Low (re-creatable on login) |
| User pseudonym (`userId`) | Backend DB and SDK localStorage         | Medium                    | High      | High                        |
| Device list               | Backend DB                              | Medium                    | High      | High                        |

## 3. Attacker model

We consider the following attacker capabilities:

- **A1 - Network attacker.** Can observe and modify traffic between the client and the GhostID server. Cannot break TLS.
- **A2 - Server compromise.** Can read the entire database and tamper with server code. Cannot retroactively 
  compromise material the server never possessed (mnemonics, private keys).
- **A3 - Phishing site.** Can host a convincing UI on a different origin and trick the user into visiting it.
- **A4 - Browser extension / supply chain.** Has script-level access to the GhostID origin's page (XSS, malicious 
  extension, compromised dependency).
- **A5 - Device thief.** Has physical possession of an unlocked device.
- **A6 - Mnemonic theft.** Has obtained the user's 12-word mnemonic.
- **A7 - Mass surveillance.** Operates at backbone scale, correlates traffic, and subpoenas providers.

## 4. What GhostID protects against

### Phishing (A1, A3)
WebAuthn binds the credential to the **origin** at registration. A passkey created for `app.example` cannot be used 
to authenticate against `app-example.evil`. The authenticator refuses, and no signature is produced. **Mitigation: 
WebAuthn origin binding.**

### Password reuse and credential stuffing
There are no passwords. **Mitigation: by design.**

### Server-side credential theft (A2)
The server never receives, stores, or transmits private keys or mnemonics. A full DB dump yields public keys and 
pseudonymous UUIDs; nothing that can be replayed against another service or used to impersonate the user. 
**Mitigation: zero-knowledge backend.**

### Session hijacking (A1, A2)
Sessions are bound to an ephemeral public key registered at login. Every authorized request is signed with the 
corresponding private key, which never leaves the client. A stolen session ID alone cannot be replayed - the 
attacker would also need the in-memory private key.

Session persistence across page reloads is handled by an httpOnly, Secure cookie. JavaScript on the page cannot 
read this cookie - a successful XSS cannot exfiltrate it. On reload, the SDK calls the restore endpoint with the 
cookie and generates a fresh ephemeral keypair; the private key is never written to disk or localStorage.

The cookie is a bearer credential *for session restore* - like an OAuth refresh token. Whoever presents it can bind 
a new session keypair and obtain a working session, so it is protected the way refresh tokens are: httpOnly + Secure 
+ SameSite, plus **rotation with reuse detection** (RFC 9700). The cookie carries a rotating secret; every restore 
issues a new one and invalidates the old. If a secret is ever presented that does not match the current one on an 
otherwise-active session - the signature that a stolen, already-rotated cookie was replayed by a second party - the 
server revokes the session, so a thief and the legitimate user cannot both hold a working cookie. This detects and 
kills cookie theft after the fact; it does not prevent an attacker who has live XSS on the page from acting within 
that page, which is game-over for any browser session regardless of storage mechanism (httpOnly prevents 
exfiltration, not in-page use).

Outside of restore, a stolen session ID cannot be used to forge signed API requests: every request also requires a 
live Ed25519 signature from the session private key, which exists only in memory on the original page. The SameSite 
policy is `None` in production (required for cross-origin deployments where the frontend and the GhostID server run 
on different domains) and `Lax` in local development. CSRF protection comes from the per-request signature, not the 
SameSite attribute; a forged request without a valid signature is rejected regardless of whether the cookie was 
sent. **Mitigation: signed-request sessions with ephemeral keys; httpOnly restore cookie with refresh-token 
rotation and reuse detection.**

One operational note: because restore rotates the cookie, two page contexts (e.g. multiple tabs) restoring the same 
session concurrently can race - the second restore presents an already-rotated secret and the session is revoked, 
forcing a re-login. The SDK single-flights restore within a page, so this only arises across separate tabs/windows 
reloaded at the same instant, and it fails safe (re-authenticate), never toward granting access.

### Replay attacks (A1)
Every challenge is single-use, scoped to a purpose (`register`, `login`, `recover`, `session`), and expires within 
`CHALLENGE_TTL_SECONDS`. Reusing a captured challenge is rejected. **Mitigation: nonce-style challenges with short 
TTL and consumed-at marker.**

### Backend identity correlation (A2, A7)
GhostID stores no email, phone, social account, or any third-party identifier. User IDs are random UUIDs. The 
protocol carries no PII (personally identifiable information). A breached or subpoenaed database cannot link `userId` 
to a real-world identity without out-of-band data. **Mitigation: PII-free schema.**

### Device loss (A5, partial)
A lost device retains its passkey, but: (a) the authenticator requires user verification (biometric/PIN) before 
signing, and (b) the rightful owner can recover via mnemonic on a new device and revoke the lost device. 
**Mitigation: WebAuthn user verification, mnemonic recovery, and revocation.**

## 5. What GhostID does NOT protect against

These are explicit non-goals. Documenting them is a feature, not a regression.

### Mnemonic theft (A6)
Anyone with the 12-word mnemonic **is** the user, by definition. We deliberately have no recovery path beyond the 
mnemonic, adding one would reintroduce a centralized authority. Users must store the mnemonic offline and treat it 
like a private key.

### Active XSS on the integrating site (A4)
If an attacker injects script into a page that hosts the GhostID SDK, they can read the in-memory session key while 
the user is logged in and forge requests for the lifetime of that session. **They cannot exfiltrate the passkey 
private key or the mnemonic.** Mitigations are the integrator's responsibility: strict content security policy, 
dependency review, Subresource Integrity, no `dangerouslySetInnerHTML` near auth surfaces.

### Compromised authenticator firmware (A5, advanced)
If the device's secure enclave is broken, ex. an unpatched hardware vulnerability, the passkey can be extracted. 
Out of scope, we trust the WebAuthn substrate.

### Coercion ("$5 wrench attack")
A user forced to authenticate is indistinguishable from a willing one. Consider duress mnemonics in a future major 
version.

### Account enumeration via timing
A naive `register`/`recover` implementation can leak whether a `userId` exists by timing differences. The backend 
MUST issue identical responses, and identical timing within reason, regardless of existence. Tracked in the server 
build.

### Denial of service
Standard mitigations only, rate limiting, infra-level WAF. Not a cryptographic guarantee.

### Cross-device account linkage
A user who reuses the same WebAuthn `userHandle` across origins could in principle be correlated by colluding RPs.
We use a per-account opaque UUID, but downstream integrators must not echo it back across other auth surfaces.

## 6. Cryptographic primitives

| Use                   | Primitive                                                         | Library                              |
|-----------------------|-------------------------------------------------------------------|--------------------------------------|
| Mnemonic              | BIP39 (12 words / 128-bit entropy)                                | `@scure/bip39`                       |
| Root key derivation   | BLAKE2b KDF on BIP39 seed                                         | `@noble/hashes`                      |
| Root signatures       | Ed25519                                                           | `@noble/curves`                      |
| Session key           | Ed25519                                                           | `@noble/curves`                      |
| Device authentication | WebAuthn (ES256 / RS256)                                          | Browser and `@simplewebauthn/server` |
| Hashing               | BLAKE2b-256                                                       | `@noble/hashes`                      |
| Random                | `crypto.getRandomValues` (client) / `crypto.randomBytes` (server) | Native                               |

We do not roll our own crypto. Any change to this table requires explicit security review.

## 7. Security boundaries (what each party trusts)

- **The user** trusts: their authenticator, their browser, the integrating site's origin, and transitively the 
  GhostID SDK shipped to that origin.
- **The integrator** trusts: the SDK source they audit, the GhostID server they self-host or the Cloud they pay, the 
  user's authenticator.
- **The GhostID server** trusts: nothing about the client. Every request is verified by signature. The server treats 
  client input as adversarial.

## 8. Operational requirements (for self-hosters)

These are not optional. A deployment that violates them is not implementing the threat model above.

1. **TLS everywhere.** WebAuthn refuses non-HTTPS origins outside `localhost`. The session cookie's `Secure` 
   flag means browsers will not send it over plain HTTP - but the server must enforce HTTPS at the infrastructure 
   level too.
2. **No PII in logs.** Never log signatures, public keys, IPs joined to user IDs, or request bodies near auth code.
3. **Tight CORS.** `RP_ORIGIN` is the only allowed origin.
4. **Constant-time comparisons** for any signature/public-key check.
5. **Challenge GC.** Expired challenges must be deleted, not just marked consumed.
6. **No silent migrations.** Schema changes that could leak data require a documented migration path.
7. **Cookie security.** The session cookie must remain httpOnly and Secure in production. SameSite is `None` for 
   cross-origin deployments (the typical case) and `Lax` for local development; CSRF protection comes from the 
   per-request signature, not SameSite. Do not expose the session token via any other channel (response body, 
   URL parameter, log line).

## 9. Open questions / future work

- **Duress mnemonic** - a second mnemonic that authenticates but flags the session.
- **Multi-recipient recovery (Shamir's Secret Sharing)** - for users who can't reliably store one mnemonic.
- **Per-RP user handles** - to harden against cross-site correlation by colluding integrators.
- **Hardware attestation policy** - currently `attestation: 'none'`. Stricter policies for high-stakes deployments.
- **Anonymity set analysis** - at what user count does pseudonymity become practically anonymous?

## 10. Reporting vulnerabilities

See `SECURITY.md` (TODO). Until then: open a private GitHub security advisory.
