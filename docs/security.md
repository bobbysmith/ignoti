# How GhostID protects your users

This covers the attacks that matter most for an auth system and how GhostID handles each one. It is written for 
builders evaluating whether GhostID is the right fit, not for cryptographers. The full technical details are in the 
threat model.

---

## No passwords means no password problems

GhostID has no passwords. There is nothing to phish, nothing to reuse across sites, and nothing for an attacker to 
brute-force or find in a breach dump. Authentication is always done with a passkey, a hardware-bound cryptographic 
key that never leaves the user's device.

## Phishing does not work

Passkeys are bound to the exact origin they were created on. A passkey registered at `app.example.com` cannot be 
used to authenticate at `fake-app.example.com` or any other domain. The authenticator will simply refuse to produce 
a signature. Users cannot be tricked into handing over credentials to a lookalike site, even a convincing one.

This also covers adversarial proxies that sit between the user and your site and replay requests in real time. The 
WebAuthn signature is tied to the origin, not just the URL the user sees.

## The server learns almost nothing

When a user registers, the server stores:

- A random UUID for their account
- Their device's passkey public key
- Their root identity public key (derived from their mnemonic)

That is it. No email, no phone number, no IP-to-identity mapping. If your database is breached, the attacker gets a 
list of public keys and UUIDs. There is no password to crack and no PII to sell.

## Server compromise does not mean account takeover

A server compromise is serious, but GhostID limits what an attacker can do with it.

What they get:

- Public keys (useless without the corresponding private keys)
- Pseudonymous UUIDs (not linked to any real-world identity)
- Session metadata (which device was last used, when)
- Active session records (but sessions are signed, so they cannot be forged without the private key)

What they do not get: mnemonics, root private keys, passkey private keys, session private keys. None of those ever 
reach the server. An attacker who owns your database cannot impersonate your users.

## You are not downstream of anyone else's breach

OAuth and OIDC providers ("Sign in with Google", Auth0, Clerk) are central points of failure. If Google's auth 
infrastructure is compromised, every application using it is affected, whether that application was targeted or not.
GhostID is self-hosted. Your auth is only as compromised as your own server.

## Session hijacking is much harder than it sounds

After login, sessions are bound to an ephemeral keypair generated in the browser. Every subsequent API request is 
signed with the session private key, which only exists in memory and never touches disk, localStorage, or any 
server. A stolen session token alone is useless because the attacker does not have the key needed to produce valid 
request signatures.

The session token itself is stored in an `httpOnly` cookie. JavaScript on your page cannot read it. Even a 
successful XSS attack cannot steal the cookie directly.

## Tokens are never in localStorage

Many auth systems store session tokens or JWTs in `localStorage`. Any script running on your page can read 
`localStorage`, including third-party analytics, chat widgets, and injected ads. GhostID stores the session token 
in an `httpOnly` cookie that JavaScript cannot access. The session signing key lives in memory only and is gone 
when the page closes.

## CSRF is blocked by design

Every authenticated request must include a live Ed25519 signature produced by the session private key, which exists 
only in memory on the user's page. A malicious page on a different origin cannot read that key and cannot produce a 
valid signature. A forged request without a valid signature is rejected by the server regardless of whether the 
session cookie was sent.

In production, the session cookie is `SameSite=None; Secure`, which is required for cross-origin deployments where 
your frontend and GhostID server are on different domains. The SameSite attribute alone is not the CSRF protection 
— the per-request signature is.

## Replay attacks are blocked

Every login and recovery flow goes through a single-use challenge. If someone captures a login request mid-flight 
and tries to replay it, the server rejects it because the challenge was already consumed. Challenges also expire 
after a short window, so a captured one is useless even if it was never used.

## Cross-endpoint replay is blocked

Each challenge is scoped to a specific purpose. A challenge issued for login cannot be used for account recovery. A 
challenge for recovery cannot be used to register a new device. A root-key signature for device registration cannot 
be used to revoke a device.

This is enforced at the protocol level, not just by convention. The `purpose` field is embedded in the signed 
payload and verified by the server on every request. An attacker who captures a valid signature from one flow 
cannot repurpose it for another.

## Account enumeration is blocked

`/register` and `/recover` return identical responses whether an account exists or not, and the server equalizes 
timing so there is no measurable difference between the two code paths. An attacker cannot use your auth endpoints 
to determine which accounts exist.

## There is no support team to social-engineer

Many high-profile account takeovers do not involve breaking crypto at all. The attacker calls support, claims to be 
the user, and gets the account reset. GhostID has no support-line recovery path. There is no "I forgot my mnemonic, 
help me reset my account" flow and no team that can override authentication. The mnemonic is the recovery mechanism 
and there is no fallback to social engineering.

## Capturing the auth flow gets you nothing

WebAuthn assertions are one-time signatures over a server-issued challenge. Even if TLS were broken and an attacker 
captured the entire registration or login exchange, they cannot replay it. The assertion contains the challenge, 
which the server marks as consumed immediately, and is cryptographically tied to the origin.

## There is no "guess the token" surface

Many auth systems use random strings as bearer tokens. If you can guess or enumerate one, you are in. GhostID 
sessions do not work this way. Every authenticated request must be accompanied by a live Ed25519 signature produced 
by the session private key. There is no token to guess because a token alone is not enough to authenticate.

## The session private key cannot be exfiltrated

The session keypair is generated with the Web Crypto API using `extractable: false`. If an attacker gets script 
execution on your page while a user is logged in, they can use the key to make authenticated requests during that 
session. They cannot, however, export the raw key bytes, serialize the key, or send it to another server. Once the 
session ends and the tab closes, the key is gone. There is nothing to persist, copy, or reuse later. The damage is 
bounded to the active session window.

## Biometric or PIN is always required

GhostID sets `userVerification: required` on every authentication and registration request. The authenticator must 
verify the user, not just their presence. Tapping a security key without a PIN or presenting a device without a 
biometric will be rejected. Someone who picks up an unlocked device cannot log in without the owner's fingerprint 
or face.

## Cloned authenticators are detectable

WebAuthn tracks a sign count: a number the authenticator increments every time it signs. GhostID's server stores 
this count and rejects any login where the new count is not higher than the stored one, which is a strong signal 
that the credential was cloned. Cloning a hardware authenticator is difficult, but if it happens, the server can 
detect it and refuse the login.

This protection applies to authenticators that actually increment the counter. Many platform authenticators (Face 
ID, Touch ID, Windows Hello) always return zero, which the spec permits, and those credentials do not benefit from 
clone detection. For those devices the protection comes from the secure enclave itself rather than the counter.

## Challenge cross-user replay is blocked for recovery and registration

Recover and register challenges are scoped to a specific user. An attacker cannot take a valid challenge issued to 
their own account and use it to complete a recovery or registration flow for a different account. Login challenges 
are not user-scoped (the user is unknown at challenge issuance), but the WebAuthn assertion that consumes them 
carries the credential ID, which maps to exactly one device and one user on the server.

## Captured root-key and session signatures expire

Root-key signatures (used for device registration, recovery, and revocation) and session binding signatures both 
include an expiry time enforced by the server. Even if an attacker captures a valid signature in transit, it is 
only usable for a short window. A signature from last week cannot be replayed today.

## Revoking a device kills all its sessions atomically

When a device is revoked, the server marks both the device and all its active sessions revoked in a single database 
transaction (the rows are hard-deleted later by garbage collection, seven days on). There is no window between the 
two operations where the device is revoked but its sessions are still live. An attacker cannot race to use an active 
session after revocation has been issued.

## Sensitive endpoints are rate limited

Registration, login, and recovery endpoints are rate limited. An attacker cannot make unlimited attempts to probe 
the system, enumerate accounts, or brute-force challenges.

## What GhostID cannot protect against

**Malicious JavaScript on your own page.** If an attacker injects script into your site, they can use the in-memory 
session key while the user is logged in and make API calls for the duration of that session. GhostID's `httpOnly` 
cookie prevents cookie theft and `extractable: false` prevents the key bytes from being exfiltrated, but neither 
stops an attacker who already has code execution on your origin from making calls during the session window.

The defense is preventing XSS in the first place. At minimum:

- **Strict Content Security Policy.** Disallow `unsafe-inline` and `unsafe-eval`. Restrict `script-src` to your own 
  origin and any vetted third parties. Example header:
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 
  'self'; frame-ancestors 'none'
  ```
- **Subresource Integrity** on any third-party script you load via `<script src>`. If the script changes, the 
  browser refuses to execute it.
- **Avoid `dangerouslySetInnerHTML` and equivalents.** Never interpolate user-supplied data into the DOM as HTML.
- **Regular dependency audits.** Most XSS in modern apps comes from a compromised npm dependency, not your own code.
  Run `npm audit` and pin versions in CI.

**Mnemonic theft.** Anyone with the user's 12-word phrase can recover the account. Users need to store it offline 
and treat it like a private key. There is no "forgot mnemonic" flow, by design.

**Physical coercion.** If someone forces a user to authenticate, GhostID cannot stop them. Duress mnemonics (a 
second phrase that authenticates but flags the session as coerced) are on the roadmap but not yet implemented.

**A compromised authenticator.** GhostID trusts the WebAuthn layer. A device with a broken secure enclave is out of 
scope.

---

For the full technical threat model including cryptographic primitive choices, trust boundaries, and operational 
requirements for self-hosters, see the threat model.
