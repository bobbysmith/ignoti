# Privacy in GhostID

Most auth systems collect identity as a side effect of doing their job. They need an email to send a verification link, a phone number to send an OTP, or an OAuth token tied to a real-world account. GhostID is built around the idea that auth does not need any of that.

---

## What the server actually stores

Here is the complete list of what ends up in the database.

**Per user:**
- A random UUID (not derived from anything about the user)
- A root identity public key (an Ed25519 public key, opaque bytes)
- A registration timestamp

**Per device:**
- A random UUID
- The WebAuthn credential ID (an opaque identifier assigned by the authenticator)
- The passkey public key
- A signature counter
- The WebAuthn transports array (technical metadata like `internal` or `usb`, needed to route authentication requests correctly)
- An optional device name (set by the integrating app, blank by default)
- Created, last used, and revoked timestamps

**Per session:**
- A random UUID
- The ephemeral session public key
- The SHA-256 hash of a rotating restore-cookie secret (never the secret itself)
- Expiry and last-used timestamps

**Operational tables (not per-user data):**
- `challenges` - single-use login/register/recover nonces with an expiry, deleted once expired
- `session_nonces` - per-request replay-prevention IDs (a UUID and an expiry), deleted once expired

That is the entire schema. No email. No phone number. No IP address. No user agent. No geolocation. No device fingerprint. No real-world identifier of any kind.

## Your users are invisible to every third party

OAuth and "Sign in with" flows route the user through a provider. Google knows which apps you use and when. Auth0 and Clerk see every login across all their customers. Even if those providers are trustworthy today, your users' auth activity is sitting in someone else's data center.

GhostID is self-hosted. The only system that sees a login is your server. There is no GhostID cloud, no licensing server, no SDK phone-home. When your user logs in, the only parties involved are the user's browser, their authenticator, and your server.

## The mnemonic never leaves the client

The 12-word recovery phrase is the root of the user's identity. It is used client-side to derive their root keypair and is never transmitted anywhere. The server only ever sees the public key. You could read every byte that crosses the network and never find the mnemonic.

## User IDs are not linkable

The `userId` stored in your database is a random UUID generated at registration. It is not derived from the user's public key, their passkey, or any other attribute. Two different applications using GhostID that somehow obtained the same user's public key cannot correlate them back to each other by `userId`, because the UUID is per-deployment.

## Stale data is deleted automatically

Sessions and challenges are automatically garbage collected. Expired challenges are deleted immediately. Sessions are deleted seven days after they expire or are revoked. The database does not accumulate years of login history by default. What was not collected cannot be subpoenaed, breached, or sold.

## GDPR and data minimization

Because GhostID collects no PII, most GDPR obligations around personal data simply do not apply in the traditional sense. There is no email to delete, no profile to export, no marketing preferences to honor. Deleting a user account means deleting a UUID, a public key, and some timestamps. Nothing in that record identifies a natural person on its own.

If your application layer collects PII and links it to a GhostID `userId`, those obligations are yours to handle. GhostID's job is to make the auth layer clean.

## What is not hidden

The server does record when a device was last used and how many times it has authenticated. An operator with database access can see that a particular opaque UUID logged in three times this week from a device registered two months ago. That is activity metadata. It does not identify who the user is in the real world, but it is not nothing. Operators should treat it accordingly and not log it alongside any identifying information from their application layer.

The transports field reveals something minor about the user's authenticator type (whether it is a platform authenticator like Face ID or a roaming key like a USB security key). This is a WebAuthn technical requirement, not a tracking mechanism, but it is worth knowing it is there.

## No device fingerprinting via attestation

WebAuthn supports attestation: a mechanism where the authenticator cryptographically proves what kind of device it is, including manufacturer, model, and firmware version. Many auth systems collect this to enforce hardware policies, but it is also a detailed device fingerprint.

GhostID explicitly requests `attestationType: 'none'`. The server verifies that a valid credential was created, but it does not collect or store any information about the authenticator's hardware identity. Your users' device details are not in your database.

## The WebAuthn username is an opaque ID

During passkey registration, WebAuthn requires a `userName` field that the authenticator may display to the user. GhostID sets this to the user's opaque UUID, not a name or email. No real-world identifier is passed to the authenticator.

## A note on platform passkey sync

Modern platform authenticators like iCloud Keychain and Google Password Manager sync passkeys across the user's devices. This is a browser and OS level behavior, not something GhostID controls. If a user registers with Safari on iPhone, Apple holds a copy of their passkey encrypted in iCloud. GhostID cannot prevent this, and it is the same trade-off users accept for any passkey-based app.

Users who want to avoid cloud sync entirely can use a hardware security key, which stores the credential on the device only.

## No SDK telemetry

The GhostID SDK does not make any network requests other than the ones your code explicitly triggers. It does not collect usage metrics, error reports, or performance data. It does not know who is using it or how often.
