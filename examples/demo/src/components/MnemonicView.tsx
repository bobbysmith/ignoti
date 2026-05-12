import { useState } from 'react';

export function MnemonicView({
  mnemonic,
  onContinue,
}: {
  mnemonic: string;
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    await navigator.clipboard.writeText(mnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <>
      <p>
        This is the only way to recover your account if you lose this device. It will not be shown
        again.
      </p>
      <pre>{mnemonic}</pre>
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        <button type="button" onClick={handleCopy}>
          {copied ? '✓ copied' : 'copy'}
        </button>
        <button type="button" onClick={onContinue}>
          → continue to sign in
        </button>
      </div>
    </>
  );
}
