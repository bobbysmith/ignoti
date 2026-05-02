import { GhostID } from '@ghostid/sdk';

// biome-ignore lint/style/noNonNullAssertion: <just a demo chill bro>
const out = document.getElementById('out')!;
const log = (msg: unknown) => {
  out.textContent += `\n${typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2)}`;
};

const ghost = new GhostID({ backendUrl: 'http://localhost:8787' });
ghost.init();
log('GhostID initialized.');

// biome-ignore lint/style/noNonNullAssertion: <just a demo chill bro>
document.getElementById('signup')!.addEventListener('click', async () => {
  try {
    const result = await ghost.createIdentity();
    log({ created: result });
  } catch (err) {
    log(`signup error: ${(err as Error).message}`);
  }
});

// biome-ignore lint/style/noNonNullAssertion: <just a demo chill bro>
document.getElementById('login')!.addEventListener('click', async () => {
  try {
    const result = await ghost.login();
    log({ session: result });
  } catch (err) {
    log(`login error: ${(err as Error).message}`);
  }
});

// biome-ignore lint/style/noNonNullAssertion: <just a demo chill bro>
document.getElementById('recover')!.addEventListener('click', async () => {
  const mnemonic = (document.getElementById('mnemonic') as HTMLInputElement).value.trim();
  if (!mnemonic) {
    log('recover error: enter your 12-word mnemonic first');
    return;
  }
  try {
    const result = await ghost.recoverIdentity(mnemonic);
    log({ recovered: result });
  } catch (err) {
    log(`recover error: ${(err as Error).message}`);
  }
});
