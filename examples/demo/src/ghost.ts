import { GhostID } from '@ghostid/sdk';

export const ghost = new GhostID({
  backendUrl: import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:8787',
});
ghost.init();
