import { GhostID } from '@ghostid/sdk';

export const ghost = new GhostID({ backendUrl: 'http://localhost:8787' });
ghost.init();
