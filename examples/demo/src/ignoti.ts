import { Ignoti } from '@ignoti/sdk';

export const ignoti = new Ignoti({
  backendUrl: import.meta.env.VITE_BACKEND_URL ?? 'http://localhost:8787',
});
ignoti.init();
