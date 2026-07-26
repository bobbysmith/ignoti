import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';

import { config } from './config.js';
import { RATE_LIMITS } from './constants.js';
import { sql } from './db/client.js';
import { runGc } from './db/queries/gc.js';
import { registerSessionAuthPlugin } from './plugins/session-auth.js';
import { registerAuthRoutes } from './routes/auth.js';
import { registerDeviceRoutes } from './routes/devices.js';
import { registerHealthRoutes } from './routes/health.js';
import { registerSessionRoutes } from './routes/sessions.js';

export async function buildServer() {
  if (!config.COOKIE_SECURE) {
    console.warn(
      '\nCOOKIE_SECURE=false — session cookies will be sent over plain HTTP.\n' +
        '   This is only safe for local development. Do not use in production.\n'
    );
  }

  const app = Fastify({
    logger: { level: config.LOG_LEVEL },
    // How much of X-Forwarded-For to trust when deriving the client IP for rate
    // limiting. Defaults to one proxy hop; see TRUST_PROXY in config.ts. Trusting
    // more hops than you actually run lets clients spoof their IP by prepending
    // fake XFF entries; trusting too few collapses everyone into one bucket.
    trustProxy: config.TRUST_PROXY,
  });

  await app.register(cookie);

  await app.register(cors, {
    origin: config.RP_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-GhostID-Nonce',
      'X-GhostID-Signature',
      'X-GhostID-Timestamp',
    ],
  });

  await app.register(rateLimit, {
    max: RATE_LIMITS.DEFAULT.max,
    timeWindow: RATE_LIMITS.DEFAULT.timeWindow,
    allowList: config.RATE_LIMIT_DISABLED ? () => true : undefined,
  });

  registerSessionAuthPlugin(app);

  await app.register(registerHealthRoutes);
  await app.register(registerAuthRoutes, { prefix: '/api/auth' });
  await app.register(registerDeviceRoutes, { prefix: '/api/devices' });
  await app.register(registerSessionRoutes, { prefix: '/api/sessions' });

  return app;
}

async function start() {
  const app = await buildServer();
  await app.listen({ port: config.PORT, host: config.HOST });

  // In-process garbage collection. Disabled (GC_INTERVAL_SECONDS=0) when an
  // external scheduler already calls ghostid_gc(). unref() so the timer never
  // keeps the process alive on its own.
  let gcTimer: NodeJS.Timeout | undefined;
  if (config.GC_INTERVAL_SECONDS > 0) {
    const sweep = () => {
      runGc()
        .then(ran => {
          if (ran) app.log.debug('gc sweep complete');
        })
        .catch(err => app.log.error({ err }, 'gc sweep failed'));
    };
    sweep();
    gcTimer = setInterval(sweep, config.GC_INTERVAL_SECONDS * 1000);
    gcTimer.unref();
  }

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'shutting down');
    if (gcTimer) clearInterval(gcTimer);
    try {
      await app.close();
      await sql.end();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'error during shutdown');
      process.exit(1);
    }
  };

  process.once('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.once('SIGINT', () => {
    void shutdown('SIGINT');
  });
}

start().catch(err => {
  console.error(err);
  process.exit(1);
});
