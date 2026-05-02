import postgres from 'postgres';

import { config } from '../config.js';

export const sql = postgres(config.DATABASE_URL, {
  prepare: config.DB_PREPARE,
  max: 10,
  idle_timeout: 30,
});
