import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/__tests__/integration/**/*.test.ts'],
    testTimeout: 30000,
    // Test files share one database; parallel workers truncate each other's data
    fileParallelism: false,
  },
});
