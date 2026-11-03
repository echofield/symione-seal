import { defineConfig } from 'vitest/config';

// Tests run the Worker in Node over node:sqlite (tests/d1.ts): no Cloudflare plugin, no network.
export default defineConfig({
  test: { environment: 'node', include: ['tests/**/*.test.ts'], testTimeout: 20000, pool: 'forks' },
});
