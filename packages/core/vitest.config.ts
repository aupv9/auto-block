import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 30_000,  // testcontainers can be slow on first pull
    hookTimeout: 60_000,
    pool: 'forks',        // better isolation for container-based tests
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/index.ts'],
    },
  },
})
