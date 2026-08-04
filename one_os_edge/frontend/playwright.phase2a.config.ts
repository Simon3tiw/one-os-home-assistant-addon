import {defineConfig} from '@playwright/test'
import path from 'node:path'
import {fileURLToPath} from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const host = process.env.PHASE2A_HOST ?? '127.0.0.1'
const marker = process.env.PHASE2A_FAKE_MARKER
if (marker !== 'ONE_OS_PHASE2A_FAKE') throw new Error('PHASE2A_FAKE_MARKER is required')
if (!['127.0.0.1', 'localhost', '::1'].includes(host)) {
  throw new Error('Phase 2A E2E refuses non-loopback hosts')
}

const port = process.env.PHASE2A_PORT ?? '4174'
const staticDir = path.resolve(__dirname, 'dist')
const backendRoot = path.resolve(__dirname, '..', 'backend')
const repoRoot = path.resolve(__dirname, '..', '..')

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  use: {
    baseURL: `http://${host}:${port}/`,
    trace: 'retain-on-failure',
    extraHTTPHeaders: {'X-Remote-User-Id': 'admin-1'},
  },
  webServer: {
    command: `npm run build && uv run --project ${JSON.stringify(repoRoot)} python ${JSON.stringify(
      path.resolve(backendRoot, 'scripts', 'run_e2e_backend.py'),
    )}`,
    cwd: __dirname,
    env: {
      PHASE2A_HOST: host,
      PHASE2A_PORT: port,
      PHASE2A_STATIC_DIR: staticDir,
      ALEMBIC_CONFIG: path.resolve(backendRoot, '..', 'alembic.ini'),
      PATH: process.env.PATH ?? '',
    },
    url: `http://${host}:${port}/health`,
    reuseExistingServer: false,
    timeout: 60000,
  },
})
