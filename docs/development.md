# Development, persistence and security

## Local

```sh
uv sync --all-extras
uv run ruff check one_os_edge/backend
uv run ruff format --check one_os_edge/backend
uv run pytest
uv run pip-audit
cd one_os_edge/frontend && npm ci && npm test && npm run typecheck && npm run lint && npm run build
npm audit --omit=dev --audit-level=high
```

Use a temporary SQLite URL for development. Runtime data is `/data/commissioning.db`; it is never committed. SQLite enables foreign keys, WAL and a 5-second busy timeout. Alembic owns schema revision `0002` (lifecycle, placement and typed properties on top of `0001`).

## Isolated end-to-end test

`one_os_edge/frontend/e2e/phase2a.spec.ts` runs the full commissioning
journey against a **real** backend process — no in-browser API mocking.
`playwright.phase2a.config.ts` builds the production frontend, then starts
`one_os_edge/backend/scripts/run_e2e_backend.py`, which boots the actual
FastAPI app with a `FakeHomeAssistant` boundary, a temporary SQLite
database and real Alembic migrations, bound to a loopback-only host/port.
Run it with:

```sh
cd one_os_edge/frontend
npx playwright install chromium
PHASE2A_FAKE_MARKER=ONE_OS_PHASE2A_FAKE npm run test:e2e
```

The harness refuses non-loopback hosts and requires the fake marker, so it
can never accidentally target a real Home Assistant instance.

## Build

The complete Home Assistant app build context is `one_os_edge/`, supporting `amd64` and `aarch64`, Ingress, `panel_admin`, cold backup and Home Assistant >= 2025.1.0. Build with modern Docker Buildx; the Dockerfile pins a multi-arch Home Assistant Python base by default and does not use deprecated `build.yaml`. CI (`.github/workflows/ci.yml`) builds both architectures, boots each image under QEMU, waits for `/health`, and uploads the image tarball, checksum and SBOM as artifacts.

## Manual installation bundle

The add-on repository is private, so Home Assistant Supervisor cannot clone
it directly. `scripts/build-release-bundle.sh` produces a checksummed
`one-os-edge-addon-bundle.tar.gz` for manual installation into the Home
Assistant local `/addons` directory. CI runs the same script as the
`release-bundle` job and publishes the bundle as a downloadable artifact.
See `INSTALL.md` for the full procedure.

## Cold backup/restore

Stop the backend, checkpoint SQLite (`PRAGMA wal_checkpoint(TRUNCATE)`), verify integrity, archive only `/data/commissioning.db`, restore into a clean `/data`, then restart and let Alembic migrate to head automatically. `test_cold_backup_restore_preserves_complete_commissioning_state` exercises the full path: overrides, selection, a created Property, an Asset split and the audit log all survive the restore, and the restored database re-verifies at Alembic head. Telemetry outbox data belongs to Phase 2C and must remain physically separate and excluded from backup.

## Security boundary

Only the configured Supervisor Ingress proxy peer is accepted (default `172.30.32.2`), verified against the raw transport peer — proxy header rewriting (`X-Forwarded-For`) is disabled in the runtime so it cannot be used to spoof a trusted proxy. Every route except payload-free `/health` requires `X-Remote-User-Id` and a live `config/auth/list` system-admin verification. Mutations additionally require JSON, an Origin drawn from verified Home Assistant config (or an explicit allowlist), same-origin fetch metadata and a time-bound per-user CSRF token that expires and is rejected fail-closed afterwards. Browser code is same-origin only. No token is returned or logged. The adapter has a bounded read-only Home Assistant contract (REST snapshot, state/registry event subscriptions, config read) — no HA mutation, cloud, MQTT, pairing or generic service-call surface.

## Live synchronization

`SyncCoordinator` (`one_os_addon/sync.py`) is started from the FastAPI lifespan when `start_background_sync=True`. It performs an authoritative snapshot on startup, subscribes to Home Assistant state and registry events, applies live state updates directly (capability drift on a changed evidence hash disables cloud control and flags review), debounces registry-triggered reconciliation, and runs periodic full reconciliation with jittered exponential backoff on reconnect. A monotonically increasing generation counter fences stale in-flight writes across reconnects.

## Phase 2B compatibility migration

Before cloud sync, the central repository must add versioned Site/Structure/Space/Asset/Point contracts and backfill legacy Building/Floor/Zone/Equipment IDs behind a deprecated adapter. Raw HA identity and legacy `writable` must not enter the new contracts.
