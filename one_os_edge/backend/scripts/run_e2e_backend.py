"""Real process launcher for the Fase-2A isolated E2E journey.

Starts an actual FastAPI application (uvicorn) backed by an in-memory
FakeHomeAssistant boundary and a temporary SQLite database, and serves the
production frontend build as static files — exactly like the packaged
Home Assistant app does. No API mocking happens in the browser: Playwright
talks to this real process over HTTP on loopback only.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import uvicorn

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from one_os_addon.app import create_app  # noqa: E402
from one_os_addon.ha.fake import FakeHomeAssistant  # noqa: E402


def main() -> None:
    host = os.environ.get("PHASE2A_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Phase 2A E2E backend refuses to bind non-loopback hosts")
    port = int(os.environ.get("PHASE2A_PORT", "4174"))
    static_dir = os.environ.get("PHASE2A_STATIC_DIR")
    if not static_dir or not Path(static_dir).is_dir():
        raise SystemExit("PHASE2A_STATIC_DIR must point at a built frontend dist directory")

    tmp_dir = tempfile.mkdtemp(prefix="one-os-e2e-")
    database_url = f"sqlite:///{tmp_dir}/one-os.db"
    origin = f"http://{host}:{port}"

    os.environ["STATIC_DIR"] = static_dir

    app = create_app(
        database_url=database_url,
        ha_client=FakeHomeAssistant.standard(),
        ingress_proxies={host, "testclient"},
        allowed_origins={origin},
        start_background_sync=True,
        sync_interval=2,
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
