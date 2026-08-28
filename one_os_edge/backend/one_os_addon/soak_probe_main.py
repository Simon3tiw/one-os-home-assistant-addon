"""Fixed-configuration entrypoint for the default-off Edge mTLS soak probe."""

from __future__ import annotations

from pathlib import Path

from .soak_probe import collect_status
from .soak_probe_server import create_server, load_allowed_client_sha256

DATABASE = Path("/data/commissioning.db")
CLIENT_CA = Path("/data/soak-probe/client-ca.pem")
SERVER_CERTIFICATE = Path("/data/soak-probe/server-certificate.pem")
SERVER_KEY = Path("/data/soak-probe/server-key.pem")
ALLOWED_CLIENT_SHA256 = Path("/data/soak-probe/allowed-client.sha256")
HOST = "0.0.0.0"  # noqa: S104 - Supervisor exposes the port only by explicit mapping.
PORT = 9443


def main() -> None:
    server = create_server(
        HOST,
        PORT,
        CLIENT_CA,
        SERVER_CERTIFICATE,
        SERVER_KEY,
        load_allowed_client_sha256(ALLOWED_CLIENT_SHA256),
        lambda: collect_status(DATABASE),
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
