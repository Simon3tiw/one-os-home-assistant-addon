from pathlib import Path

ROOT = Path(__file__).parents[2]
RUN = ROOT / "rootfs/etc/services.d/one-os-soak-probe/run"
MAIN = ROOT / "backend/one_os_addon/soak_probe_main.py"


def test_probe_service_is_separate_default_off_and_fixed_configuration() -> None:
    run = RUN.read_text()
    main = MAIN.read_text()
    assert "soak_probe_enabled" in run
    assert "exec sleep infinity" in run
    assert "exec python3 -I -m one_os_addon.soak_probe_main" in run
    for fixed in (
        "/data/commissioning.db",
        "/data/soak-probe/client-ca.pem",
        "/data/soak-probe/server-certificate.pem",
        "/data/soak-probe/server-key.pem",
        "/data/soak-probe/allowed-client.sha256",
        'HOST = "0.0.0.0"',
        "PORT = 9443",
    ):
        assert fixed in main
    for forbidden in ("SUPERVISOR_TOKEN", "INGRESS", "argparse", "os.getenv", "sys.argv"):
        assert forbidden not in main
    assert RUN.stat().st_mode & 0o111
