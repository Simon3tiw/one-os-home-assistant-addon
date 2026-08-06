from pathlib import Path

import yaml

ADDON_CONFIG = Path(__file__).resolve().parents[2] / "config.yaml"


def test_addon_backup_excludes_private_edge_identity() -> None:
    manifest = yaml.safe_load(ADDON_CONFIG.read_text(encoding="utf-8"))

    assert manifest["backup_exclude"] == ["identity", "identity/**"]
