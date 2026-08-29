from pathlib import Path

import pytest
from one_os_addon.addon_options import (
    AddonOptionsError,
    addon_options_from_path,
    telemetry_enabled_from_options,
)


def test_missing_options_default_telemetry_fail_closed(tmp_path: Path) -> None:
    assert telemetry_enabled_from_options(tmp_path / "missing.json") is False


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"{}", False),
        (b'{"telemetry_enabled":false}', False),
        (b'{"telemetry_enabled":true}', True),
    ],
)
def test_boolean_telemetry_option(payload: bytes, expected: bool, tmp_path: Path) -> None:
    options = tmp_path / "options.json"
    options.write_bytes(payload)
    assert telemetry_enabled_from_options(options) is expected


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"telemetry_enabled":1}',
        b'{"telemetry_enabled":"true"}',
        b'{"telemetry_enabled":true,"telemetry_enabled":false}',
        b'{"telemetry_enabled":false,"telemetry_enabeld":false}',
        b'{"telemetry_enabled":true,"telemetry_enabeld":false}',
        b'{"telemetry_enabled":',
        b"\xff",
    ],
)
def test_invalid_options_fail_closed(payload: bytes, tmp_path: Path) -> None:
    options = tmp_path / "options.json"
    options.write_bytes(payload)
    with pytest.raises(AddonOptionsError):
        telemetry_enabled_from_options(options)


def test_oversized_options_fail_closed(tmp_path: Path) -> None:
    options = tmp_path / "options.json"
    options.write_bytes(b" " * 4097)
    with pytest.raises(AddonOptionsError, match="size limit"):
        telemetry_enabled_from_options(options)


def test_symlinked_options_fail_closed(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text('{"telemetry_enabled":true}', encoding="utf-8")
    options = tmp_path / "options.json"
    options.symlink_to(target)
    with pytest.raises(AddonOptionsError, match="cannot open"):
        telemetry_enabled_from_options(options)


def test_soak_probe_is_separate_default_off_boolean(tmp_path: Path) -> None:
    missing = addon_options_from_path(tmp_path / "missing.json")
    assert missing.telemetry_enabled is False
    assert missing.soak_probe_enabled is False
    options = tmp_path / "options.json"
    options.write_text('{"telemetry_enabled":false,"soak_probe_enabled":true}')
    parsed = addon_options_from_path(options)
    assert parsed.telemetry_enabled is False
    assert parsed.soak_probe_enabled is True


@pytest.mark.parametrize("value", [1, "true", None, [], {}])
def test_invalid_soak_probe_option_fails_closed(value, tmp_path: Path) -> None:
    import json

    options = tmp_path / "options.json"
    options.write_text(json.dumps({"soak_probe_enabled": value}))
    with pytest.raises(AddonOptionsError, match="soak_probe_enabled"):
        addon_options_from_path(options)


def test_telemetry_authority_option_is_explicit_and_default_off(tmp_path: Path) -> None:
    assert addon_options_from_path(tmp_path / "missing.json").telemetry_authority_enabled is False
    path = tmp_path / "options.json"
    path.write_text('{"telemetry_enabled":true,"telemetry_authority_enabled":true}')
    assert addon_options_from_path(path).telemetry_authority_enabled is True


def test_identity_recovery_authorization_is_exact_boolean_and_default_off(tmp_path: Path) -> None:
    assert addon_options_from_path(tmp_path / "missing.json").identity_recovery_authorized is False
    path = tmp_path / "options.json"
    path.write_text('{"identity_recovery_authorized":true}')
    assert addon_options_from_path(path).identity_recovery_authorized is True


@pytest.mark.parametrize(
    "conflict",
    ["telemetry_enabled", "telemetry_authority_enabled", "soak_probe_enabled"],
)
def test_identity_recovery_authorization_rejects_concurrent_runtime_modes(
    tmp_path: Path, conflict: str
) -> None:
    path = tmp_path / "options.json"
    path.write_text('{"identity_recovery_authorized":true,"' + conflict + '":true}')
    with pytest.raises(
        AddonOptionsError,
        match="identity_recovery_authorized requires telemetry and soak modes disabled",
    ):
        addon_options_from_path(path)


@pytest.mark.parametrize("value", [1, "true", None, [], {}])
def test_invalid_identity_recovery_authorization_fails_closed(value, tmp_path: Path) -> None:
    import json

    path = tmp_path / "options.json"
    path.write_text(json.dumps({"identity_recovery_authorized": value}))
    with pytest.raises(AddonOptionsError, match="identity_recovery_authorized"):
        addon_options_from_path(path)
