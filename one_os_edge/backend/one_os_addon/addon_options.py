from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

_MAX_OPTIONS_BYTES = 4096


class AddonOptionsError(RuntimeError):
    pass


@dataclass(frozen=True)
class AddonOptions:
    telemetry_enabled: bool = False
    telemetry_authority_enabled: bool = False
    soak_probe_enabled: bool = False


def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AddonOptionsError("duplicate add-on option")
        result[key] = value
    return result


def addon_options_from_path(path: Path) -> AddonOptions:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return AddonOptions()
    except OSError as error:
        raise AddonOptionsError("cannot open add-on options") from error

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AddonOptionsError("add-on options is not a regular file")
        if metadata.st_size > _MAX_OPTIONS_BYTES:
            raise AddonOptionsError("add-on options exceeds size limit")
        payload = os.read(descriptor, _MAX_OPTIONS_BYTES + 1)
        if len(payload) > _MAX_OPTIONS_BYTES:
            raise AddonOptionsError("add-on options exceeds size limit")
    finally:
        os.close(descriptor)

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_closed_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AddonOptionsError("invalid add-on options") from error
    if type(value) is not dict:
        raise AddonOptionsError("add-on options must be an object")
    if set(value) - {"telemetry_enabled", "telemetry_authority_enabled", "soak_probe_enabled"}:
        raise AddonOptionsError("unknown add-on option")
    telemetry_enabled = value.get("telemetry_enabled", False)
    telemetry_authority_enabled = value.get("telemetry_authority_enabled", False)
    soak_probe_enabled = value.get("soak_probe_enabled", False)
    if type(telemetry_enabled) is not bool:
        raise AddonOptionsError("telemetry_enabled must be a boolean")
    if type(telemetry_authority_enabled) is not bool:
        raise AddonOptionsError("telemetry_authority_enabled must be a boolean")
    if type(soak_probe_enabled) is not bool:
        raise AddonOptionsError("soak_probe_enabled must be a boolean")
    return AddonOptions(
        telemetry_enabled=telemetry_enabled,
        telemetry_authority_enabled=telemetry_authority_enabled,
        soak_probe_enabled=soak_probe_enabled,
    )


def option_from_path(path: Path, name: str) -> bool:
    options = addon_options_from_path(path)
    if name not in {"telemetry_enabled", "telemetry_authority_enabled", "soak_probe_enabled"}:
        raise AddonOptionsError("unknown requested add-on option")
    return getattr(options, name)


def telemetry_enabled_from_options(path: Path) -> bool:
    return option_from_path(path, "telemetry_enabled")


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) >= 2 else Path("/data/options.json")
    name = sys.argv[2] if len(sys.argv) == 3 else "telemetry_enabled"
    try:
        enabled = option_from_path(path, name)
    except AddonOptionsError as error:
        print(f"ONE.OS add-on options error: {error}", file=sys.stderr)
        raise SystemExit(78) from error
    print("true" if enabled else "false")


if __name__ == "__main__":
    main()
