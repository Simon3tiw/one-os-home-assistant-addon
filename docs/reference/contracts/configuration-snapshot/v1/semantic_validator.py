#!/usr/bin/env python3
"""Dependency-light executable semantic contract for configuration snapshot V1.

The JSON Schema owns shape and scalar bounds. This module owns constraints JSON
Schema cannot express portably: deterministic ordering, graph integrity, the
closed V1 point metadata matrix, and strict UTC timestamp spelling.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Never

RFC3339_UTC_PATTERN = re.compile(
    r"^(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?Z$"
)

# Closed V1 matrix. Changing this table requires a versioned contract change.
V1_DISPLAY_UNITS: dict[str, frozenset[str]] = {
    "Cel": frozenset(("degC", "degF")),
    "%": frozenset(("%",)),
    "W": frozenset(("W",)),
    "kW": frozenset(("kW",)),
    "W.h": frozenset(("Wh",)),
    "kW.h": frozenset(("kWh",)),
    "V": frozenset(("V",)),
    "A": frozenset(("A",)),
    "Hz": frozenset(("Hz",)),
    "Pa": frozenset(("Pa",)),
    "hPa": frozenset(("hPa",)),
    "[ppm]": frozenset(("ppm",)),
    "lx": frozenset(("lx",)),
}


class SemanticValidationError(ValueError):
    """Stable machine-readable semantic rejection."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> Never:
    raise SemanticValidationError(code, message)


def _ids(document: dict[str, Any], collection: str, label: str) -> set[str]:
    identifiers = [node["id"] for node in document[collection]]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        _fail(
            "ordering_or_duplicate_id",
            f"{label} IDs must be strictly sorted and unique",
        )
    return set(identifiers)


def _validate_timestamp(value: str) -> None:
    if RFC3339_UTC_PATTERN.fullmatch(value) is None:
        _fail("strict_utc", "capturedAt must be strict UTC RFC3339 with Z")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        _fail("strict_utc", "capturedAt is not a real UTC instant")
    offset = parsed.utcoffset()
    if parsed.tzinfo is None or offset is None or offset.total_seconds() != 0:
        _fail("strict_utc", "capturedAt must use UTC")


def _validate_point_metadata(point: dict[str, Any]) -> None:
    value_type = point["valueType"]
    canonical = point["canonicalUnit"]
    display = point["displayUnit"]
    decimals = point["decimals"]
    if value_type != "number":
        if canonical is not None or display is not None or decimals is not None:
            _fail(
                "point_metadata_matrix",
                "Non-numeric points require null canonicalUnit, displayUnit, and decimals",
            )
        return
    if canonical is None or display is None:
        if canonical is not None or display is not None:
            _fail(
                "point_metadata_matrix",
                "Numeric point units must both be null or both be set",
            )
        return
    if display not in V1_DISPLAY_UNITS.get(canonical, frozenset()):
        _fail("point_metadata_matrix", "Point units are not compatible in snapshot V1")


def validate_semantics(document: dict[str, Any]) -> None:
    """Validate V1 semantics after structural JSON Schema validation."""

    _validate_timestamp(document["capturedAt"])
    structure_ids = _ids(document, "structures", "Structure")
    space_ids = _ids(document, "spaces", "Space")
    asset_ids = _ids(document, "assets", "Asset")
    point_ids = _ids(document, "points", "Point")

    all_ids = structure_ids | space_ids | asset_ids | point_ids
    if len(all_ids) != sum(map(len, (structure_ids, space_ids, asset_ids, point_ids))):
        _fail("cross_kind_duplicate_id", "Projection IDs must be unique across node kinds")

    for space in document["spaces"]:
        if space["structureId"] not in structure_ids:
            _fail("unknown_structure_reference", "Space references unknown structure")
    for asset in document["assets"]:
        if asset["spaceId"] not in space_ids:
            _fail("unknown_space_reference", "Asset references unknown space")
    for point in document["points"]:
        if point["assetId"] not in asset_ids:
            _fail("unknown_asset_reference", "Point references unknown asset")
        _validate_point_metadata(point)
