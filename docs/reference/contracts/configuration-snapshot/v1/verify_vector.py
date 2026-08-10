#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def main() -> None:
    source = Path(__file__).with_name("canonical-vectors.json")
    document = json.loads(source.read_text(encoding="utf-8"))
    projection = document["projection"]
    if list(projection) != ["structures", "spaces", "assets", "points"]:
        raise ValueError("projection key order is not canonical")
    encoded = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    expected = document["projectionSha256"]
    if b64u(hashlib.sha256(encoded).digest()) != expected:
        raise ValueError("configuration snapshot digest mismatch")
    print("configuration_snapshot_v1_vector=exact")


if __name__ == "__main__":
    main()
