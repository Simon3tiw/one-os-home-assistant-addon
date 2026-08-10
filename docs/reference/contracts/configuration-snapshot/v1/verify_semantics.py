#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from semantic_validator import SemanticValidationError, validate_semantics


def materialize(base: dict[str, Any], operations: list[dict[str, Any]]) -> dict[str, Any]:
    document = copy.deepcopy(base)
    for operation in operations:
        parts = operation["path"].split(".")
        target: Any = document
        for part in parts[:-1]:
            target = target[int(part)] if isinstance(target, list) else target[part]
        final = parts[-1]
        if isinstance(target, list):
            target[int(final)] = copy.deepcopy(operation["value"])
        else:
            target[final] = copy.deepcopy(operation["value"])
    return document


def evaluate(document: dict[str, Any]) -> str:
    try:
        validate_semantics(document)
    except SemanticValidationError as error:
        return error.code
    return "valid"


def main() -> None:
    source = Path(__file__).with_name("semantic-vectors.json")
    vectors = json.loads(source.read_text(encoding="utf-8"))
    base = vectors["baseDocument"]
    cases = vectors["cases"]
    for case in cases:
        actual = evaluate(materialize(base, case["operations"]))
        if actual != case["code"] or (actual == "valid") != case["valid"]:
            raise ValueError(
                f"semantic vector {case['name']} expected {case['code']}, got {actual}"
            )
    print(f"configuration_snapshot_v1_semantic_vectors=exact cases={len(cases)}")


if __name__ == "__main__":
    main()
