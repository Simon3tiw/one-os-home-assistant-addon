from __future__ import annotations

import json
import sys

from .central_destination import DiscoveryError, _test_pinned_discovery_in_worker

_MAX_REQUEST_BYTES = 4096
_SAFE_ERRORS = {"trust_error", "protocol_error", "unreachable"}


def main() -> int:
    raw_request = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    if len(raw_request) > _MAX_REQUEST_BYTES:
        print(json.dumps({"ok": False, "error": "protocol_error"}))
        return 0
    try:
        request = json.loads(raw_request)
        if not isinstance(request, dict):
            raise ValueError
        result = _test_pinned_discovery_in_worker(
            request["origin"],
            request["fingerprint"],
            timeout=float(request["timeout"]),
            max_response_bytes=int(request["maxResponseBytes"]),
        )
    except DiscoveryError as error:
        code = str(error)
        if code not in _SAFE_ERRORS:
            code = "protocol_error"
        print(json.dumps({"ok": False, "error": code}))
        return 0
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        print(json.dumps({"ok": False, "error": "protocol_error"}))
        return 0
    print(json.dumps({"ok": True, "result": result}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
