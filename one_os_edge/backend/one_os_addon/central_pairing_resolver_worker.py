from __future__ import annotations

import json
import socket
import sys


def main() -> int:
    try:
        request = json.load(sys.stdin)
        host = request["host"]
        port = request["port"]
        if not isinstance(host, str) or type(port) is not int:
            raise ValueError("invalid resolver request")
        targets = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        result = []
        seen = set()
        for family, socket_type, protocol, _canonical_name, address in targets:
            key = (family, socket_type, protocol, address)
            if key in seen:
                continue
            seen.add(key)
            result.append([family, socket_type, protocol, list(address)])
            if len(result) == 4:
                break
        json.dump({"ok": True, "targets": result}, sys.stdout, separators=(",", ":"))
        return 0
    except (KeyError, OSError, TypeError, ValueError):
        json.dump({"ok": False}, sys.stdout, separators=(",", ":"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
