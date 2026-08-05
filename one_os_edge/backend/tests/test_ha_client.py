import json
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from one_os_addon.ha.client import HomeAssistantReadOnlyClient


@pytest.mark.asyncio
async def test_snapshot_keeps_supervisor_core_prefix():
    client = HomeAssistantReadOnlyClient("test-token")
    client._commands = AsyncMock(
        return_value={"floors": [], "areas": [], "devices": [], "entities": []}
    )
    client._get = AsyncMock(return_value=[])

    await client.snapshot()

    assert client.core_url == "http://supervisor/core/"
    assert client._get.await_args == call("api/states")


@pytest.mark.asyncio
async def test_trusted_origins_come_from_read_only_home_assistant_config():
    client = HomeAssistantReadOnlyClient("test-token")
    client._get = AsyncMock(
        return_value={
            "internal_url": "http://homeassistant.local:8123",
            "external_url": "https://building.example",
        }
    )

    origins = await client.trusted_origins()

    assert origins == {
        "http://homeassistant.local:8123",
        "https://building.example",
    }
    assert client._get.await_args == call("api/config")


@pytest.mark.asyncio
async def test_registry_websocket_allows_large_entity_registry(monkeypatch):
    from one_os_addon.ha import client as client_module

    ws = AsyncMock()
    ws.recv.side_effect = [
        json.dumps({"type": "auth_required"}),
        json.dumps({"type": "auth_ok"}),
        *[
            json.dumps({"id": request_id, "type": "result", "success": True, "result": []})
            for request_id in range(1, 5)
        ],
    ]
    context = AsyncMock()
    context.__aenter__.return_value = ws
    connect = MagicMock(return_value=context)
    monkeypatch.setattr(client_module.websockets, "connect", connect)

    client = HomeAssistantReadOnlyClient("test-token")
    await client._commands(["floors", "areas", "devices", "entities"])

    assert connect.call_args.kwargs["max_size"] >= 16 * 1024 * 1024
