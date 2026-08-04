from unittest.mock import AsyncMock, call

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
