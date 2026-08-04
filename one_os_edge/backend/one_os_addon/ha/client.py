from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import websockets

from .fake import IncompatibleHomeAssistant

LIST_COMMANDS = {
    "floors": "config/floor_registry/list",
    "areas": "config/area_registry/list",
    "devices": "config/device_registry/list",
    "entities": "config/entity_registry/list",
    "users": "config/auth/list",
}
SUBSCRIPTIONS = {"subscribe_events"}
REGISTRY_EVENTS = {
    "floor_registry_updated",
    "area_registry_updated",
    "device_registry_updated",
    "entity_registry_updated",
}
BLOCKED_FRAGMENTS = ("call_service", "create", "update", "delete")


class HomeAssistantReadOnlyClient:
    """Closed Core adapter: list, GET states/config and subscriptions only."""

    def __init__(
        self,
        token: str,
        core_url="http://supervisor/core/",
        ws_url="ws://supervisor/core/websocket",
    ):
        self.__token = token
        self.core_url = core_url
        self.ws_url = ws_url
        self.connector_presence = "offline"

    def _headers(self):
        return {"Authorization": f"Bearer {self.__token}"}

    async def _get(self, path):
        async with httpx.AsyncClient(
            base_url=self.core_url, headers=self._headers(), timeout=20
        ) as client:
            response = await client.get(path)
            response.raise_for_status()
            return response.json()

    async def _commands(self, names):
        result = {}
        request_id = 1
        try:
            async with websockets.connect(self.ws_url, additional_headers=self._headers()) as ws:
                hello = json.loads(await ws.recv())
                if hello.get("type") == "auth_required":
                    await ws.send(json.dumps({"type": "auth", "access_token": self.__token}))
                    auth = json.loads(await ws.recv())
                else:
                    auth = hello
                if auth.get("type") != "auth_ok":
                    raise IncompatibleHomeAssistant("websocket auth failed")
                for name in names:
                    await ws.send(json.dumps({"id": request_id, "type": LIST_COMMANDS[name]}))
                    reply = json.loads(await ws.recv())
                    if not reply.get("success") or not isinstance(reply.get("result"), list):
                        raise IncompatibleHomeAssistant(f"required {name} command unavailable")
                    result[name] = reply["result"]
                    request_id += 1
        except IncompatibleHomeAssistant:
            raise
        except Exception as exc:
            raise IncompatibleHomeAssistant("read contract unavailable") from exc
        return result

    async def snapshot(self):
        registries = await self._commands(["floors", "areas", "devices", "entities"])
        registries["states"] = {
            s["entity_id"]: s for s in await self._get("api/states") if "entity_id" in s
        }
        self.connector_presence = "online"
        return registries

    async def trusted_origins(self) -> set[str]:
        config = await self._get("api/config")
        return {
            value.rstrip("/")
            for value in (config.get("internal_url"), config.get("external_url"))
            if isinstance(value, str) and value.startswith(("http://", "https://"))
        }

    async def is_admin(self, user_id):
        users = (await self._commands(["users"]))["users"]
        return any(
            u.get("id") == user_id
            and u.get("is_active") is True
            and "system-admin" in u.get("group_ids", [])
            for u in users
        )

    async def _subscribe_events(self, event_types: tuple[str, ...]) -> AsyncIterator[dict]:
        allowed = {"state_changed", *REGISTRY_EVENTS}
        if not event_types or any(event_type not in allowed for event_type in event_types):
            raise IncompatibleHomeAssistant("event type outside read-only allowlist")
        async with websockets.connect(self.ws_url, additional_headers=self._headers()) as ws:
            hello = json.loads(await ws.recv())
            if hello.get("type") != "auth_required":
                raise IncompatibleHomeAssistant("websocket auth contract unavailable")
            await ws.send(json.dumps({"type": "auth", "access_token": self.__token}))
            auth = json.loads(await ws.recv())
            if auth.get("type") != "auth_ok":
                raise IncompatibleHomeAssistant("websocket auth failed")
            subscriptions = {}
            for request_id, event_type in enumerate(event_types, start=1):
                subscriptions[request_id] = event_type
                await ws.send(
                    json.dumps(
                        {
                            "id": request_id,
                            "type": "subscribe_events",
                            "event_type": event_type,
                        }
                    )
                )
            pending = set(subscriptions)
            while True:
                reply = json.loads(await ws.recv())
                request_id = reply.get("id")
                if reply.get("type") == "result" and request_id in pending:
                    if reply.get("success") is not True:
                        raise IncompatibleHomeAssistant("required event subscription unavailable")
                    pending.remove(request_id)
                    continue
                if (
                    reply.get("type") != "event"
                    or request_id not in subscriptions
                    or request_id in pending
                ):
                    raise IncompatibleHomeAssistant("invalid event envelope")
                event = reply.get("event")
                if (
                    not isinstance(event, dict)
                    or event.get("event_type") != subscriptions[request_id]
                    or not isinstance(event.get("data"), dict)
                ):
                    raise IncompatibleHomeAssistant("invalid event payload")
                yield event

    async def subscribe_state_events(self) -> AsyncIterator[dict]:
        async for event in self._subscribe_events(("state_changed",)):
            yield event

    async def subscribe_registry_events(self) -> AsyncIterator[dict]:
        async for event in self._subscribe_events(tuple(sorted(REGISTRY_EVENTS))):
            yield event
