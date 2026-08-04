from __future__ import annotations

from copy import deepcopy


class IncompatibleHomeAssistant(RuntimeError):
    pass


class UnavailableHomeAssistant:
    """Fail-closed boundary used when Supervisor credentials are unavailable."""

    connector_presence = "offline"

    async def snapshot(self):
        raise IncompatibleHomeAssistant("Supervisor token unavailable")

    async def is_admin(self, user_id: str) -> bool:
        raise IncompatibleHomeAssistant("Supervisor token unavailable")

    async def trusted_origins(self) -> set[str]:
        raise IncompatibleHomeAssistant("Supervisor token unavailable")

    async def subscribe_state_events(self):
        raise IncompatibleHomeAssistant("Supervisor token unavailable")
        yield

    async def subscribe_registry_events(self):
        raise IncompatibleHomeAssistant("Supervisor token unavailable")
        yield


class FakeHomeAssistant:
    """Closed, read-only fake. Mutating calls are deliberately impossible."""

    def __init__(self, *, floors, areas, devices, entities, states, users):
        self.floors = floors
        self.areas = areas
        self.devices = devices
        self.entities = entities
        self.states = states
        self.users = users
        self.auth_available = True
        self.mutation_attempts = []
        self.connector_presence = "online"

    @classmethod
    def standard(cls):
        return cls(
            floors=[{"floor_id": "floor-1", "name": "Ground floor"}],
            areas=[{"area_id": "area-1", "name": "Office", "floor_id": "floor-1"}],
            devices=[{"id": "device-1", "name": "Office multisensor", "area_id": "area-1"}],
            entities=[
                {
                    "entity_id": "sensor.room_temperature",
                    "unique_id": "temp-001",
                    "platform": "demo",
                    "config_entry_id": "entry-1",
                    "device_id": "device-1",
                    "area_id": None,
                    "name": "Room temperature",
                    "disabled_by": None,
                    "hidden_by": None,
                    "entity_category": None,
                },
                {
                    "entity_id": "light.office",
                    "unique_id": "light-001",
                    "platform": "demo",
                    "config_entry_id": "entry-1",
                    "device_id": "device-1",
                    "area_id": None,
                    "name": "Office light",
                    "disabled_by": None,
                    "hidden_by": None,
                    "entity_category": None,
                },
                {
                    "entity_id": "sensor.outside",
                    "unique_id": "outside-001",
                    "platform": "demo",
                    "config_entry_id": "entry-1",
                    "device_id": None,
                    "area_id": None,
                    "name": "Outside",
                    "disabled_by": None,
                    "hidden_by": None,
                    "entity_category": "diagnostic",
                },
            ],
            states={
                "sensor.room_temperature": {
                    "state": "21.236",
                    "last_updated": "2026-08-04T10:00:00Z",
                    "attributes": {
                        "friendly_name": "Room temperature",
                        "unit_of_measurement": "°C",
                        "device_class": "temperature",
                        "state_class": "measurement",
                        "suggested_display_precision": 2,
                    },
                },
                "light.office": {
                    "state": "on",
                    "last_updated": "2026-08-04T10:00:01Z",
                    "attributes": {"friendly_name": "Office light", "supported_features": 0},
                },
                "sensor.outside": {
                    "state": "unknown",
                    "last_updated": "2026-08-04T10:00:02Z",
                    "attributes": {"friendly_name": "Outside"},
                },
            },
            users=[
                {"id": "admin-1", "is_active": True, "group_ids": ["system-admin"]},
                {"id": "viewer-1", "is_active": True, "group_ids": ["system-users"]},
            ],
        )

    async def snapshot(self):
        required = (self.floors, self.areas, self.devices, self.entities, self.states)
        if any(value is None for value in required):
            raise IncompatibleHomeAssistant("required ADR-0012 response missing")
        return {
            "floors": deepcopy(self.floors),
            "areas": deepcopy(self.areas),
            "devices": deepcopy(self.devices),
            "entities": deepcopy(self.entities),
            "states": deepcopy(self.states),
        }

    async def is_admin(self, user_id: str) -> bool:
        if not self.auth_available:
            raise IncompatibleHomeAssistant("config/auth/list unavailable")
        return any(
            u["id"] == user_id and u["is_active"] and "system-admin" in u["group_ids"]
            for u in self.users
        )

    async def trusted_origins(self) -> set[str]:
        return {"http://testserver"}

    async def subscribe_state_events(self):
        if False:
            yield None

    async def subscribe_registry_events(self):
        if False:
            yield None
