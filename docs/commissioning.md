# Phase 2B commissioning guide

1. Open **ONE.OS Commissioning** from Home Assistant as a current administrator.
2. Run **Discover now**. All source inventory stays local and starts unreviewed and unselected.
3. Inspect live values, source quality and immutable capability evidence.
4. Apply presentation overrides. Reset an override to resume Home Assistant inheritance; ONE.OS never writes to Home Assistant.
5. Review and select existing Points explicitly. Parent selection is a point-in-time bulk action; new children do not inherit it.
6. Use split/merge to model functional Assets independently from PhysicalDevices.
7. Treat Missing as retained mapping state. Replacement and archive are explicit, audited operations.
8. Configure the pinned ONE.OS Central destination, complete secure pairing and verify that only the selected configuration projection is synchronized.
9. Export Diagnostics only through the allowlisted endpoint; raw IDs, names, values and free error text are excluded.

Secure pairing, certificate lifecycle and selected-configuration synchronization are part of Phase 2B. MQTT telemetry, the offline telemetry outbox, cloud commands and Home Assistant service calls remain Phase 2C.

The add-on requests only `homeassistant_api` access for its read-only Home Assistant inventory client. It does not request the broader Supervisor (`hassio_api`) privilege.
