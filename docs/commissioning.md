# Phase 2A commissioning guide

1. Open **ONE.OS Commissioning** from Home Assistant as a current administrator.
2. Run **Discover now**. All source inventory stays local and starts unreviewed and unselected.
3. Inspect live values, source quality and immutable capability evidence.
4. Apply presentation overrides. Reset an override to resume Home Assistant inheritance; ONE.OS never writes to Home Assistant.
5. Review and select existing Points explicitly. Parent selection is a point-in-time bulk action; new children do not inherit it.
6. Use split/merge to model functional Assets independently from PhysicalDevices.
7. Treat Missing as retained mapping state. Replacement and archive are explicit, audited operations.
8. Export Diagnostics only through the allowlisted endpoint; raw IDs, names, values and free error text are excluded.

Cloud pairing, transport, MQTT and service calls do not exist in Phase 2A.
