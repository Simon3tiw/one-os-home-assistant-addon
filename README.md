# ONE.OS Home Assistant Edge Connector

Private Home Assistant OS add-on repository for ONE.OS local discovery and commissioning.

## Design baseline

- Source repository: `Simon3tiw/one-os`
- Approved design commit: `ae2df5f83d27a96df9d8ee59ab63a6822f408baa`
- Add-on repository baseline: `60d224b9950b9c6dcc36bd779df609c5cb86ce50`
- Scope: Phase 2A — add-on packaging, read-only Home Assistant discovery, local ontology, commissioning UI and persistence.
- Explicitly excluded: cloud pairing, MQTT, cloud publication and Home Assistant service calls.

The immutable reference snapshot is stored under `docs/reference/`. Development, build, backup and security instructions are in `docs/development.md`; commissioning behavior is in `docs/commissioning.md`.

## Installation

This repository is private, so Home Assistant Supervisor cannot clone it
directly as a custom add-on repository. See [`INSTALL.md`](INSTALL.md) for
the manual bundle build and installation procedure.
