# ONE.OS Home Assistant Edge Connector

Private Home Assistant OS add-on repository for ONE.OS local discovery and commissioning.

## Design baseline

- Source repository: `Simon3tiw/one-os`
- Approved design commit: `ae2df5f83d27a96df9d8ee59ab63a6822f408baa`
- Add-on repository baseline: `60d224b9950b9c6dcc36bd779df609c5cb86ce50`
- Scope: Phase 2B plus the default-off Phase 2C Telemetry v1 client — secure ONE.OS Central pairing and certificate lifecycle, read-only Home Assistant discovery, local ontology, commissioning UI, persistence, selected-configuration synchronization and a bounded durable offline telemetry outbox.
- Telemetry v1 uses outbound HTTPS batches over a pinned device-mTLS connection and remains disabled by default. Cloud commands and Home Assistant service calls remain excluded.

The immutable reference snapshot and development documentation remain available in
the private source repository at
`https://github.com/Simon3tiw/one-os-home-assistant-addon/tree/main/docs`; they are
not part of the manual installation bundle.

## Installation

This repository is private, so Home Assistant Supervisor cannot clone it
directly as a custom add-on repository. See [`INSTALL.md`](INSTALL.md) for
the manual bundle build and installation procedure.
