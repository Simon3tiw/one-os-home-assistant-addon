# ONE.OS — goedgekeurde architectuur

## 1. Doel

ONE.OS is de commerciële BMS-productlaag boven lokale gebouwintegraties. Het systeem biedt twee professionele gebruikersinterfaces:

1. **Customer Portal** voor eigenaars, facility managers, operatoren en viewers.
2. **Operations Portal** voor platformbeheerders, installateurs en commissioning engineers.

Home Assistant blijft lokaal verantwoordelijk voor integraties en automatiseringen. ONE.OS schermt Home Assistant volledig af van eindgebruikers.

## 2. Niet-onderhandelbare grenzen

- De browser ontvangt nooit Home Assistant-credentials.
- Alleen de lokale ONE.OS Edge Connector add-on communiceert met Home Assistant; de centrale Backend/BFF ontvangt uitsluitend genormaliseerde, expliciet geselecteerde ONE.OS-data.
- Home Assistant-entity-ID's zijn geen publiek ONE.OS-contract.
- De eerste live integratie is read-only.
- Bediening vereist een expliciete allowlist, autorisatie, validatie, idempotency en audittrail.
- Home Assistant wordt niet publiek ontsloten of in een iframe opgenomen.
- De bestaande EMS-app op `192.168.1.7` blijft volledig gescheiden.

## 3. Systeemcontext

```text
┌──────────────────────────── ONE.OS centraal ─────────────────────────┐
│ Customer Portal ─┐                                                   │
│                  ├── same-origin API ── FastAPI Backend/BFF           │
│ Operations Portal┘                         ├── Auth/SQLite             │
│                                           ├── Audit                   │
│                                           └── Runtime                 │
└─────────────────────────────────────────────┬─────────────────────────┘
                                              │ HTTPS + MQTT 5/mTLS
                                              │ uitsluitend outbound edge
┌────────────────────────────── edge ─────────▼─────────────────────────┐
│ ONE.OS Edge Connector add-on                                          │
│ ├── commissioning en ontology                                         │
│ ├── selectie, mapping en lokale policy                                │
│ ├── SQLite inventory/outbox                                           │
│ └── Home Assistant Supervisor/Core REST + WebSocket                   │
└─────────────────────────────────────────────┬─────────────────────────┘
                                              ▼
                                  Home Assistant OS/Core
                                  192.168.1.5:8123
```

## 4. Monorepo

Geplande structuur:

```text
one-os/
├── apps/
│   ├── customer-portal/       # React/Vite
│   ├── operations-portal/     # React/Vite
│   └── backend/               # FastAPI
├── addons/
│   └── one-os-edge/           # HA OS add-on: FastAPI + React
├── packages/
│   ├── design-system/         # gedeelde UI en designtokens
│   ├── domain/                # TypeScript-domeintypes
│   ├── runtime-contract/      # BuildingRuntime-contract
│   └── config/                # gedeelde lint/TS-configuratie
├── tests/
│   └── e2e/                   # Playwright
├── deploy/
│   ├── nginx/
│   └── systemd/
├── docs/
├── .env.example
├── SECURITY.md
└── README.md
```

De twee portals zijn afzonderlijke applicaties, delen hetzelfde design system en kunnen later onder afzonderlijke hostnames worden gedeployed. De eerste deployment gebruikt één listener op poort 8080 met gescheiden routes.

## 5. Deploymenttopologie

### Bestaand en onaangeroerd

| Service | Luisteradres |
|---|---|
| EMS frontend | `0.0.0.0:80` |
| EMS backend | `0.0.0.0:8000` |
| EMS InfluxDB | `0.0.0.0:8086` |

### ONE.OS

| Component | Luisteradres | Publiek op LAN |
|---|---:|---|
| Nginx frontend/gateway | `0.0.0.0:8080` | Ja |
| FastAPI Backend/BFF | `127.0.0.1:8001` | Nee |
| SQLite | lokaal bestand | Nee |

Routes voor de eerste deployment:

- `/` — Customer Portal
- `/ops/` — Operations Portal
- `/api/` — reverse proxy naar FastAPI
- `/health` — beperkte externe healthcheck

Deploymentpaden:

- applicatie: `/opt/one-os`
- operationele data: `/var/lib/one-os`
- secrets/config: `/etc/one-os/one-os.env`
- logs: systemd journal

Geplande services/configuratie:

- `one-os-backend.service`
- Nginx-site `one-os`, uitsluitend luisterend op poort 8080

De Nginx-defaultsite op poort 80 mag niet worden geactiveerd, omdat EMS daar actief is.

## 6. Backendmodules

```text
app/
├── api/
│   ├── auth
│   ├── sites
│   ├── points
│   ├── alarms
│   ├── commissioning
│   ├── commands
│   └── health
├── domain/
├── runtime/
│   ├── contract
│   ├── mock
│   ├── home_assistant
│   └── evcc
├── services/
├── persistence/
├── security/
└── main.py
```

De lokale Edge Connector is de enige component die raw Home Assistant-ID's, attributen en services kent. De centrale backend gebruikt uitsluitend stabiele ONE.OS-ID's en genormaliseerde contracten.

## 7. BuildingRuntime

Het stabiele contract omvat conceptueel:

```typescript
interface BuildingRuntime {
  getConnectionHealth(): Promise<RuntimeHealth>
  getSites(): Promise<Site[]>
  getPoints(): Promise<Point[]>
  getPointHistory(query: PointHistoryQuery): Promise<PointHistory>
  subscribe(handler: RuntimeEventHandler): Unsubscribe
  execute(command: Command): Promise<CommandResult>
}
```

Implementatievolgorde:

1. `MockBuildingRuntime` in Fase 1.
2. De lokale Edge Connector levert discovery en live read-only data in Fase 2A.
3. `CloudBuildingRuntimeAdapter` ontvangt geselecteerde edge-data vanaf Fase 2B/2C.
4. Veilige commands volgen in Fase 2D.
5. `EvccAdapter` volgt later alleen wanneer EVCC werkelijk beschikbaar is.

## 8. Domeinmodel

Kernconcepten:

- Tenant, User en Role
- Site, recursieve Structure en Space
- PhysicalDevice, Asset, Point, Property, SourceBinding en CommandCapability
- Alarm en AlarmRule
- Command, Schedule en Override
- EdgeDevice en Integration
- ChargingSite, ChargePoint, Connector, Vehicle en ChargingSession

Building en Floor zijn Structure-types, Zone is een Space-type en Equipment is een Asset-type. Een Point gebruikt een stabiele ONE.OS-identificatie; de bronentity blijft uitsluitend lokale SourceBinding- en commissioningmetadata.

Status wordt over afzonderlijke assen gemodelleerd:

- `sourceLifecycle`: `active | missing | archived`;
- `reviewStatus`: `unreviewed | reviewed`;
- `valueQuality`: `good | stale | invalid | unknown | unavailable`;
- `connectorPresence`: `online | reconnecting | offline`.

`offline` zegt dus uitsluitend iets over connectorconnectiviteit en maakt een bronobject niet Missing. Onbekende, onbeschikbare of verouderde data wordt nooit als gezond weergegeven.

## 9. Authenticatie en autorisatie

Rollen:

- `platform_admin`
- `installer`
- `tenant_admin`
- `facility_manager`
- `operator`
- `viewer`

Beveiligingsmodel:

- Argon2id-wachtwoordhashes
- opaque sessietokens
- alleen een hash van het sessietoken in SQLite
- HttpOnly-cookie
- SameSite-beleid
- CSRF-bescherming voor mutaties
- server-side expiry en revocation
- geen authenticatietoken in localStorage

## 10. Home Assistant Edge Connector

De Home Assistant OS add-on gebruikt lokaal:

- REST voor discovery, snapshots en gerichte operaties
- WebSocket voor state changes en connection health
- automatische reconnect met exponential backoff en jitter
- stale-datadetectie
- gecontroleerde logging zonder secrets
- volledige lokale discovery met expliciete cascaderende cloudselectie

Alle bronobjecten blijven lokaal zichtbaar. Alleen geselecteerde Points en noodzakelijke ancestorcontext verlaten de add-on; niet-geselecteerde objecten blijven intern.

## 11. Commandomodel

Bediening blijft uitgeschakeld tot Fase 2D. Daarna bevat elk commando minimaal:

- unieke `commandId`
- `siteId`
- genormaliseerde `targetId`
- action en gevalideerde value
- aanvrager en tijdstip
- vervaltijd
- idempotencystatus
- acknowledgement
- auditrecord

De centrale backend valideert uitsluitend het genormaliseerde ONE.OS-command en routeert het naar de juiste edge-installatie. Alleen de lokale Edge Connector vertaalt een toegestaan genormaliseerd command na zijn eigen policyvalidatie naar een concrete Home Assistant-servicecall; raw HA-identiteit en servicenames zijn geen centraal contract.

## 12. Persistence

### SQLite

Voor:

- tenants en gebruikers
- rollen en sessies
- sitestructuur
- entity- en pointmapping
- alarmstatus
- auditlog
- command-idempotency
- outbox en synchronisatiestatus

SQLAlchemy 2 en Alembic beheren schema en migraties.

### InfluxDB

InfluxDB wordt in de frontend-MVP niet gewijzigd of geïnstalleerd. De `TelemetryStore`-interface bereidt voor:

- `bms_normalized`
- optioneel `edge_raw`

InfluxDB blijft de time-seriesopslag voor centrale historiek en diagnose waar passend. De Edge Connector gebruikt geen InfluxDB als leveringsbuffer: een afzonderlijke begrensde SQLite-outbox verzorgt durable offline telemetry en acknowledgements, terwijl de backupbare configuratie-/mappingdatabase operationele state, SourceBindings en lokaal auditspoor bewaart.

## 13. UX-richting

- clean, crisp en professioneel
- datadicht maar overzichtelijk
- neutrale slatebasis met één ONE.OS-accentkleur
- subtiele borders en beperkte schaduwen
- dark en light mode
- WCAG AA
- responsief voor desktop en tablet
- mobiel bruikbaar voor status, alarmen en beperkte bediening
- geen glassmorphism, decoratieve gradients of hobby-smart-home-esthetiek
- voorlopig centraal tekstwoordmerk `ONE.OS`

## 14. Teststrategie

- backendunit- en integratietests met pytest
- fake Home Assistant REST- en WebSocketservers
- frontendunit- en componenttests met Vitest en Testing Library
- E2E met Playwright
- lint, typecheck, builds en secrets scan voor elke push
- geen live Home Assistant-token in CI

## 15. Fasegrenzen

### Fase 1

Foundation, beide portals, design system, authenticatie, mock runtime, tests en eerste deployment.

### Fase 2A

Home Assistant OS add-on, admin-only Ingress, volledige lokale discovery, ontology, live read-only waarden, overrides en cloudselectie zonder cloudverkeer.

### Fase 2B

Eenmalige pairing, deviceidentity, Tenant/Site-binding en HTTPS inventory/configuratiesync.

### Fase 2C

MQTT 5/mTLS telemetry, WSS-fallback, bounded SQLite-outbox, acknowledgements, gaps en herstel.

### Fase 2D

Veilige bediening met immutable HA CommandCapabilities, lokale toestemming, autorisatie, TTL, idempotency, acknowledgement en audittrail.

### Fase 2E

Multi-arch add-onrelease, echte HA OS-verificatie, backup/restore, upgrade, rollback en volledige securityreview.

### Latere productfases

Energie, klimaat, apparatuur, alarmen, rapportering, EVCC-domein en verdere veldbusadapters bouwen voort op dezelfde Point- en SourceBindinggrens.

Na iedere fase volgen tests, deploymentverificatie en een expliciet beslismoment.
