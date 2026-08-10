# Fase 2B.3 — geselecteerde inventory- en configuratiesync

## Status en scope

Deze specificatie sluit het inventorysync-deel van Fase 2B uit de Home Assistant Edge Connector-master-spec. Zij begint pas nadat Fase 2B.2 één actieve mTLS-devicecredential heeft opgeleverd.

Fase 2B.3 publiceert uitsluitend de actuele, effectief geselecteerde configuratieprojectie van één Installation naar de reeds gebonden Site. Zij publiceert geen telemetryreeks, outboxrecord, command, Home Assistant-servicecall, niet-geselecteerd object of raw Home Assistant-bronmetadata. MQTT, WSS, presence, capture-watermarks, live resync en time-seriesopslag blijven Fase 2C.

## Projectiegrens

Een Point is uitsluitend effectief geselecteerd wanneer lokaal tegelijk geldt:

- `selectionIntent = include`;
- `reviewStatus = reviewed`;
- `sourceLifecycle = active`;
- de SourceBinding is niet ambigu of onbevestigd tijdelijk;
- iedere vereiste normalisatie- en unitvalidatie is geldig.

Edge neemt alleen deze Points en hun minimaal vereiste `Structure → Space → Asset`-context op. Een parentactie uit het verleden autoriseert geen later ontdekt kind. Een Point dat niet langer effectief geselecteerd is, ontbreekt in de volgende snapshot en wordt Central-side retired; de stabiele Point-ID en historische referentie worden niet hergebruikt.

Verboden in iedere outbound snapshot:

- Home Assistant entity-, device-, area-, config-entry- of registry-ID’s;
- raw attributes, diagnostics, tokens, URLs of protocolmetadata;
- niet-geselecteerde nodes of Points;
- private keys, certificaatbytes, pairingcode, bootstrap- of recoverysecret;
- actuele meetwaarden, histories of commandcapabilities.

## Endpoint

`POST /api/v1/edge/device/configuration-snapshots`

Authenticatie vereist dezelfde actieve/current mTLS-devicegrens als `GET /api/v1/edge/device/status`. Central leidt Installation, Tenant en Site uitsluitend af uit het gevalideerde certificaat en de actuele databasebinding. Bodyvelden mogen die autoriteit niet vervangen.

De request is strict JSON, `Content-Type: application/json`, maximaal 2 MiB, geen duplicate of onbekende velden, geen compressie in V1 en bevat exact:

- `schemaVersion`: exact `1.0`;
- `snapshotId`: canonical UUIDv4;
- `installationId`: canonical UUID, moet exact de mTLS-installatie zijn;
- `configVersion`: uint64, lokaal strikt oplopend bij iedere effectieve projectiewijziging;
- `capturedAt`: UTC RFC 3339 met `Z`, uitsluitend diagnostisch en nooit orderingautoriteit;
- `projectionSha256`: strict unpadded base64url van 32 bytes;
- `structures`, `spaces`, `assets`, `points`: deterministisch gesorteerde arrays.

Maxima per snapshot: 256 Structures, 2.048 Spaces, 4.096 Assets en 20.000 Points. Iedere string is UTF-8 zonder controls, expliciet begrensd; namen maximaal 160 codepoints, IDs maximaal 80 ASCII-tekens. ID’s zijn stabiele ONE.OS-domain-ID’s en nooit bron-ID’s.

### Canonical projection bytes

`projectionSha256` is SHA-256 over UTF-8 JSON van uitsluitend `structures`, `spaces`, `assets` en `points`, met lexicografisch gesorteerde objectsleutels, arrays oplopend op `id`, geen insignificant whitespace en JSON-getallen volgens het gedeelde V1-contract. Central canonicaliseert opnieuw en vergelijkt de digest constant-time vóór opslag.

Minimale nodevelden:

- Structure: `id`, `name`, `ontologyClass`;
- Space: `id`, `structureId`, `name`, `ontologyClass`;
- Asset: `id`, `spaceId`, `name`, `ontologyClass`;
- Point: `id`, `assetId`, `name`, `ontologyClass`, `valueType`, `canonicalUnit`, `displayUnit`, `decimals`.

`canonicalUnit`, `displayUnit` en `decimals` zijn nullable waar het Pointtype dit toestaat. Een display-unit mag nooit een incompatibele canonical unit relabelen. V1 publiceert geen controlpermission of broncapability.

## Central-state en idempotency

Central bewaart transactioneel:

- een immutable snapshotmanifest met Installation, gebonden Tenant/Site, snapshot-ID, configversion, projectiedigest, requesthash en ontvangsttijd;
- actuele projection nodes en Points met stable ID, actuele configversion en `active|retired`;
- de laatst geaccepteerde configversion en digest per Installation.

Constraints:

- `(installation_id, snapshot_id)` is uniek;
- `(installation_id, config_version)` is uniek;
- Point- en node-ID’s zijn uniek binnen één Installation;
- iedere parentreferentie moet in dezelfde snapshot bestaan;
- de snapshot-Site is uitsluitend de actuele gebonden Site onder rowlock.

Identieke retry met dezelfde snapshot-ID, configversion, projectiedigest en requesthash retourneert bytegelijk het oorspronkelijke succes zonder tweede mutatie of audit. Afwijkende retry op dezelfde snapshot-ID of configversion faalt `409`. Een lagere configversion faalt `409`. Een hogere configversion vervangt de actuele projectie in één transactie: aanwezige records worden upserted, ontbrekende eerder actieve records worden retired en pas daarna wordt het manifest current. Auditfailure rolt alles terug.

De response is `Cache-Control: no-store` en bevat exact `snapshotId`, `installationId`, `configVersion`, `projectionSha256`, `acceptedAt`, `activePointCount` en status `accepted`.

`GET /api/v1/edge/device/configuration-status` vereist actieve/current mTLS en retourneert uitsluitend de laatst geaccepteerde configversion/digest/count of `none`. Edge gebruikt dit na response-loss en restart; het endpoint publiceert geen Tenant-/Sitenaam of projectiebody.

## Edge-state en verzending

Edge bouwt de projectie binnen één consistente readtransactie uit de commissioningdatabase. Vóór netwerkverkeer schrijft en fsynct Edge atomisch een pending snapshotrecord met snapshot-ID, configversion, canonical projectiedigest en requesthash. De volledige request kan deterministisch uit de backupbare commissioningdatabase worden herbouwd; er staat geen secret in het record.

Per Installation bestaat maximaal één verzendende snapshot. Bij lokale projectiewijziging tijdens een lopende upload blijft de lopende versie immutable en ontstaat daarna een hogere versie. Response-loss wordt eerst via `configuration-status` gereconcilieerd; dezelfde snapshot mag exact worden herhaald, nooit met gewijzigde bytes.

Niet-gepaard, revoked, ontbrekend identitymateriaal, onbereikbaar Central, certificaatfout, lokale databasefout of ambigue snapshotstate faalt gesloten zonder cloudmutatie. Lokale commissioning en HA read-only discovery blijven functioneren.

## Lockvolgorde en revocationrace

Central lockt in dezelfde globale devicevolgorde: Installation, relevante pairing sessions, renewals en credentials; daarna snapshotmanifest/projectierecords op stabiele ID. Vlak vóór commit worden Installation `paired`, bound Tenant/Site, revision en exact active/current credential opnieuw gecontroleerd.

Revoke die eerst commit wint: snapshot faalt `401` en mutaties blijven afwezig. Snapshot die eerst commit wint: die ene reeds geauthenticeerde configuratieversie mag committen; revoke blokkeert iedere volgende request onmiddellijk. Storefailure is `503`, nooit een lokale acceptatie zonder persistency.

## Operationsweergave

Operations toont per Installation uitsluitend publieke syncstatus: laatst geaccepteerde configversion, digestverkorting, active Pointcount, accepted-at en healthy/stale/error. De UI toont geen raw snapshotbody of Home Assistant-bron-ID’s. Pairingstatus en configuratiesyncstatus blijven afzonderlijke assen.

## Test- en releasegates

- Gedeelde versioned JSON Schema en canonical hashvectors in beide repositories.
- Edge RED/GREEN: selectiegrens, minimale parents, deterministische canonical bytes, restart, response-loss en projectiewijziging tijdens upload.
- Negatieve exfiltratietest bouwt volledige lokale inventory met selected/unselected/orphan/disabled/diagnostic records en bewijst bytevoor-byte dat verboden identifiers/metadata niet in outbound bytes voorkomen.
- Central RED/GREEN: strict schema/limits, cert-installationbinding, parent-FK’s, digest, configversion, retire/upsert, idempotency en auditrollback.
- Echte PostgreSQL-concurrency voor dubbele versie, snapshot/revoke en twee opeenvolgende projecties.
- Echte Nginx/Unix-socket/mTLS E2E: active device accepteert snapshot, revoked device krijgt `401`, andere Installation kan alleen de eigen projectie muteren en storefailure geeft `503`.
- Operations authorization- en mobiele UI-test.
- Edge cold backup/restore behoudt commissioningselectie en pending publieke snapshotmetadata, maar bevat nooit identitymateriaal.
- Ruff/format/typecheck/tests/audits/builds groen; exact staged tree + HEAD en twee onafhankelijke reviews per repository.
- `pairingSupported=true` vereist eerst alle Fase-2B.2-gates. Configuratiesyncadvertising of faseverhoging vereist daarnaast deze volledige 2B.3-E2E-gate.

## Buiten scope

- actuele Pointwaarden of history;
- MQTT/WSS, outbox, sequence, message-ID, application ACK, gaps en capture-watermark;
- cloudcommands of Home Assistant-mutaties;
- niet-geselecteerde inventory of raw SourceBindingmetadata;
- Tenant/Site-transfer.
