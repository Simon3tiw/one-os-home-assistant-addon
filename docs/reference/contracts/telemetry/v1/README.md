# ONE.OS Telemetry Contract v1 — Fase 2C.1

**Status:** normatieve kandidaat
**Transport:** HTTPS-batches over pinned device-mTLS
**Scope:** contract, canonicalisatie, validatie en threat model; geen collection, outbox, ingestopslag, uploadworker of UI

## 1. Scopegrens

Telemetry v1 transporteert uitsluitend read-only waarnemingen van Points uit een door Central historisch geaccepteerde configuration snapshot. Het contract bevat geen command, target, service, action, generic payload, attributes, sourcebinding of Home Assistant-ID. Onbekende members worden op ieder niveau geweigerd vóór datastoretoegang.

## 2. Recordsoorten

### TelemetrySample

Een immutable nieuwe waarde voor precies één Point. V1 accepteert uitsluitend:

- `booleanValue`: echte JSON-boolean;
- `decimalValue`: canonical decimale string met maximaal 18 significante cijfers en schaal 0..9.

`integer`, `float`, exponentnotatie, `string` en `enum` zijn geen v1-wiretypes. Een geheel getal wordt als decimal string zonder fractioneel deel verzonden. Snapshottypen `string` en `enum` zijn niet telemetryselecteerbaar in v1.

`valueQuality` is voor samples exact `good | stale`. `stale` bevat de laatst nieuw waargenomen typed value en is geen source lifecycle.

### TelemetryQualityEvent

Een qualityovergang zonder verzonnen of herhaalde meetwaarde. `valueQuality` is exact `invalid | unknown | unavailable`. Het record bevat geen value. Source lifecycle (`active | missing | archived`) blijft configuration/reconciliation en wordt niet als quality gecodeerd.

### TelemetryGap

Duurzaam bewijs dat een inclusief sequencebereik niet behouden of geleverd kon worden. Een gap bevat `firstMissingSequence`, `lastMissingSequence`, `detectedAt` en een gesloten reason:

- `outbox_capacity`
- `retention_expired`
- `storage_failure`
- `clock_discontinuity`
- `operator_reset`

V1 coalescet geen telemetry. Een record dat niet kan worden behouden wordt uitsluitend via een expliciet, duurzaam gapbereik verantwoord.

## 3. Identiteit en snapshotbinding

Iedere sample en quality event bindt aan:

- canonical lowercase UUIDv4 `installationId`;
- signed-int64 `configVersion` (`0..9223372036854775807`);
- canonical lowercase UUIDv4 `snapshotId`;
- strict unpadded base64url SHA-256 `projectionSha256`;
- stable ONE.OS `pointId` volgens ASCII-ID-grammatica, maximaal 80 bytes;
- canonical lowercase UUIDv4 `streamEpochId`;
- signed-int64 `sequence`, start exact op 0 en strikt oplopend per `(installationId, pointId, streamEpochId)`.

`installationRevision` staat bewust niet in telemetry: credentialrenewal mag geldige backlog niet ongeldig maken. Central autoriseert transport via de gepresenteerde actieve mTLS-credential en valideert ieder record tegen de immutable historische snapshotbinding. Revoke stopt ieder nieuw transport. Repair/re-pair vormt een aparte authorizationgrens; toelating van historische backlog wordt in 2C.3 expliciet aan credentialhistory gebonden.

Een nieuwe `streamEpochId` is alleen toegestaan wanneer sequencecontinuïteit niet meer bewijsbaar is, niet alleen na een OS-reboot. Runtimebeleid limiteert nieuwe epochs tot 64 per Point per rollende 24 uur op Central-servertijd.

## 4. Deterministische record-ID

`sampleId` heet voor alle waardesamples en quality events hetzelfde en wordt berekend als:

```text
base64url_no_pad(
  SHA-256(
    UTF8("ONE.OS-TELEMETRY-RECORD-V1\0") || canonicalRecordWithoutSampleId
  )
)
```

`canonicalRecordWithoutSampleId` bevat alle overige recordvelden. Een recordpositie `(installationId, pointId, streamEpochId, sequence)` is eveneens uniek. Zelfde positie met andere bytes is `sequence_conflict`; zelfde `sampleId` met andere bytes is `sample_id_conflict`.

Gapidentiteit is de tuple `(installationId, pointId, streamEpochId, firstMissingSequence, lastMissingSequence)` en mag niet overlappen met een andere geaccepteerde gap in dezelfde stream.

## 5. Canonical JSON v1

Canonical bytes zijn UTF-8 zonder BOM, met:

- JSON-objectkeys lexicografisch oplopend op Unicode codepoint;
- separators exact `,` en `:` zonder whitespace;
- arrays in de normatieve recordvolgorde;
- `ensure_ascii=false`, maar controls, surrogates en niet-NFC strings verboden;
- geen duplicate keys, NaN, Infinity of floating-/exponentnumbers;
- ieder JSON-integerlexeem is exact `0 | [1-9][0-9]*`; `-0`, negatieve integers, `1.0` en `1e0` zijn verboden;
- telemetrydecimalen staan uitsluitend als canonical strings in typed valuevelden;
- timestamps exact UTC `Z`, geldige kalenderdatum, seconden verplicht en 0..3 fractionele cijfers;
- UUID en base64url in exact canonical spelling.

Edge verstuurt alleen canonical batchbytes. Central parseert strict, canonicaliseert opnieuw en eist bytegelijkheid vóór datastoretoegang. HTTP `Content-Encoding` is in v1 verboden.

De JSON Schema-artifacts beschrijven de gesloten structuur ná de lexicale wiregate. JSON Schema kan een integerwaarde `1` niet onderscheiden van JSON-number `1.0`; daarom is schema-validatie alleen nooit voldoende voor wireacceptatie. De raw-negative vectors en strict byteparser zijn normatief voor lexicale nummer-, duplicate-key-, encoding-, canonicalisatie- en depthregels. Iedere conforme Central- en Edge-parser voert die gate vóór schema/semantiek uit.

## 6. Batch

Een batch bindt aan precies één `installationId` en de via mTLS gepresenteerde `credentialId`. Hij bevat drie deterministisch gesorteerde arrays: `samples`, `qualityEvents`, `gaps`.

Sortering:

1. `pointId` bytelexicografisch;
2. `streamEpochId` bytelexicografisch;
3. sequence of gap-start numeriek;
4. recordtypevolgorde `sample`, `qualityEvent`, `gap` is door de afzonderlijke arrays al gesloten.

Alle records moeten dezelfde `installationId` hebben. Een batch mag meerdere historische snapshots/configVersions bevatten om backlog na configwissel te verzenden; ieder record draagt daarom zijn eigen snapshotbinding. `payloadSha256` is:

```text
base64url_no_pad(
  SHA-256(
    UTF8("ONE.OS-TELEMETRY-BATCH-PAYLOAD-V1\0") ||
    canonical({"gaps": [...], "qualityEvents": [...], "samples": [...]})
  )
)
```

De HTTP-requesthash is strict base64url SHA-256 over de exacte canonical requestbytes, zonder domeinprefix. `batchId` is UUIDv4, eenmaal duurzaam gegenereerd en immutable gedurende retries.

## 7. ACK

Central publiceert pas na durable commit een canonical ACK met:

- `schemaVersion` exact `1.0`;
- `installationId`;
- `credentialId` van de request-mTLS-identiteit;
- `batchId`;
- `requestSha256` over exact ontvangen canonical requestbytes;
- `acceptedSamples`, `duplicateSamples`;
- `acceptedQualityEvents`, `duplicateQualityEvents`;
- `acceptedGaps`, `duplicateGaps`;
- monotone installatiegescopeerde signed-int64 `ingestCursor`;
- `acceptedAt` op Central-servertijd.

Per recordsoort moet `accepted + duplicate == requestcount`. Gedeeltelijke acceptatie is verboden. Dezelfde `batchId` plus requesthash retourneert bytegelijk dezelfde ACK; dezelfde `batchId` met andere bytes is conflict. Edge verwijdert uitsluitend de lokaal gepersisteerde records uit exact die bytegelijke batch na volledige ACKbinding en cursorregressiecontrole.

## 8. Harde limieten

- raw requestbody: maximaal 1,048,576 bytes;
- records per batch totaal: 1..500;
- maximaal 256 distinct streams per batch;
- JSON-depth: maximaal 8, root meegerekend;
- canonical record: maximaal 1,024 bytes;
- IDs: maximaal 80 ASCII-bytes;
- decimal: maximaal 18 significante cijfers, schaal 0..9;
- timestamp: maximaal milliseconden;
- sequence/config/cursor: signed-int64 nonnegative;
- runtime future skew: maximaal 5 minuten t.o.v. Central receipt time;
- runtime past age: maximaal 7 dagen plus 5 minuten;
- runtime reorderwindow: maximaal 4096 sequences per stream;
- runtime rate startbeleid: 12 batches/min/installatie, burst 3, één gelijktijdige request/installatie.

Byte-, encoding- en depthgrenzen worden vóór volledige semantische parse/datastore afgedwongen. Rate-, clock-, snapshot-, credential-, epoch- en replaybeleid worden in 2C.3 transactioneel afgedwongen en gebruiken Central-servertijd.

## 9. Besluiten voor volgende werkpakketten

- Collectionfrequentie: hybride/eventgedreven beleid in 2C.2; wirecontract blijft frequentie-agnostisch.
- Outboxretentie: maximaal 7 dagen én 256 MiB, met afzonderlijke gereserveerde controlruimte voor gaps/status.
- Coalescing: verboden in v1.
- Strings/enums: verboden in v1.
- Centralopslag: gewone PostgreSQL long-table/partitionering, geen nieuwe extensie.
- Batchgrens: 500 records en 1 MiB.
- Queryscope: ingeststatus; historische dashboard-API valt buiten de eerste 2C-release.

## 10. Expliciet buiten scope

Collection, SQLite-tabellen, HTTP-routes, PostgreSQL-ingesttabellen, runtime credentialpolicy, uploadworker, UI, dashboards, commands, actuatie en iedere Home Assistant-mutatie. Die mogen niet als neveneffect van 2C.1 worden toegevoegd.
