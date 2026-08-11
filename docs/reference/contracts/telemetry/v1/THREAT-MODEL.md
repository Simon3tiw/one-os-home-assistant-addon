# ONE.OS Telemetry v1 threat model

## Assets

- geselecteerde measurementwaarden en qualityovergangen;
- immutable snapshotbinding en Point-authorisatie;
- Edge-outboxintegriteit en beschikbare diskruimte;
- Central exact-once-effect, ordering en ingestcursor;
- devicecredential, installationbinding en tenant/site-isolatie;
- operatorbewijs van gaps, drops en ingeststatus.

## Trust boundaries

1. Home Assistant is een read-only bron maar niet automatisch vertrouwd voor waarde, tijd of metadata.
2. Edge commissioning/selectie bepaalt lokaal wat verzameld mag worden.
3. Edge filesystem/SQLite bewaart samples, gaps en immutable retries; private identity blijft apart.
4. Netwerk, DNS en pre-pin TLS zijn vijandig tot pin/SAN/geldigheid slagen.
5. mTLS bewijst credential-origin, niet de waarheid van waarden, timestamps, config of sequence.
6. Nginx/UDS-boundary attesteert clientcertificaatheaders; backend-TCP blijft verboden.
7. Central datastorecommit is de grens vóór ACK-publicatie.

## Dreigingen en normatieve mitigaties

| Dreiging | Mitigatie | Verificatie |
|---|---|---|
| Sample replay | deterministic sample-ID plus unieke streampositie; idempotente insert | identieke retry één effect |
| Zelfde ID, andere inhoud | canonical recordhash en conflict op ID/positie | `sample_id_conflict`, `sequence_conflict` |
| Batch-ID replay met andere bytes | immutable batch-ID→requesthashbinding | `batch_conflict` |
| ACK spoof/replay | bind installatie, immutable bodycredential, batch-ID, requesthash, counts en monotone cursor; actueel mTLS-credential wordt afzonderlijk via dezelfde lineage geautoriseerd | mismatch laat outbox intact |
| ACK vóór commit | ACK uitsluitend na durable commit; response-loss retry retourneert opgeslagen ACK | crashpoint- en response-losstest |
| Stale/forged config | ieder record bindt configVersion, snapshotId en projectionhash; Point/type tegen historische snapshot | stale/mismatch/retired vectors |
| Credentialrenewal met backlog | recordidentiteit bevat geen mutable installationrevision/credential; transportcredential apart geautoriseerd | renewal-backlog lifecycle |
| Revoke/repair bypass | actieve mTLS transportautoriteit plus transactionele credentialhistorypolicy | revoked upload nul inserts |
| Forged device time | tijden alleen eventmetadata; Central receipt time voor auth/retentie/rate; ±5 min future, 7d+5m past | clock vectors |
| Epoch churn | UUIDv4, start sequence 0, 64 nieuwe epochs/Point/24h op servertijd | epoch-rate test |
| Ordering regressie | streamtuple, strict signed-int64 sequence, reorderwindow 4096 en conflicts | race/ordering vectors |
| Typed-value ambiguity | boolean of canonical decimal-string; string/enum/JSON-number verboden | cross-parser vectors |
| Quality als sentinel | aparte quality event zonder value; geen `0`, empty string of repeated last value | matrixvectors |
| Silent data loss | sequence vóór outboxadmission; duurzame niet-overlappende gaprecords; geen coalescing | diskpressure/crash-E2E |
| Command smuggling | closed objects op ieder niveau; geen generic payload/metadata/action/service/target/data | unknown-member vectors vóór store |
| Source-ID/privacy leak | alleen ONE.OS Point-ID en snapshotbinding; geen HA IDs/attributes/raw payload | forbidden-field scans |
| Parser differential | exact canonical UTF-8 bytes, duplicate-key/NaN/BOM/surrogate/depthrejectie, bytegelijke artifacts | Central/Edge parity |
| Oversized/slow body | 1 MiB vóór parse, geen compression, total monotone deadline | boundary/slow-drip tests |
| Cardinality/storage abuse | 500 records, 256 streams, 1 KiB/record, rate/concurrencylimieten, bounded outbox | max+1 en resource tests |
| Tenant/site confusion | installatie uit geattesteerde mTLS-context; body moet exact overeenkomen; Site nooit body-authoriteit | wrong-installation test |
| Digest timing oracle | strict decode en constant-time digestvergelijking | unittest en code review |
| Unicode confusables/control | IDs ASCII; overige strings gesloten enums/timestamps; NFC en geen controls/surrogates | raw vectors |

## Fail-closed foutvolgorde

1. featureflag vóór bodyread;
2. raw length/content-encoding/deadline;
3. UTF-8/BOM/duplicate/constant/depth;
4. canonical-bytegelijkheid;
5. gesloten shape en lokale semantiek;
6. mTLS installation/credentialbinding;
7. rate/concurrency;
8. snapshot/Point/type/tijd/epoch/order/replay onder transactie;
9. atomische insert plus cursor plus ACK;
10. responsepublicatie.

Een fout vóór stap 8 raakt geen datastore. Iedere fout vanaf stap 8 rolt de volledige ingesttransactie terug. V1 heeft geen gedeeltelijke batchacceptatie.

## Restrisico’s en latere gates

- Een gecompromitteerde geldige Edge kan plausibele maar valse waarden produceren; anomaly detection valt buiten 2C.1.
- Central receipt time beperkt tijdmisbruik maar corrigeert geen verkeerde Edge-wallclock; clock status wordt operatorzichtbaar in 2C.6.
- Bounded outbox kan bij langdurige uitval data verliezen; duurzame gaps maken dit zichtbaar maar reconstrueren waarden niet.
- De concrete repair/re-pair backlogpolicy wordt vóór 2C.3-ingest als aparte fail-closed lifecyclematrix bevroren.
- HTTPS batching levert geen hard realtimegedrag; latency-SLO volgt in 2C.2 en rechtvaardigt niet automatisch MQTT.
