<!-- one-os-role {"bundleId":"phase2c-p-telemetry-authority-v2-draft4-20260825","candidateStatus":"UNFROZEN_STAGING","generation":4,"roleId":"authority_contract"} -->
# ONE.OS Phase 2C-P Telemetry Authority v2 — Draft 4

**Status:** `DRAFT 4 / STAGING PROTOCOL CANDIDATE / UNFROZEN / NOT APPROVED`  
**Datum:** 2026-08-25  
**Scope P:** wire, vier gesloten schemas, public-only vectors, strict codec, semantische/cryptografische verifiers en een hermetisch protocolreferentiemodel dat uitsluitend gevalideerde vectorbytes naar trusted transactioncommands projecteert.  
**Scope M:** toekomstige Central/Edge-productmigratie; niet geïmplementeerd en niet goedgekeurd.

## 1. Authority- en approvalgrens

Draft 4 vervangt Draft 3 uitsluitend als nieuwe staginggeneratie. Draft 3 blijft immutable FAIL-evidence. Deze bytes verlenen geen productimplementatie-, migration-, commit-, push-, deployment-, canary- of soakauthority. Het aanwezige manifest heeft status `UNFROZEN_STAGING`; het is geen final reviewmanifest, hashfreeze of reviewapproval.

P en M zijn gescheiden. P specificeert de wire. M moet later in de productrepositories als afzonderlijke exact-byte candidate worden gebouwd en gereviewd. Bestaande dirty Central `0011` en Edge `0014` zijn niet-normatieve WIP; hun paden, hashes en bytes zijn geen Draft-4-rollen.

## 2. Canonical wire

Iedere wire is exact één canonical UTF-8 JSON-object: geen BOM of omliggende whitespace, keys Unicode-codepoint-lexicografisch, separators `,` en `:`, minimale escaping, geen Unicode-normalisatie, duplicate keys recursief verboden, geen floats/exponenten/non-minimale integers, geen NaN/Infinity en geen lone surrogates. Integerauthority gebruikt exact `type(x) is int`; booleans en `7.0` zijn geen integers. Controltijden zijn Gregorian-valid UTC-seconden. Telemetry-recordtijden zijn exact Gregorian-valid UTC-milliseconden.

JSON Schema verleent alleen structurele acceptance. Protocolacceptatie vereist de manifestrol `semantic_validator` (`validate_one_os_phase2c_p_draft4.py`); crypto-/issuanceacceptatie vereist de manifestrol `semantic_crypto_verifier` (`verify_semantics_one_os_phase2c_p_draft4.py`).

## 3. TelemetryBatch, identitybijectie en ACK

TelemetryBatch v2 bevat uitsluitend de gesloten batchschemafields. `payloadSha256` is SHA-256 over `ONE.OS-TELEMETRY-BATCH-PAYLOAD-V2\0 || canonical(payload)`. De aggregate som van `samples + qualityEvents + gaps` is exact `1..500`; iedere array is maximaal 500. Een lege renewalcut is `backlogMode=none` en bevat geen TelemetryBatch.

Durable ingest bewaart raw requestbytes, requesthash, batch-ID en terminal responsebytes als één transactie. Zowel `(installationId,batchId)`→andere requestbytes/hash als `(installationId,requestSha256)`→andere batch-ID, en dezelfde aliases met niet-bytegelijk raw request, geven exact HTTP 409 en de canonical body:

- `schemaVersion="one-os-telemetry-error/v2"`;
- submitted canonical `batchId`;
- SHA-256 van submitted raw canonical bytes;
- `code="immutable_identity_conflict"`;
- `retryClass="terminal_quarantine"`;
- één opgeslagen `decidedAt`.

De conflictledgerkey is `SHA256("ONE.OS-TELEMETRY-CONFLICT-V2\0" || installationId || batchId || requestSha256)`. Exacte loserreplay geeft bytegelijk dezelfde error; exacte winnerreplay geeft bytegelijk de opgeslagen ACK.

## 4. RenewalContext en historical receipt

Eén immutable `RenewalContext` komt uitsluitend uit atomair opgeslagen startrequest, reservation en issuerresultaat: request-ID/hash, installation, lineage, installationrevision-before, telemetryrevision-before/after, old credential/certificate DER/SPKI, pending credential, CSR DER/SPKI, backlogmode, manifesthash en cut-marker.

Historical receipt bindt exact die context. `allowedTransportCredentialIds` is exact de bytelexicografisch gesorteerde lijst `[oldCredentialId,pendingCredentialId]`. Entries zijn objectgelijk de opgeslagen manifestentries. `historicalAuthorizationRevision=k`, `ingestAuthorizationRevision=k+1` na overflowcheck. `expiresAt == notBefore + 86400 seconden`. Receiptbytes en hash worden één keer opgeslagen; GET reconstrueert nooit.

## 5. Pending, issued en renewal-ACK

Pending en issued herhalen exact installation, lineage, installationrevision-before, k/k+1, manifest, receipt, old credential/certificate DER+SPKI, new credential en CSR DER+SPKI. `newCredentialId==pendingCredentialId`. Issued voegt leaf DER-hash, leaf-SPKI-hash, certificate PEM en CA-chain PEM toe. De equality chain is `CSR SPKI == durable pending SPKI == issued leaf SPKI`; certificatehashes zijn altijd over DER.

De signed ACK herhaalt alle stored-start/issued aliases plus start- en issued-responsehash. Alleen de stored issued-new SPKI is signatureauthority; pending mTLS leaf is bytegelijk de stored issued leaf. ACK-response herhaalt alle aliases en gebruikt afzonderlijk `installationRevisionAfter=installationRevisionBefore+1`. Raw ACK-request, requesthash, response en responsehash committen atomair. Replaylookup op `(requestId,ACK-requesthash)` gebeurt vóór expiry/statuscontrole.

## 6. Cancel- en capability-DAG

Cancelresponse bindt exact cancel-ID/requesthash, target-ID/startrequesthash/manifesthash, installation, lineage, telemetryrevision, authenticating current credential/certificate, status en decidedAt. De cancelledger dwingt beide bijecties af; iedere partiële targetcollision is terminal conflict. GET geeft uitsluitend stored bytes.

Capability bevat `issuedAt` en `expiresAt` met exact `expiresAt=issuedAt+300s`. Central bewaart canonical capabilitybytes en hash. Enable signed preimage bindt capabilityhash, nonce, installation, protocol-ID, exact vier schemahashes, capability issuedAt/expiresAt en expected telemetryrevision. Onder rowlock geldt `issuedAt <= DB-now < expiresAt`; nonceconsumptie, enabletuple en stored responsebytes committen atomair.

## 7. CSR/X.509-profiel

PKCS#10 is exact DER zonder trailing bytes, P-256, ECDSA-SHA256, geldig self-signed, exact subject `CN=<pendingCredentialId>`, exact één extensionRequest met exact één noncritical SAN URI `urn:one-os:installation:<installationId>:credential:<credentialId>`.

Leaf is X.509 v3, ECDSA-SHA256, positive serial `1..2^159-1`, exact issuer/subject, CSR-SPKI, validity binnen CA en issuanceinstant, en exact 366 dagen in deze fixtureprofile. Extensievolgorde/criticality is normatief:

1. BasicConstraints critical CA=false;
2. KeyUsage critical uitsluitend digitalSignature;
3. EKU critical uitsluitend clientAuth;
4. SAN noncritical exact één verwachte URI;
5. SKI noncritical RFC 5280 method 1;
6. AKI noncritical uitsluitend issuer-SKI keyIdentifier.

Root heeft exact BasicConstraints critical CA=true/pathLen=0, KeyUsage critical keyCertSign+crlSign en method-1 SKI noncritical. `issuerId` is exact `SHA-256(canonical issuer/root certificate DER)`. De tuple `(issuerId,serial-positive-integer)` is zowel in de cryptoverifier als de durable ledger uniek; alleen byte-identieke operationreplay mag dezelfde leaf hergebruiken.

## 8. Repair/replacement en toekomstige M-gate

Draft 4 introduceert geen nieuwe publieke adminwire of caller-supplied authority-evidencehash. Central telemetryinvalidatie is een in-process hook binnen de bestaande geauthenticeerde pairing repair/replacement-rowlocktransactie. De hook ontvangt trusted databaseobjecten/FK's en commit atomair telemetryrevision/tombstone, sluit current/pending credentials, invalideert receipts, quarantinet uncommitted entries en terminaliseert renewal/cancel/enable met stored loserbytes. Edge gebruikt bestaande HA-admin + trusted ingress + same-origin + CSRF + confirmed pairingtransition. Cross-installation replacement blijft unsupported zonder productauthority.

De latere M-gate vereist preflight vóór DDL, migrationlock over preflight+DDL, weigering bij iedere bestaande ingest/journal/lease/ACK-row, geen inferentiële backfill, alleen ondubbelzinnige paired baseline, named CHECKs/composite FKs/partial unique indexes/32-byte hashes, fresh→head, predecessorroundtrip, dirty refusal met ongewijzigde catalog, SQLite/PostgreSQL/ORM-parity en echte PostgreSQL lock/raceprobes.

## 9. Stagingvectors en grenzen

De public vector-DAG materialiseert 256 canonical TelemetryBatch parents → echte lengths/hashes → 256-entry manifest → startrequest → exact receipt → pending → issued public leaf → issued hash → signed ACK → ACK-response. Ook aanwezig: cancel-DAG, capability/enable-DAG, exact immutable-identity-conflictwire, entrygrenzen 255/256/257 en aggregate 1/499/500/501 inclusief `(500,0,0)`, `(0,500,0)`, `(0,0,500)`, `(498,1,1)` en reject `(499,1,1)`.

Huidige concrete 256-DAG: 256 unieke batches/requesthashes, iedere request 998 bytes, `totalRequestBytes=255488`, manifest 60255 bytes, receipt 60627 bytes, start 61701 bytes en issued response 63165 bytes. Deze is de maximale **entrycount**-witness, niet zelf de exact-byte cap-fill witness. De afzonderlijk gebonden rollen `cap_x509_boundary_evidence` en `cap_x509_boundary_verifier` bewijzen voor manifest, receipt, renewal start en issued response ieder een constructible canonical exact-cap/cap+1-paar; die bewijsstatus geldt uitsluitend wanneer de gesloten full-manifestgate alle 19 rollen accepteert. Dit is `UNFROZEN_STAGING`-constructibility en verleent geen protocolfreeze-, product-, migratie- of deploymentauthority.
