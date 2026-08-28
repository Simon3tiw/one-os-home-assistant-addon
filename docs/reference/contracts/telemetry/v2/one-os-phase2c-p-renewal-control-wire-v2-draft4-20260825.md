<!-- one-os-role {"bundleId":"phase2c-p-telemetry-authority-v2-draft4-20260825","candidateStatus":"UNFROZEN_STAGING","generation":4,"roleId":"renewal_control_wire"} -->
# ONE.OS Phase 2C-P Renewal Control Wire v2 — Draft 4

**Status:** `DRAFT 4 / STAGING / UNFROZEN / NOT APPROVED`  
**Parent:** `one-os-phase2c-p-telemetry-authority-contract-v2-draft4-20260825.md`  
**Schema:** `one-os-phase2c-p-renewal-control-v2-draft4-20260825.schema.json`

## Endpoints en stored-byte rule

De bestaande routes blijven `POST /api/v1/edge/device/renewal`, renewal status-GET, renewal ACK, cancel plus cancelstatus-GET, capability-GET, enable-POST en enablestatus-GET. `protocol="2.0"` selecteert deze wire; v1/v2-menging faalt. Iedere GET geeft uitsluitend atomair opgeslagen canonical responsebytes. Geen GET reconstrueert securitybytes uit current rows.

## Start en reservation

Start bevat exact protocol, request/installation/lineage, old credential en old DER/SPKI-hashes, pending credential, CSR DER/DER-hash/SPKI-hash, nonce/epoch, `installationRevisionBefore`, expected telemetryrevision, mode, volledig manifest/hash en signature. Signaturepreimage is tagged framing onder `ONE.OS-DEVICE-RENEW-V2` zoals executable vastgelegd door manifestrol `protocol_helpers` (`protocol_helpers_one_os_phase2c_p_draft4.py:start_preimage`). Signer en presented mTLS zijn exact de stored old leaf.

Onder installation-rowlock valideert Central canonical bytes, schema, semantiek, mTLS, CSR/profile, hashes en signature vóór mutation. Reservation commit raw start/hash, immutable RenewalContext, manifest bytes/hash, pending credential/SPKI, k→k+1, old active→retiring, receipt bytes/hash en pending response bytes/hash atomair. Exact requestId+hash replay retourneert stored bytes; partiële collision is terminal.

## Pending/issued

Pending en issued gebruiken de aliases uit parent §5 en afzonderlijk `installationRevisionBefore`. Historical mode vereist volledige stored receipt plus hash. Issuer CAS bindt dezelfde operation, CSR en pending SPKI. Issued leaf moet volledig door de public crypto verifier geaccepteerd worden vóór `pending_ack`. Issuer+serialcollision met andere DER is corruption/terminal repair; byte-identieke replay van dezelfde operation is toegestaan.

## ACK

ACK signed preimage onder `ONE.OS-DEVICE-RENEW-ACK-V2` bindt request-ID, installation, lineage, installationrevision-before, old/new IDs, alle certificate/CSR DER+SPKI-hashes, start- en issued-responsehash, k/k+1, mode, manifest en receipt. Stored issued-new leaf is de enige signature- en mTLS-authority. Promotion commit raw ACK/hash, new active, old superseded, pointer, `installationRevisionAfter=before+1` en exact responsebytes/hash atomair. Exact ACK-replaylookup gebeurt vóór expiry/status.

## Cancel

Cancel signed preimage onder `ONE.OS-DEVICE-RENEW-CANCEL-V2` bindt cancel/target IDs, installation/lineage, current credential/certificate, target requesthash, manifesthash, expected revision en nonce. Alleen als geen reservation/receipt/pending/ingest/tombstonecollision bestaat, commit Central `cancelled_no_reservation`. Response bindt bovendien `cancelRequestSha256`. Cancel-ID↔hash en target-ID↔requesthash↔manifest zijn bijectief.

## Capability/enable

Capability is TLS-authenticated en bevat exact protocol-ID, vier runtime-schemahashes, installation, servernonce, beide availabilitybits en UTC `issuedAt/expiresAt`, exact 300 seconden uit elkaar. Enable signaturepreimage onder `ONE.OS-TELEMETRY-AUTHORITY-ENABLE-V2` bindt capabilityhash en alle capabilityaliases, expected revision en edge nonce. Rowlockacceptance vereist exact-type integers, ongebruikte nonce en `issuedAt <= DB-now < expiresAt`. Enable response herhaalt capabilityhash/nonce/tijden/schemahashes en stored revision; GET retourneert stored bytes.

## Error en replay

Na succesvolle mTLS en canonical TelemetryBatch parsing is iedere identitybijectiecollision exact HTTP 409, `immutable_identity_conflict`, `terminal_quarantine`, met submitted batch-ID/requesthash en stored decidedAt. Voor malformed/noncanonical wire vóór betrouwbare identity geldt HTTP 400 lege body zonder mutation. HTTP-status alleen verleent nooit retryauthority.

## Crypto- en sizegrenzen

CSR is maximaal 507 base64urlchars. `certificatePem` is exact één canonical leafcertificaat en maximaal 851 ASCII bytes. `caChainPem` is in Draft 4 exact één canonical rootcertificaat, zonder intermediate of tweede certificaat, en maximaal 599 ASCII bytes. De raw canonical objectcaps zijn exact 60.256 bytes voor manifest, 60.628 voor receipt, 61.703 voor renewal-start en 63.218 voor issued response; schema-geldige cap+1-bytes worden vóór verdere acceptance afgewezen met `D4S_OBJECT_BYTE_CAP`. Manifest bevat maximaal 256 entries en aggregate TelemetryBatch exact 1..500. Manifestrollen `cap_x509_boundary_evidence` en `cap_x509_boundary_verifier` bewijzen voor elke raw cap een constructible exact/cap+1-paar en voor het X.509-profiel public-only positieve en negatieve boundaries. Private sleutels zijn geen normatieve fixture.

## P/M-separatie

Dit document is protocolscope P. Het beschrijft de toekomstige producttransacties, maar implementeert geen DDL/ORM/migrationrunner en verleent geen M-authority. Repair/replacement gebruikt uitsluitend bestaande productauthenticatie als upstream grens en introduceert geen nieuwe publieke telemetry-adminroute.
