# Fase 2B.2 — veilige Edge-pairing

## Status en scope

Deze specificatie vult ADR-0003 en de Home Assistant Edge Connector-master-spec normatief aan. Fase 2B.2 maakt uitsluitend veilige installation pairing, certificaatstatus, intrekking, geautoriseerde herpairing en certificaatvernieuwing operationeel. Zij publiceert geen inventory, Points, telemetry of Home Assistant-bronmetadata en activeert geen cloudbediening.

De installateur neemt één waarde over: Edge toont een kortlevende pairingcode; een `platform_admin` voert alleen die code in ONE.OS Operations in en kiest Tenant en actieve Site. Installation ID en public key zijn vooraf automatisch door Edge geregistreerd.

## Trustbootstrap

### Sandboxbesluit

- De sandboxorigin is exact `https://192.168.1.7:8080`.
- De verwachte pin is SHA-256 over het volledige DER-leafcertificaat, weergegeven als 32 uppercase hex-octetten met dubbele punten en intern als exact 32 bytes constant-time vergeleken.
- De pin mag niet uit dezelfde eerste onbevestigde TLS-verbinding worden vertrouwd. Voor deze sandbox wordt hij via de reeds vertrouwde SSH-hostgrens/rootconsole of een ondertekend deploymentartefact verkregen en door de operator buiten de Edge-verbinding vergeleken.
- Alleen na deze out-of-bandbevestiging mag exact het gepinde leafcertificaat als per-destination trustanchor gelden. Er is geen globale CA-write, `CERT_NONE`, `verify=False` of hostname-disable.
- Edge blijft certificaatgeldigheid, digitale-signature key usage, exacte IP SAN `192.168.1.7`, pin, één DNS-resolutieset, hetzelfde geselecteerde socketadres, redirectverbod, framing, responslimiet en totaaldeadline controleren.
- Certificaatwijziging vereist een nieuwe expliciete trustbootstrap.

### Origincontract

Een origin is exact `scheme://host[:port]`: uitsluitend lowercase `https`, geen userinfo, path (ook geen `/`), query, fragment, whitespace, percent-encoding of impliciete normalisatie. IPv4 gebruikt canonical dotted decimal; DNS wordt lowercase IDNA A-label; IPv6 staat tussen brackets in RFC 5952-vorm. Poort is expliciet `1..65535`; afwezig betekent 443. Parser en gereconstrueerde waarde moeten bytegelijk zijn aan de invoer. Een IP-origin vereist exact dezelfde IP SAN; CN-fallback is verboden.

## Cryptografische keuzes

- Installation ID en pairing-session ID zijn UUIDv4.
- Edge-key: ECDSA P-256 (`secp256r1`), PKCS#8 private PEM en canonical SubjectPublicKeyInfo DER/PEM.
- Public-keyfingerprint: SHA-256 over SPKI DER.
- CSR: PKCS#10 DER, door dezelfde Edge-key ondertekend; Central controleert CSR-signature en exacte SPKI-match en negeert alle aangevraagde subject/extensies.
- Nonces en bootstrap-token: 32 CSPRNG-bytes.
- Pairingcode: exact honderd CSPRNG-bits, rechtstreeks vertaald naar twintig symbolen uit `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, gepresenteerd `XXXX-XXXX-XXXX-XXXX-XXXX`.
- Normalisatie accepteert uitsluitend exact twintig symbolen uit dit alfabet, ASCII case-insensitive, zonder koppeltekens of met koppeltekens exact op posities 5/10/15/20 van de presentatie. Geen trimming, Unicode, Crockford-aliasing of lookalike-substitutie.
- Code TTL: tien minuten vanaf succesvolle eerste PoP. Expiry gebruikt een geïnjecteerde monotone/UTC-klokgrens en wordt niet verlengd.
- Central bewaart uitsluitend `HMAC-SHA256(pairing_pepper[version], normalized_code_ascii)` als geïndexeerde lookup. De ongekeyde `SHA256(normalized_code_ascii)` bestaat alleen tijdelijk voor signatureverificatie en wordt niet opgeslagen of gelogd.
- Bootstrap-token en registration recovery-secret worden alleen als HMAC-SHA256 met afzonderlijke peppers opgeslagen en constant-time vergeleken; hun plaintext valt onder dezelfde no-log/no-audit/no-backupgrens als de code.

## Normatieve V1-signingbytes

Geen JSON-string of future fixture definieert het signingcontract. De preimage is:

```text
ASCII(domain) || 0x00 || field(1) || field(2) ...
field(tag, value) = uint16_be(tag) || uint32_be(len(value)) || value
```

Tags staan exact oplopend, komen exact eenmaal voor en onbekende tags worden geweigerd. Strings zijn strikt UTF-8 zonder BOM/NUL/Unicode-normalisatie. Als UUID aangeduide velden zijn zestien raw RFC-4122-bytes en hebben in JSON exact lowercase canonical `8-4-4-4-12`. Tenant ID moet ASCII `[a-z0-9][a-z0-9._-]{0,35}` zijn en Site ID ASCII `[a-z0-9][a-z0-9._-]{0,119}`; signing en SPIFFE-pad gebruiken exact deze ongereserveerde bytes zonder percent-encoding. Bestaande IDs buiten deze grammatica zijn niet pairbaar vóór expliciete migratie. Tijden en revisions zijn unsigned 64-bit big-endian. Hashes/nonces zijn raw 32 bytes. Base64url in JSON is unpadded en strict-decoded.

P-256 ondertekent de volledige preimage met ECDSA-SHA256. Wire-signature is exact 64 bytes `r(32)||s(32)`, big-endian. Edge normaliseert naar low-S; Central vereist `1<=r<n`, `1<=s<=n/2` en weigert DER, high-S en non-canonical encodings. Contractfixtures bevatten geldige bytes/signatures en één gewijzigde vector per veld.

### Eerste PoP: `ONE.OS-PAIRING-SESSION-PROOF-V1`

1. protocol ASCII `1.0`
2. pairing-session UUID
3. Installation UUID
4. SPKI SHA-256
5. CSR SHA-256
6. edge nonce
7. server nonce
8. session expiry epochseconds
9. tijdelijke SHA-256 van normalized pairingcode

### Claim-PoP: `ONE.OS-PAIRING-CLAIM-PROOF-V1`

1. protocol ASCII `1.0`
2. pairing-session UUID
3. Installation UUID
4. SPKI SHA-256
5. Tenant ID exact ASCII
6. Site ID exact ASCII
7. claim nonce
8. claim expiry epochseconds
9. claim revision uint64
10. CSR SHA-256
11. bound Installation revision uint64

### Certificaat-ACK: `ONE.OS-PAIRING-CERT-ACK-V1`

1. protocol ASCII `1.0`
2. pairing-session UUID
3. Installation UUID
4. credential UUID
5. certificaat SHA-256
6. claim revision
7. bound Installation revision uint64

### Renewalproof: `ONE.OS-DEVICE-RENEW-V1`

1. protocol ASCII `1.0`
2. Installation UUID
3. huidige credential UUID
4. huidig certificaat SHA-256
5. request UUID
6. CSR SHA-256
7. edge nonce
8. epochminute uint64
9. Installation revision uint64

### Renewal-ACK: `ONE.OS-DEVICE-RENEW-ACK-V1`

1. protocol ASCII `1.0`
2. Installation UUID
3. oude credential UUID
4. oud certificaat SHA-256
5. nieuwe credential UUID
6. nieuw certificaat SHA-256
7. request UUID
8. ACK-expiry epochseconds
9. Installation revision uint64

## Datamodel

### `installations`

Stabiele Installation ID, actuele Tenant/Site-binding, status `unpaired|paired|revoked`, revision en current credential ID. Public-keyhistorie leeft niet uitsluitend in deze rij.

### `pairing_sessions`

Session ID, Edge-generated registration request ID, token generation uint64, mode `initial|repair`, target Installation ID, SPKI DER/fingerprint, CSR DER/hash, code HMAC + pepperversion, edge nonce, servernonce, recovery-secret-HMAC, bootstrap-token-HMAC, status, afzonderlijke deadlines, claimant, Tenant/Site, claimnonce/revision, bound Installation revision, proofrequesthash, issuance/ackstatus en timestamps. Publieke nonces mogen tot terminale retentie verbatim worden opgeslagen; code/bootstrap/recoveryplaintext nooit.

Status:

`registered → pop_verified → claimed → claim_proved → issuing → issued → acked`

Alleen de bij de status genoemde deadline mag naar `expired`; bootstrap-cancel of platform-admin-abort mag naar `cancelled` vanuit zijn expliciet toegestane bronstates. Geen andere achterwaartse overgang.

### `device_credentials`

Credential ID, Installation ID, public-keyfingerprint, CA issuer/version, gereserveerde serial, PEM-certificaat, fingerprint, not-before/not-after, status `reserved|pending_ack|active|revoked|superseded|abandoned`, revocation reason/tijd en replacement ID. Historie wordt behouden.

### Overige tabellen

- `pairing_throttles`: atomaire persistente counters.
- `credential_renewal_sessions`: maximaal één niet-terminale per Installation via partiële unique constraint; request-ID, CSR/hash, nonce, bound Installation revision, oude current credential, pending credential, status, request-/ACK-hash en ACK-deadline.
- `pairing_sessions` heeft een partiële unique constraint voor maximaal één niet-terminale session per Installation.
- `installation_audit_events`: append-only allowlisted transities zonder code/code-HMAC/bootstrap/recovery-secret/signature/CSR-body/requestbody/private key/volledig certificaat.
- Tenant/Site-consistentie krijgt een database-invariant: de claim bewaart Tenant ID en Site ID via een samengestelde foreign key naar een unieke `(managed_sites.id, managed_sites.tenant_id)`-sleutel.
- Iedere transactie die meerdere objectsoorten raakt gebruikt exact deze lockvolgorde: `installations` op ID, daarna `pairing_sessions` op ID, daarna `credential_renewal_sessions` op ID, daarna `device_credentials` op ID, daarna `device_issuers` op ID en ten slotte `managed_sites` op ID; niet-gerakende soorten worden overgeslagen en binnen een soort geldt oplopend UUID/ID. Registrationretry/proof/cancel die nog geen Installation muteren locken alleen hun ene sessionrij. Tests forceren alle revoke/abort/expiry/ACK/issuance-races onder deze volgorde.

## Endpoint- en toestandscontract

### 1. Sessionregistratie

`POST /api/v1/edge/pairing/sessions`

Vóór het eerste request schrijft Edge atomisch een transient record met registration request ID (UUIDv4), 32-byte recovery-secret, mode `initial|repair`, Installation ID (nieuw/stabiel voor initial, bestaand target voor repair), code, edge nonce, SPKI/CSR-hashes, token generation `0` en lokale created-at. De exact begrensde JSON-body bevat deze velden plus protocol, SPKI DER, CSR DER en normalized code. Central valideert formats/CSR/SPKI; voor een nieuwe initial ID maakt hij in dezelfde transactie een schone `unpaired` Installation zonder binding/credential. Daarna berekent hij code- en recovery-HMAC, maakt session/servernonce/bootstrap-token en retourneert session ID, servernonce, bootstrap-token en een vaste registration-challenge-expiry van twee minuten. Code wordt nog niet in Edge-UI getoond.

De eerste succesvolle response heeft `token_generation=1`. Een retry met dezelfde request ID en geldig recovery-secret moet bytegelijk dezelfde mode/target/key/CSR/code-HMAC/edge-nonce binden. Registrationretry, proof en cancel locken dezelfde sessionrij; alleen status `registered` mag token generation verhogen/roteren. Vanaf `pop_verified` geeft registrationretry zonder mutatie een conflict en blijft het reeds gefsyncte bootstrap-token geldig. Central verhoogt bij toegestane retry atomisch `token_generation`, retourneert dezelfde session/servernonce/registrationexpiry plus die generation, genereert een nieuw bootstrap-token en vervangt de oude token-HMAC. Edge serialiseert lokaal per request ID en commit met local CAS uitsluitend een response waarvan generation groter is dan de gefsyncte generation; een later arriverende stale response wordt genegeerd en nooit gebruikt. Daardoor is response-loss vóór lokale tokencommit herstelbaar en bestaat nooit een onbekende blokkerende session. Afwijkende retry faalt en iedere retry verbruikt rate budget.

Voor `initial` is Installation ID nieuw óf exact een bestaande schone `unpaired` Installation zonder Tenant/Site/current credential/niet-terminale session en zonder ooit actieve credential; eerdere failed reserves moeten `abandoned` zijn. Voor `repair` is Installation ID exact een bestaand `paired|revoked` target; registratie maakt uitsluitend een ongebonden candidatesession en wijzigt de Installation niet. De partial unique staat één candidate toe. Repair claim vereist later expliciete platform-admin replacementbevestiging.

### 2. Eerste PoP

`POST /api/v1/edge/pairing/sessions/{session_id}/proof`

Vereist bootstrap-token in een dedicated authorizationheader, niet in URL/cookie. De strict JSON-body bevat exact `normalizedCode` en `signature` (unpadded base64url van exact 64 bytes); duplicate/unknown velden en andere codevormen worden geweigerd. Central reconstrueert de preimage, controleert de code-HMAC en verifieert signature vóór de vaste registration-challenge-expiry en zet via compare-and-swap `registered→pop_verified`. In dezelfde transactie ontstaat een afzonderlijke code-expiry van `now + 10 minuten`; deze staat niet in de eerste signature en wordt in de response teruggegeven. Pas na deze response toont Edge de code. Identieke proofretry retourneert idempotent dezelfde publieke status en code-expiry; afwijkende retry faalt.

`POST /api/v1/edge/pairing/sessions/{session_id}/cancel` vereist bootstrap-token en expected sessionrevision. Toegestaan vanuit `registered|pop_verified|claimed` zolang issuance niet is gestart. De CAS zet `cancelled`, invalidateert code en challenge en verwijdert bij `claimed` tevens de nog unpaired Tenant/Site-binding; een bestaande paired/revoked binding wordt nooit geraakt. Hij bewaart de bootstrap-HMAC uitsluitend 24 uur voor een idempotente identieke cancelretry en schrijft audit transactioneel. Bij interactieve cancel/reset commit Edge eerst Central-cancel, schrijft/fsynct daarna lokale publieke status `cancelled` en verwijdert/fsynct vervolgens het transient secret. Onbereikbare of ambigue Central houdt de lokale session actief tot zijn vaste expiry.

### 3. Operationsclaim

`POST /api/v1/operations/pairing/claims`

Alleen `platform_admin`, met geldige sessie, JSON, CSRF en bestaande same-originpolicy. Voor mode `initial` bevat de body pairingcode, tenantId en siteId. Central verbruikt bron-/account-/globale rate budgetten vóór lookup, vindt de session via code-HMAC en retourneert voor onbekend/verlopen/verbruikt extern exact dezelfde fout.

`POST /api/v1/operations/pairing/lookups` heeft dezelfde platformadmin/JSON/CSRF/same-origin/rategrens, consumeert niets en accepteert alleen de code. Het retourneert no-store uitsluitend mode, Installation ID, candidate fingerprint, code-expiry en voor repair de bestaande Tenant/Site IDs, targetstatus/revision en oude current fingerprint; nooit code/code-HMAC/bootstrap/recovery/CSR/certificaat. Onbekend/verlopen/verbruikt is dezelfde generieke fout. De UI moet deze response tonen vóór initial claim of `confirmReplacement`.

`POST /api/v1/operations/pairing/repair-claims` gebruikt dezelfde grenzen en bevat pairingcode, expectedInstallationRevision, exact de vaste reasoncode `credential_replacement` en `confirmReplacement: true`. De code vindt exact de repairsession en target zonder extra identifier. Eén transactie volgens de vaste lockvolgorde vereist target `paired|revoked`, gelijke revision en geldige Tenant/Site; terminaliseert alle concurrerende pairing- en renewal sessions behalve exact deze repairsession; zet reserves abandoned en alle oude pending/active credentials revoked; zet target `revoked`; verhoogt Installation revision; bewaart die als `bound_installation_revision`; consumeert code en maakt claimchallenge/audit. Binding blijft gelijk. De candidate loopt claim-PoP/issuance/ACK; ACK kan alleen target weer `paired` maken via CAS op die bound revision.

In één PostgreSQL-transactie voor initial claim: Installation locken en verifiëren als schoon `unpaired`, daarna session en actieve Site locken; status/TTL/code en samengestelde Tenant/Site-invariant controleren; code exact eenmaal consumeren; Tenant/Site binden; Installation revision verhogen en als `bound_installation_revision` in de session bewaren; claimrevision verhogen; 32-byte claimnonce met twee minuten TTL genereren; audit invoegen; commit. Auditfailure rolt alles terug.

`POST /api/v1/operations/pairing/sessions/{session_id}/abort` vereist `platform_admin`, JSON/CSRF/same-origin, expected sessionrevision, expected Installation revision, vaste reden en expliciete bevestiging. Hij is geldig voor `claimed|claim_proved|issuing|issued` in initial en repair. Eén transactie volgens de vaste lockvolgorde CAS’t de bound Installation revision, verhoogt die revision, zet de session `cancelled` met reason `admin_abort`, invalideert code/bootstrap/recovery en zet iedere gekoppelde `reserved|pending_ack` credential `abandoned/revoked`; audit is atomisch. Voor initial wist hij Tenant/Site/current credential en laat een schone `unpaired` Installation zonder ooit-active credential achter; voor repair blijft target+binding `revoked`. De identieke adminretry is 24 uur op requesthash idempotent; iedere device-ACK op de oude bound revision faalt.

Iedere terminale initial device-cancel vanuit `claimed` en iedere expiry/admin-abort vanuit `claimed|claim_proved|issuing|issued` voert dezelfde modegebonden cleanup uit: alle reserves/pending credentials abandoned/revoked, voorlopige binding gewist, Installation revision verhoogd en status schoon `unpaired`. Bootstrap-geauthenticeerde device-cancel is vanaf `claim_proved` niet toegestaan; vanaf dat moment terminaliseren uitsluitend platform-admin-abort of deadline-expiry. Daardoor kan dezelfde stabiele Installation ID na terminale cleanup opnieuw mode `initial` registreren. Repairterminalisatie laat de bestaande binding/status `revoked` en verwijdert alleen candidate state.

Zodra Edge via result de geclaimde status ziet, herschrijft/fsynct het transient secret atomisch zonder de al verbruikte pairingcode; alleen bootstrap/recovery/sessionmetadata blijft tot ACK/cancel/expiry.

### 4. Claim-PoP en issuance

`GET /api/v1/edge/pairing/sessions/{session_id}/result` vereist bootstrap-token en retourneert voor `claimed` alleen minimale claimchallenge: Tenant ID, Site ID, claimnonce, expiry en revision. Edge tekent exact de claim-PoP-preimage. Voor `claim_proved` retourneert result uitsluitend session/Installation ID, status, claimrevision, bound Installation revision en issuancedeadline; de verbruikte claimchallenge wordt nooit opnieuw getoond.

`POST /api/v1/edge/pairing/sessions/{session_id}/claim-proof` vereist bootstrap-token en een strict JSON-object met exact `claimRevision` en een unpadded-base64url raw 64-byte low-S P-256-signature. Central verbruikt vóór sessielookup het persistente bronbudget, valideert bootstrap vóór inhoudelijke bodyparse en lockt daarna volgens de globale volgorde Installation, gesorteerde sessions, renewals en credentials. Onder lock controleert hij actuele status, claimrevision, bound Installation revision, wallclock- én monotone claimdeadline en de signature over alle normatieve velden. Alleen `claimed→claim_proved` is geldig; challengebytes worden geïnvalideerd, code was al bij claim verbruikt, requestbyteshash en proof-timestamp worden atomisch vastgelegd en auditfailure rolt de gehele overgang terug.

Identieke retry wordt herkend aan `(session_id, claim_revision, SHA256(request_bytes))` en mag vóór de issuancedeadline uitsluitend exact dezelfde publieke `claim_proved`-response retourneren zonder tweede revision/audit. Afwijkende body/signature/key/revision krijgt nooit een tweede serial. Succesvolle claim-PoP creëert een afzonderlijke wallclock- en monotone issuance-deadline van vijf minuten; een boot-ID-mismatch of exact bereiken van een deadline faalt gesloten en voert modegebonden expirycleanup uit. Code- en claimdeadline zijn daarna niet meer van toepassing. Strict parse- en signaturefouten tellen mee in het persistente sessiefailurebudget; de vijfde fout terminaliseert transactioneel.

### 5. Herstelbare certificaatuitgifte

Een idempotente signerworker lockt `claim_proved`, controleert deadline/bound Installation revision en voert CAS `claim_proved→issuing` uit die sessionrevision, credential ID, random positieve RFC-5280-serial van 128–159 bits, issuer-ID, exact canonical TBSCertificate-input en deadline atomisch bindt. Een retry hervat uitsluitend deze reserve. De dedicated signer schrijft het gesigneerde DER eerst naar `/var/lib/one-os/issuer-spool/{credential-id}.der.tmp`, fsynct, hernoemt atomisch naar `.der`, fsynct de mode-`0700` spooldirectory en retourneert pas dan digest; directory/bestand zijn alleen signer/backend leesbaar (`0700/0600`). Recovery valideert spool-DER byte voor byte tegen gebonden TBSCertificate, serial, issuer, key en digest en persist exact die bytes als `pending_ack`; een geldige spool wordt nooit opnieuw gesigneerd. Startup en periodieke reconciler locken de credential/session en verwijderen ieder `.tmp` of `.der` waarvan database-state niet exact dezelfde `issuing|issued` reserve/digest toestaat; zo kan een signer die na abort/expiry terugkeert alleen een niet-deliverable orphan achterlaten. Een incomplete `.tmp` is nooit deliverable, wordt verwijderd en dezelfde gebonden reserve mag vóór deadline opnieuw worden gesigneerd. Na databasecommit wordt de spoolcopy verwijderd; crash na commit is via credential-DER/digest herkenbaar. Er ontstaat nooit een tweede reserve/serial.

Expiry vóór reserve zet session expired zonder credential. Expiry in `issuing` atomiseert reserve en eventuele spool/credential naar `abandoned/revoked`, verwijdert spool na commit en voert de initial/repaircleanup uit; na deadline wordt niets geleverd. De persisttransactie controleert session/revision/deadline opnieuw, bewaart exact spool-DER, zet credential `pending_ack`, session `issued` en ACK-deadline tien minuten. Issuance stopt fail-closed bij onbetrouwbare CA, spool, tijd, database of audit.

`GET result` met bootstrap-token retourneert uitsluitend vóór de ACK-deadline het `pending_ack`-clientcertificaat en de CA-chain; geen Tenant-/Sitenaam. De `issued`-response bevat exact `sessionId`, `installationId`, `status`, `claimRevision`, `installationRevision`, `credentialId`, `certificatePem`, strict unpadded-base64url `certificateSha256`, `caChainPem` en `ackExpiresAt`, steeds met `Cache-Control: no-store`. Edge verifieert chain, keymatch, URI SAN, KU/EKU, validity en Installation ID vóór atomische lokale opslag.

Er bestaat geen bootstrap-only ACK. Exact één endpoint `POST /api/v1/edge/device/ack` vereist werkelijk mTLS met het uitgegeven certificaat, bootstrap-token en certificaat-ACK-signature. Voor de eerste commit accepteert de uitzondering uitsluitend credential `pending_ack` plus exact Installation/session/claimrevision/certfingerprint en CAS’t installation `unpaired|revoked`, `revision=bound_installation_revision`, geen current active credential en session `issued` vóór ACK-deadline. Eén transactie zet credential `active`, installation `paired`, session `acked`, current credential en audit zonder de Installation revision opnieuw te wijzigen.

Edge bewaart key+pending cert+session/ACK-requesthash atomisch als candidate vóór verzending en promoveert lokaal pas na successresponse. Bij response-loss of restart herhaalt hij met die candidate. Gedurende 24 uur accepteert hetzelfde endpoint ook exact het inmiddels `active/current` certificaat voor dezelfde `acked` session, bootstrap-HMAC, bound revision en bytegelijke ACK-requesthash en retourneert alleen het oorspronkelijke succes zonder transitie; iedere afwijkende replay faalt. Bij ACK-timeout wordt pending credential `abandoned/revoked`, session `expired` en voert Central de initial-cleanup (`unpaired`, binding leeg, revision verhoogd) of repair-cleanup (target blijft `revoked`, revision verhoogd) uit. Bootstrap-token is daarna voor andere acties ongeldig en recoveryhash wordt na 24 uur gewist.

De lokale Edge-UI biedt voor iedere identity-dragende toestand (`paired`, `revoked`, `compromised`, een geterminaliseerde repair of `identity_missing_after_restore`) geen reset die alleen de lokale status wijzigt. Herstel loopt uitsluitend via een expliciet bevestigde repair/sleutelrotatie. De bestaande private key en credential blijven daarbij intact totdat de candidate met zijn eigen mTLS-certificaat succesvol is ge-ACK't; pas daarna promoveert Edge atomisch de candidate. Lokale reset naar `unpaired` is alleen toegestaan voor `unpaired` en geterminaliseerde initial/transient states zonder identitymetadata.

## Device-CA

- Aparte device-PKI; serverleaf/key nooit hergebruiken.
- Offline root; online P-256 intermediate met `BasicConstraints CA:TRUE,pathLen:0`, `KeyUsage keyCertSign+cRLSign`, mode `0600`, alleen leesbaar door dedicated signer/service en buiten Git/databasebackup/frontend/generieke workers.
- Startup valideert key/certmatch, algoritme, constraints, validity, issuerchain en actieve issuer-ID. De transactionele bron voor issuance is exact één `device_issuers.status=active`-rij met issuer-ID, generation en SHA-256 van intermediate-DER en publieke chainbytes. Reserve kopieert beide materiaalhashes immutable naar de credentialrij. Persist lockt de registryrij opnieuw en vereist nog steeds `active` plus bytegelijke ID, generation en hashes; retirement, compromise of materiaaldrift tussen reserve en persist faalt vóór `issued`. Fout betekent geen issuance.
- Leaf: `CA:FALSE`, digitalSignature, uitsluitend `clientAuth`, 30 dagen geldig en nooit voorbij intermediate; SAN URI `spiffe://one-os/tenants/{tenant}/sites/{site}/installations/{installation}`. Central bouwt subject/SAN zelf.
- De FastAPI-webservice leest uitsluitend een expliciete publieke `issuer-id→chain-file`-registratie en bezit of leest geen signerkey. De dedicated one-shot signerworker leest de database-URL uit de serviceomgeving, accepteert uitsluitend een niet-symlinkende signer-owned mode-`0600` P-256 keyfile en een signer-owned mode-`0700` spooldirectory, verwerkt maximaal één reserve per run en reconcileert de spool bij iedere run. Wallclock, monotone klok en boot-ID worden afzonderlijk vlak vóór reserve én opnieuw na signing vlak vóór persist gelezen; expiry of een monotone-epoch/bootwissel tijdens signing heeft daardoor voorrang en kan nooit `issued` committen. De systemd timer is de periodieke trigger; key- of chainmateriaal wordt nooit via argv, stdout of audit gelogd.
- De offline P-256 root wordt op een netwerkloze, tijdelijk gebootte beheeromgeving door de platformeigenaar gegenereerd; private material staat alleen in tmpfs en wordt na ceremonie vernietigd. Sandboxauthorization is expliciet 1-uit-1 platformeigenaar; productie vereist vóór opschaling een 2-uit-3-quorum buiten deze fase.
- De ceremonie maakt twee authenticated `age`-versleutelde root-keypakketten op twee afzonderlijke offline media. De bijbehorende X25519 identities worden gescheiden opgeslagen: één in de passwordmanager van de platformeigenaar en één fysieke recoverycopy op een derde locatie. Een openbaar manifest bevat rootcertfingerprint, generation, created/expiry, mediainventory en ciphertextchecksums; manifest en rootcert mogen in Git/audit, nooit private identities.
- Iedere intermediate-issuance/retirement start met een revisiongebonden, geaudit platform-admin change record en een CSR+issuer-generation export. Offline signing vereist de actieve manifestfingerprint en levert cert+chain+checksum terug; Central activeert alleen na key/chain/constraints/generationvalidatie. Jaarlijks en vóór iedere CA-rotatie wordt één recoverycopy in een netwerkloze omgeving gedecrypt, een test-CSR getekend/gevalideerd en de toegang geaudit. Rootcompromise trekt alle descendants in, roteert root+trustbundle via expliciete onderhoudsrelease en vereist re-pairing; verlies van beide recoveryidentities maakt de PKI onherstelbaar en blokkeert issuance fail-closed.
- Source of truth van de online intermediate-key is `/var/lib/one-os/secrets/device-ca/<issuer-id>/intermediate-key.pem`, eigenaar dedicated signer, mode `0600`. Tijdens de gecontroleerde CA-ceremonie ontstaat tevens een authenticated `age`-recoverypakket met key+cert+chain+issuer-ID+manifestchecksums; ciphertext gaat naar offline backupmedia, de X25519 age-identity naar een afzonderlijke passwordmanager/offline secretdrager en geen van beide naar database/appbackup/Git. Alleen de platformeigenaar mag restore activeren. Restore vereist geslaagde AEAD-authenticatie, manifestchecksums, key/cert/chain/constraints/validitymatch en database-issuer-ID; een lagere of retired issuergeneration wordt als rollback geweigerd en iedere handeling geaudit.
- CA-rotatie ondersteunt huidig+volgend intermediate en trustbundle-overlap; issuance gebruikt één actieve issuer. Certificaten, serialadministratie, revocations en audit hebben geteste backup/recovery. Bij bewezen verlies zonder herstelbaar pakket wordt de issuer retired/compromised, worden zijn actieve credentials ingetrokken, tekent de offline root een nieuwe intermediate en volgt expliciete re-pairing; nooit wordt een nieuwe key onder dezelfde issuer-ID geïmproviseerd. Rootprivate key blijft offline.

## Bestaande HTTPS-devicegrens en revocation

Vóór `pairingSupported=true` configureert Nginx optionele clientcertificaatvalidatie tegen de device-trustbundle. Browserroutes blijven zonder clientcertificaat werken. `one-os-backend.socket` bezit `/run/one-os/backend.sock` via systemd socket activation met `SocketUser=one-os`, `SocketGroup=one-os-proxy`, `SocketMode=0660` en `DirectoryMode=0750`; alleen Nginx draait als lid van `one-os-proxy`. `one-os-backend.service` ontvangt de listener als fd 3 en start Uvicorn uitsluitend met `--fd 3`; er is geen `--host/--port` of TCP-listener. Startup/preflight controleert directory/socket owner, group, mode en fd-type en faalt bij afwijking.

Nginx verwijdert alle inkomende gelijknamige headers en `X-Real-IP`, zet `X-Real-IP` zelf uit de TLS-peer `$remote_addr` en gebruikt een stock `map`: exact `SUCCESS→SUCCESS`, `NONE→NONE`, regex `^FAILED:`→`FAILED`, default `FAILED`. Hij zet daarna exact `X-One-OS-Proxy-Auth: mtls-v1`, `X-One-OS-Client-Verify: <mapped>` en `X-One-OS-Client-Cert: $ssl_client_escaped_cert`. Cert is de eenmaal percent-escaped PEM-representatie van Nginx, maximaal 16 KiB; leeg bij geen cert. Backend accepteert headers alleen via de geërfde Unix listener, controleert de ruwe ASGI-headerlijst op exact één van ieder en geen andere `X-One-OS-Client-*`, strict-decodeert exact eenmaal naar één PEM-certificate, parseert dit begrensd en berekent DER SHA-256 en serial zelf. Hij vereist verify `SUCCESS` en een niet-leeg cert; `NONE|FAILED`, malformed escape/PEM, duplicate/missing/onverwachte device-authheader of oversize faalt gesloten. De marker is defense-in-depth; socketpermissie is peer-authenticatie.

`GET /api/v1/edge/device/status` en renewal vereisen geldig mTLS-certificaat en `installation=paired`, `credential=active`. Device ACK gebruikt uitsluitend de hierboven beschreven pending-credentialuitzondering. Iedere request controleert zonder positieve cache (`max age=0` in 2B.2) serial, fingerprint, Installation ID en status in PostgreSQL. Store unavailable betekent fail-closed `503`; revoked/unknown/mismatch `401`. Edge pollt status maximaal iedere dertig seconden en onderscheidt `revoked` van `unreachable`.

Revoke gebruikt één transactie volgens de vaste lockvolgorde: Installation, alle niet-terminale pairing sessions, alle niet-terminale renewal sessions en alle `reserved|pending_ack|active` credentials. Hij vereist expected Installation revision, verhoogt die revision, zet Installation `revoked`, terminaliseert sessions, invalideert pairingbootstrap/recovery, zet reserves `abandoned` en pending/active credentials `revoked`, en schrijft audit atomisch. Pairing-ACK CAS’t de modegebonden bronstatus (`unpaired` initial, `revoked` repair) en bound Installation revision; renewal-ACK CAS’t `installation=paired`, de bij renewalstart gebonden revision en exact de toenmalige current credential. Een revoke/abort die eerst commit laat iedere ACK falen. Nieuwe HTTPS-device requests falen onmiddellijk; in 2B.2 bestaan geen device-MQTT/WSS-verbindingen. Iedere latere MQTT/WSS-grens moet dezelfde statuscheck met cache max dertig seconden uitvoeren en actieve verbindingen bij revoke beëindigen.

Een end-to-end gate paart, bewijst mTLS-status 200, revoket, bewijst dezelfde certificate status 401 en een andere installatie blijft 200. Pas daarna mag discovery `pairingSupported=true` melden.

## Rate limits

Bronadres komt uitsluitend uit Nginx’ strict overschreven `X-Real-IP` over de permission-restricted Unix socket. Directe TCP en andere forwarded headers worden geweigerd. IPv4 budget per `/32`, IPv6 per `/64`.

PostgreSQL voert fixed-window upserts atomisch uit; counters overleven restart. Cleanup bewaart verlopen windows 24 uur. Store unavailable faalt registratie/PoP/claim/result gesloten. Budget `N` staat exact N toegestane pogingen toe en blokkeert vanaf poging `N+1`; uniforme `429` bevat integer `Retry-After` tot windoweinde en geen codebestaan-signaal. Vijf mislukte proofs zetten de session transactioneel `cancelled`, invalidateren code/challenge en vereisen een nieuwe session.

- sessionregistratie: 10 per 10 minuten per bron, 3 per 10 minuten per Installation ID, 200 per 10 minuten globaal;
- eerste/claim-PoP: 5 failures per session en 20 per uur per bron;
- Operationsclaim: 5 per minuut én 20 per uur per `(account, bron)`, 50 per uur per account, 500 per uur globaal;
- resultpoll: 1 per seconde per session, 60 per minuut per bron;
- device status/ACK/renewal: 120 per minuut per Installation ID.

Onbekende codes verbruiken bron-, account- en globale claimbudgetten. Tests injecteren klok/adres en bewijzen windowgrens, parallelle counters, IPv6-aggregatie, cleanup, restart en fail-closed storefailure.

## Operationsautorisatie en UI

In 2B.2 mogen uitsluitend `platform_admin`:

- Tenant en actieve Site lezen/creëren;
- pairingcode claimen;
- geclaimde/pending pairing revision-safe aborteren;
- installatie intrekken;
- re-pair/keyrotatie autoriseren.

Andere rollen, inclusief `installer`, krijgen `403` vóór code-/resourcebestaan wordt onthuld. Claim lockt en hercontroleert Tenant/Site na authorisatie; nonexistent, inactive en mismatch worden apart intern getest maar extern zonder cross-tenantlek. Een latere installer-scope vereist eerst een expliciet tenant/site-permissionmodel.

Operations `/ops/commissioning` bevat Tenant/Site create/select, één codeveld, claimstatus, publieke Installation/fingerprint/certstatus en abort/revoke/re-pair met expliciete bevestiging, CSRF en expected session+Installation revisions. Code komt niet in URL, browserstorage, telemetry, error/successstate of audit.

## Edge-opslag en lokale API

- Private key atomisch onder `/data/identity/`, directory `0700`, PKCS#8-file `0600`, eigenaar runtimeuser, geen symlink; bij mismatch/corruptie/onveilige owner/mode fail-closed zonder overschrijven.
- Edge Alembic `0005` bewaart alleen publieke identity/pairing/certmetadata; pairingcode en private key niet in SQLite.
- De langlevende private key en alle clientcertificaten staan onder `/data/identity/` en `config.yaml` bevat exact `backup_exclude: ["identity", "identity/**"]`, paden relatief aan appdata volgens de actuele Home Assistant appconfiguratie. Cold-backuptests inspecteren het werkelijke Supervisor-equivalente tar-artefact en bewijzen dat geen identitybestand aanwezig is; commissioning-SQLite en selecties blijven wel opgenomen.
- Na restore bevat SQLite publieke metadata maar ontbreekt `/data/identity`; startup genereert niets stil en zet `identity_missing_after_restore`. Een lokale actuele Ingress-admin kan expliciet `POST /api/v1/pairing/replace-identity-after-restore` starten: Edge maakt een candidate key, repair session en één code, terwijl de oude publieke Installation ID behouden blijft. De platformadmin claimt dezelfde code via de atomische replacementclaim, die de oude Centralcredential intrekt. Pas na nieuwe mTLS-ACK wordt candidate de actieve lokale identity. Zo kan een HA-backup nooit een clonable deviceidentity creëren en is verlies zonder oude key toch uitvoerbaar.
- De lopende code, registration request ID, recovery-secret en na response het bootstrap-token staan samen uitsluitend in een atomisch geschreven transient secretbestand onder `/data/identity/transient/`, directory `0700`, bestand `0600`, nooit via symlink. Het bestand bevat session ID/deadlines zodra bekend, wordt vóór het eerste netwerkrequest gefsynct, wordt bij iedere read tegen publieke SQLite-state gecontroleerd en wordt verplicht veilig verwijderd bij expiry, cancel, ACK, reset of mismatch. Na Operationsclaim wordt het atomisch herschreven zonder code. Het bestaat alleen om response-loss en processrestart tijdens de actieve session te herstellen.
- Home Assistant voert bij `backup: cold` geen app `backup_pre/post`-hook uit; het ontwerp vertrouwt dus niet op een onuitvoerbare pre-backupcancel. `identity` en transient secrets zijn altijd excluded. Na restore zet ontbrekende secret/identity iedere lokale niet-terminale of paired state fail-closed op `identity_missing_after_restore`; hij hervat, ACKt of pollt niets. De achtergebleven Central-session kan zonder bootstrap/pending cert niet worden benut en bereikt autonoom zijn registration/code/claim/issuance/ACK-expiry, waarbij pending credentials revoked/abandoned worden. Herstel gebruikt uitsluitend de repaircodeflow.
- `GET /api/v1/pairing/status` vereist actuele geverifieerde Ingress-admin en bevat nooit code.
- `GET /api/v1/pairing/code` vereist actuele Ingress-admin, bestaat alleen in `pop_verified`, retourneert exact code+expiry met `Cache-Control: no-store`; dit is de enige browserresponse waarin de code mag staan.
- `POST /api/v1/pairing/start|refresh|reset|rotate-key` vereisen actuele Ingress-admin, JSON, same-origin en CSRF. `refresh` is de interactieve trigger; de interne worker heeft geen browserroute.
- Achtergrondpoll gebruikt één begrensde worker, exponential backoff met full jitter 1..30 seconden, maximaal één request/seconde, herstelt state na restart en stopt op expiry/cancel/revoke. Maximaal twee gelijktijdige pairingnetwerkoperaties.
- Reset/rotate van paired, revoked, expired of restored identity start uitsluitend een lokale `repair` candidatesession en verwijderen de oude key/cert nooit vóór nieuwe mTLS-ACK. Geen stil sleutelverlies.

## Re-pairing, restore en keyrotatie

Edge maakt na expliciete lokale adminactie een candidate key (of gebruikt dezelfde key voor `same_key`), registreert mode `repair` met target Installation ID, doorloopt eerste PoP en toont één code. De oude identity blijft onaangeraakt zolang aanwezig. Operations toont na codelookup target Installation, oude en candidate fingerprint, bestaande Tenant/Site, status/revision en vaste reden; platformadmin claimt via `repair-claims` met expliciete replacementbevestiging, waarbij oude credentials atomisch worden ingetrokken. Er is geen clientcertificaat of oude private key nodig om de codeflow te starten, waardoor restore en expiry uitvoerbaar blijven.

Na repair claim doorloopt de candidate exact de normale claim-PoP, issuance, result en pending-cert mTLS-ACK. Central consumeert code/revision exact eenmaal, laat Tenant/Site onveranderd en houdt oude credentials revoked. Edge promoveert candidate pas na ACK en verwijdert/fsynct daarna oude private/certbestanden; bij cancel/expiry/fout verwijdert hij alleen candidate en behoudt hij de oude identity. Zonder oude key na restore wordt bij falen geen key gepromoveerd en kan een nieuwe repair session worden gestart.

## Renewal

Per installatie bestaat maximaal één niet-terminale renewal session. `POST /api/v1/edge/device/renewal` vereist huidig actief mTLS-certificaat, minimaal 48 uur resterende geldigheid en maximaal zeven dagen tot expiry. Eén transactie lockt Installation/current credential, bindt exact hun IDs plus Installation revision, request-ID, CSR/hash en edge nonce. De raw low-S signature over `ONE.OS-DEVICE-RENEW-V1` bevat die revision. Central accepteert uitsluitend huidige of direct vorige UTC-epochminute; requesthash maakt identieke retry 24 uur idempotent, iedere afwijking/replay faalt. Response is `pending|issued` met request-ID, deadline en bij `issued` pending credential/certchain.

`GET /api/v1/edge/device/renewals/{request_id}` accepteert vóór ACK uitsluitend het gebonden oude active cert en retourneert `pending|issued|expired`. Na succesvolle ACK accepteert hij 24 uur ook exact het nieuwe active/current cert en retourneert `acked` met de oorspronkelijke publieke IDs/fingerprints; andere certs falen. Signer delay en verloren POST/resultresponse zijn daarmee herstelbaar.

De signerstate machine geeft één nieuwe credential `pending_ack` met 24-uurs ACK-deadline. Edge valideert en bewaart pending cert+chain+request-ID+ACK-requesthash atomisch als candidate vóór ACK. Tijdens overlap blijft alleen oud `active` voor normale devicepaden; nieuw `pending_ack` mag uitsluitend `POST /api/v1/edge/device/renewals/{request_id}/ack` gebruiken. Eerste renewal-ACK vereist nieuw-cert mTLS plus raw `ONE.OS-DEVICE-RENEW-ACK-V1`, lockt volgens vaste volgorde en CAS’t renewal `issued`, Installation `paired` op bound revision en current credential exact oud; commit zet nieuw active/current, oud superseded/revoked, renewal `acked`, verhoogt Installation revision en bewaart ACK-requesthash/audit.

Bij response-loss/restart gebruikt Edge de opgeslagen candidate voor exact dezelfde ACK. Gedurende 24 uur accepteert hetzelfde endpoint exact het nieuwe active/current cert, dezelfde request-ID, oude/nieuwe IDs+fingerprints, signature en requesthash tegen status `acked` en retourneert het oorspronkelijke succes zonder transitie; iedere afwijkende replay faalt. Pas na succesresponse of `GET ... = acked` promoveert Edge candidate lokaal. Bij timeout wordt nieuw abandoned/revoked en oud blijft tot eigen expiry active. Omdat start minimaal 48 uur vóór expiry vereist, resteert na timeout minimaal 24 uur om opnieuw te renewen of code-repair te starten; na expiry werkt alleen code-repair. Beide certs zijn nooit tegelijk algemeen active.

## Golden endpoint/state-tabel

| Endpoint/worker | Toegestane bron | Authenticatie | Deadline | Idempotency/race | Resultaat/cleanup |
|---|---|---|---|---|---|
| `POST pairing/sessions` initial/repair | nieuw/schoon unpaired of bestaand paired/revoked target; geen nonterminal pairing session | recovery-secret op retry; TLS trust | registration 2m | partial unique + request-ID + row lock + generation; Edge CAS | `registered`; terminal initial blijft schoon herbruikbaar |
| `POST sessions/{id}/proof` | `registered` | bootstrap + code + P-256 signature | registrationdeadline | exact requesthash idempotent; 5 failures cancel | `pop_verified`, nieuwe code-expiry 10m |
| `POST sessions/{id}/cancel` | `registered|pop_verified|claimed` | bootstrap + expected revision | vóór issuance | CAS; identieke retry 24h | `cancelled`, code/challenge/bindingcleanup |
| Operations initial claim | `pop_verified/initial` | platformadmin sessie+CSRF+code | code-expiry | session/Site locks, code exact eenmaal | `claimed`, binding + claimdeadline 2m |
| Operations lookup | `pop_verified` | platformadmin sessie+CSRF+code | code-expiry | read-only, rate-limited, no-store | minimale initial/repair-preview; consumeert niets |
| Operations repair claim | `pop_verified/repair`, target `paired|revoked` | platformadmin sessie+CSRF+code+target revision | code-expiry | atomisch competing sessions/old credentials terminal; code eenmaal | target revoked, session claimed/bound revision, claimdeadline 2m |
| Operations abort | `claimed|claim_proved|issuing|issued` | platformadmin sessie+CSRF+beide revisions | vóór ACK | globale lockvolgorde + CAS | revision++, sessions terminal, reserve/pending revoked; initial schoon unpaired, repair revoked |
| `GET sessions/{id}/result` | `claimed|claim_proved|issuing|issued` | bootstrap | statusdeadline | read-only rate-limited | challenge, pending of exact certresultaat |
| `POST sessions/{id}/claim-proof` | `claimed` | bootstrap + claim signature/revision | claimdeadline 2m | requesthash; CAS | `claim_proved`, issuance deadline 5m |
| signer reserve/sign/persist | `claim_proved|issuing` | dedicated signer/spool | issuance deadline | CAS bindt één reserve; durable exact DER-spool | `issued/pending_ack` of terminal `abandoned`; nooit tweede serial |
| `POST edge/device/ack` | `issued/pending_ack` of identiek `acked/active` | candidate mTLS + bootstrap + ACK signature | ACK 10m/replay 24h | CAS bound Installation revision; requesthash | active/paired of exact successreplay; timeout cleanup |
| Operations revoke | installation `paired` | platformadmin sessie+CSRF+revision | geen | lockt alle sessions+credentials | revision++; pairing/renewal terminal; reserved abandoned, pending/active revoked |
| `GET edge/device/status` | installation `paired` | active mTLS | cert validity | per-request DB-check, geen positieve cache | 200 active, 401 revoked/mismatch, 503 store unavailable |
| `POST edge/device/renewal` | active cert, 7d..48h resterend | active mTLS + renewalproof | request/epochminute | één pending + request-ID | renewal pending/issued, ACK 24h |
| `GET renewals/{id}` | pending/issued of acked-retentie | oud active of exact nieuw current mTLS | ACK/replaydeadline | read-only exact resultaat | pending/issued/expired/acked |
| `POST renewals/{id}/ack` | nieuw pending of identiek acked/active | nieuw-cert mTLS + renewal-ACK | 24h | CAS bound revision/current; requesthash | één current + revision++, of exact successreplay; timeout nieuw abandoned |

## Test- en releasegates

- Versioned JSON Schemas plus byte-level signingvectors in beide repositories; fixtures verifiëren bovenstaande normatieve bytes.
- RED/GREEN TDD-tracers voor iedere transitie, malformed crypto/body, response loss, crashpoint, restart en secretgrens.
- PostgreSQL `FOR UPDATE`/CAS-concurrency: exact één claim, proof, issuance, ACK, revoke en re-pairwinnaar.
- Registration-response-loss, tokenrotatie, bootstrap-cancel en iedere statusdeadline/race hebben deterministische crashpointtests.
- Alembic fresh, upgrade en online downgrade/re-upgrade op SQLite en PostgreSQL. Online PostgreSQL-downgrade lockt `device_credentials` en `device_issuers` vóór de verliespreflight zodat gelijktijdige writes niet tussen telling en DDL kunnen committen. Een offline `0006→0005`-downgrade wordt vóór DDL-generatie geweigerd omdat exacte DER-, issuerhash- en issuerregistrystate zonder live dataquery niet lossless kan worden bewezen.
- mTLS E2E door echte Nginx/servicegrens: paired 200, revoked 401, andere installation 200, storefailure 503.
- Deploymentfixture bewijst één systemd socket/fd 3, owner/group/modes, geen backend-TCP, stock Nginx `ssl_verify_client optional`/map/Unix `proxy_pass`/singleton headers en weigering van directe UDS-connectie door iedere andere UID/GID.
- TLS adversarial: full-cert/SPKI-pinverwarring, verkeerde SAN, not-before/expiry, redirect, rebinding, framing, oversized/slow response en deadline.
- CA startup/rotation/backup/crashpointtests; geen onbekend geldig certificaat.
- Edge restart in iedere state; symlink/owner/mode/key/cert mismatch; code uitsluitend via no-store adminroute.
- Operations authorizationmatrix voor alle rollen en race met Site-deactivation.
- Ruff/format/warnings-as-errors/pip-audit; clean npm install/tests/typecheck/lint/build/audit; mobile `390×844`; secret-/artifactscan.
- Iedere gebruikerszichtbare Edge-release bump; amd64/aarch64 build/startupsmoke of expliciete blocker.
- Exact staged tree-ID + HEAD en onafhankelijke review per repository. Geen commit/push/deploy na negatieve review.
- Live Centraldeploy, device-CA-secretprovisioning, `pairingSupported=true`, Edge release/install en eerste live pairing zijn afzonderlijke expliciete keuzemomenten.

## Buiten scope

- Inventorysnapshot, Pointpublicatie, MQTT, telemetry, outbox en commands.
- Tenant/Site-transfer tijdens pairing.
- Installer-scoped pairing zonder een later expliciet permissionmodel.
- Productie-HSM/TPM-oplevering; sandbox intermediate blijft wel apart, begrensd en herstelbaar.
- Home Assistant-mutaties of generieke servicecalls.
