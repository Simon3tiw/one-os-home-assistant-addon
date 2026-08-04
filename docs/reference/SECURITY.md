# Securitybeleid voor ONE.OS

## Secrets

Commit nooit:

- `.env`-bestanden;
- Home Assistant-tokens;
- wachtwoorden;
- sessietokens;
- private keys of certificaten;
- databases;
- runtime- of auditlogs.

Voorbeeldconfiguratie bevat uitsluitend lege of duidelijk fictieve waarden. Productiesecrets worden later buiten Git opgeslagen in `/etc/one-os/one-os.env` met minimale filesystemrechten.

## Home Assistant

- De browser maakt geen rechtstreekse verbinding met Home Assistant.
- Alleen de lokale Edge Connector gebruikt de gedocumenteerde readinterfaces en het begrensde, op minimaal Home Assistant 2025.1.0 source-verified WebSocketcontract uit ADR-0012; browser en centrale cloud ontvangen nooit een Home Assistant- of Supervisor-token.
- Fase 2A exposeert uitsluitend een gesloten allowlist van GET-/list-/subscriptionoperaties, geen generieke request/sendmethode en geen Home Assistant-servicecallcodepad. Tests falen op iedere poging tot POST/PUT/PATCH/DELETE, registrymutatie of `call_service`.
- Alle entities zijn lokaal zichtbaar voor commissioning; alleen expliciet geselecteerde Points en noodzakelijke ancestorcontext mogen naar de cloud.
- Raw entity-ID's zijn geen publiek ONE.OS-contract.
- Home Assistant wordt niet publiek ontsloten en niet in een iframe getoond.

## Add-oncommissioning

- De volledige UI en alle gevoelige API’s zijn admin-only; `panel_admin` is geen backendautorisatie.
- Alleen verkeer van de gedocumenteerde Supervisor Ingress-proxy wordt vertrouwd. `X-Remote-User-Id` wordt voor iedere sessie/verbinding fail-closed tegen een actuele actieve `system-admin`-gebruiker gecontroleerd.
- Mutaties vereisen same-origin `Origin`, `Sec-Fetch-Site: same-origin`, JSON en een kortlevend gebruikersgebonden CSRF-token; WebSocket/SSE valideert proxy, Origin en adminstatus opnieuw.
- Directe backendtoegang, wildcard-CORS, cross-origin credentials en een aparte LAN-beheerpoort zijn verboden.
- Diagnostiek is allowlist-only en bevat geen raw HA-ID’s, namen, states, attributen, Properties, URL’s, headers, tokens, certificaten, paden, stacktraces of vrije fouttekst.

## Edge-naar-cloudegress

- Niet-geselecteerde objecten, raw HA-ID’s en HA-credentials verlaten de add-on nooit, ook niet via snapshots, logs of diagnostiek.
- Een volledige snapshot betekent uitsluitend de geselecteerde Pointprojectie plus noodzakelijke ancestorcontext en een expliciete watermark.
- Iedere installatie gebruikt een unieke intrekbare mTLS-identiteit en een broker-ACL voor uitsluitend de eigen versiegebonden topicnamespace.

## Authenticatie

- Argon2id-wachtwoordhashes
- opaque server-side sessies
- alleen sessietokenhashes in de database
- HttpOnly-cookies
- CSRF-bescherming voor mutaties
- server-side expiry en revocation
- rollen en tenantisolatie op iedere beveiligde API-route
- persistente throttling per account en IP vóór Argon2-verificatie
- gelijke Argon2-codepath voor bestaande en onbekende gebruikers
- auditlogging van succesvolle, mislukte en geblokkeerde loginpogingen
- one-shot bootstrap zonder langdurig plaintextwachtwoord in environment of filesystem

## Commando's

Bediening wordt pas in Fase 2D geactiveerd nadat het commandomodel beschikt over:

- genormaliseerde capability- en action-allowlists in de cloud plus een lokale Point-naar-HA-mapping die nooit als publiek contract wordt geëxposeerd;
- rolcontrole;
- waardevalidatie en veilige bereiken;
- command-ID en idempotency;
- vervaltijd;
- acknowledgement;
- audittrail;
- bevestiging voor impactvolle acties.

## Meldingen

Publiceer geen gevoelige informatie in een publiek issue. Gebruik een privécommunicatiekanaal voor mogelijke kwetsbaarheden.
