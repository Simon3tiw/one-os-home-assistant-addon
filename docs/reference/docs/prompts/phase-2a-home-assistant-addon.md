# Uitvoerprompt — Fase 2A: Home Assistant OS add-on en lokale commissioning

## Rol

Werk als senior product engineer, backend engineer, frontend engineer, Home Assistant add-on engineer en security engineer. Bouw en verifieer daadwerkelijk een werkende Fase 2A in de afzonderlijke private repository `Simon3tiw/one-os-home-assistant-addon`. Stop niet bij scaffolding, pseudocode, een plan of ongeoefende configuratie. Gebruik TDD aan de publieke testseams, voer alle gates echt uit en rapporteer uitsluitend werkelijk waargenomen resultaten.

## Repository en normatieve context

Gebruik de goedgekeurde documenten uit `Simon3tiw/one-os` als normatieve designbaseline en kopieer daarvan een immutable referentiesnapshot naar `docs/reference/` in de add-onrepository. Lees vóór iedere wijziging minimaal:

- `CONTEXT.md`;
- `SECURITY.md`;
- `docs/architecture.md`;
- `docs/specs/home-assistant-edge-connector-master-spec.md`;
- alle ADR’s in `docs/adr/`, in het bijzonder ADR-0001 tot en met ADR-0012;
- de add-onrepositorystructuur en eventuele expliciet geëxporteerde ONE.OS-contract-/design-tokenartefacten.

De master specification, `CONTEXT.md` en ADR’s zijn normatief waar oudere architectuurtekst nog spreekt over het rigide Building/Floor/Zone/Equipment-model of een HA-token in de centrale backend.

Deze uitvoerprompt mag pas starten nadat de ontwerpdocumentatie in `Simon3tiw/one-os` afzonderlijk is goedgekeurd, gecommit en gepusht. Noteer die designbaseline-SHA in de add-onrepository. Initialiseer de nieuwe add-onrepo met een schone `main`, maak daarna een afzonderlijke featurebranch plus worktree en stop bij onbekende of pre-existente wijzigingen. Wijzig de afzonderlijke EMS-app of zijn services/poorten nooit. Stage uitsluitend een expliciete kandidaatbestandallowlist; `git add -A` en het meenemen van onbekende wijzigingen zijn verboden. Leg na review en groene gates eerst het kandidaatdiff voor; commit, push en live deployment vereisen daarna een expliciet menselijk keuzemoment.

## Doel

Lever een installeerbare Home Assistant OS add-onfoundation met een professionele admin-only Supervisor Ingress-commissioning-UI die lokaal:

1. alle Home Assistant Floors, Areas, Devices, Entities, metadata, actuele states en technische capabilities ontdekt;
2. deze deterministisch vertaalt naar `Site → Structure → Space → Asset → Point` met PhysicalDevices en SourceBindings;
3. live waarden en kwaliteit toont;
4. Home Assistant-defaults gebruikt voor naam, unit, precision en capabilities;
5. uitsluitend ONE.OS-overrides bewaart zonder ooit terug te schrijven naar HA;
6. Brick-compatible ontologyclasses/tags en typed Properties laat beheren;
7. cloudselectie op ieder boomniveau met cascade en uitzonderingen laat configureren;
8. nieuwe en verdwenen HA-objecten veilig reconcilieert;
9. alle lokale configuratie en stable ONE.OS-ID’s persistent bewaart;
10. geen cloudverbinding, pairing, MQTT-publicatie of echte Home Assistant-servicecall uitvoert.

## Niet-onderhandelbare veiligheidsgrenzen

- Geen Home Assistant-, Supervisor-, cloud- of MQTT-credential in browserstate, localStorage, logs, tests, fixtures, screenshots, Git of antwoorden.
- De add-onbrowser communiceert uitsluitend same-origin met de lokale FastAPI-API via Ingress.
- Alleen de add-onbackend gebruikt de ondersteunde Supervisor/Core API.
- De volledige commissioning-UI en alle gevoelige read- en mutatie-API’s zijn uitsluitend toegankelijk voor een geverifieerde Home Assistant-administrator. Gebruik `panel_admin: true` alleen als defense-in-depth: accepteer uitsluitend verkeer van de officieel gedocumenteerde Supervisor Ingress-proxy (momenteel `172.30.32.2`), vereis de door Supervisor geïnjecteerde `X-Remote-User-Id`, verifieer die ID server-side via Home Assistant als actieve gebruiker met `system-admin` in `group_ids`, en faal gesloten bij ontbrekende identity of lookupfout. Gebruik daarvoor exact het in ADR-0012 gepinde, source-verified read-only `config/auth/list`-compatibiliteitscontract en behandel dit niet als onbeperkt stabiele publieke API. Het `SUPERVISOR_TOKEN` blijft uitsluitend backend-side en mag nooit in de browser of logs komen. Alleen een minimale payloadvrije containerhealthcheck mag van de gebruikersautorisatie worden uitgezonderd.
- Accepteer mutaties alleen als JSON met exact toegestane same-origin `Origin`, `Sec-Fetch-Site: same-origin` en een kortlevend, aan de geverifieerde gebruiker gebonden CSRF-token in een custom header. Valideer bronproxy, Origin en actuele adminstatus opnieuw bij WebSocket/SSE-upgrade. Gebruik geen wildcard-CORS of cross-origin credentials en blokkeer directe backendtoegang.
- Geen echte `call_service`, REST-serviceactie of andere apparaatbediening in Fase 2A.
- Home Assistant is een read-only configuratiebron: schrijf geen names, areas, units, precision, registryopties of andere metadata terug.
- Raw HA-ID’s zijn alleen commissioningmetadata/SourceBindings en nooit publieke ONE.OS-ID’s.
- Geen inbound LAN-beheerpoort; gebruik Supervisor Ingress.
- Geen secrets of databases committen.

## Verplichte preflight tegen actuele Home Assistant-documentatie

Gebruik vóór implementatie officiële Home Assistant developer/add-on-documentatie als bron van waarheid voor:

- actuele add-on repository- en manifeststructuur;
- ondersteunde amd64/aarch64 base images;
- Supervisor Ingress en base-pathgedrag;
- Home Assistant/Supervisor API-toegang vanuit een add-on;
- veilige beschikbaarheid van administratoridentity, inclusief Supervisor remote-userheaders, `panel_admin`, bron-IP-beperking en server-side adminverificatie;
- het in ADR-0012 expliciet geaccepteerde read-only Core WebSocket-contract en de minimale Home Assistant-versie `2025.1.0`;
- persistente `/data`-opslag en backupgedrag;
- add-onconfigvalidatie en lokale buildprocedure.

Leg alleen beslissingen vast die door actuele officiële documentatie of het expliciet source-verified ADR-0012-contract worden gedragen. Raad geen verouderde configkeys. Pin `homeassistant: 2025.1.0` of strenger in de add-onmetadata. Als admin-only autorisatie of de vereiste registrycommands niet beschikbaar zijn, rapporteer `incompatible_home_assistant` en stop voordat commissioningdata of muterende routes worden vrijgegeven.

## Gewenste projectvorm

Structureer de afzonderlijke repository volgens de actuele officiële Home Assistant add-onrepositoryconventies. Houd logisch gescheiden:

- add-onmanifest/build/container/rootfs;
- FastAPI-backend en Alembicmigraties;
- React/Vite commissioning-UI;
- fake Home Assistant/Supervisor testserver;
- gedeelde domein- en contractschema’s.

Gebruik binnen de add-onrepo een kleine workspace voor frontend en contracts. Neem alleen expliciet versieerbare ONE.OS-design tokens of contractschema’s over; kopieer geen centrale applicatiecode en introduceer geen build- of runtime-afhankelijkheid op `Simon3tiw/one-os`.

Ondersteun minimaal `amd64` en `aarch64`. De add-on moet achter een willekeurige Ingress-base path werken; geen absolute `/api`, asset- of routerpaden die alleen op root functioneren. Kies voor de Fase-2A mappingdatabase `backup: cold`: de backend is gestopt tijdens backup/restore. De echte Supervisorbackup/restoreproef blijft Fase 2E, maar Fase 2A moet de cold lifecycle lokaal met een tijdelijke `/data` aantonen.

## Canoniek lokaal datamodel

Implementeer persistente modellen en API-schema’s voor minimaal:

- Site;
- Structure met precies één Site- of parent-Structurebinding en type;
- Space met precies één Structurebinding en type;
- PhysicalDevice;
- Asset met precies één Spacebinding en type;
- Point met precies één Assetbinding, value quality en presentatieconfiguratie;
- SourceBinding voor HA floor/area/device/entity;
- Property met typed waarde;
- ontologyclass-URI en tags;
- immutable Home Assistant-capabilitybronbewijs plus een versieerbare, deterministische en niet-verruimende CommandCapability-projectie;
- afzonderlijke `selectionIntent = include | exclude | unset` en `reviewStatus = unreviewed | reviewed` per Point; effectieve publicatie vereist include + reviewed + active en parent tri-state is uitsluitend berekend;
- cloud control permission state;
- override provenance per overschrijfbaar veld;
- afzonderlijke source lifecycle, review status, value quality en connector presence;
- sync/reconciliation run en veilige diagnostics.

Gebruik stable, lokaal gegenereerde ONE.OS-ID’s. Wijzig een ONE.OS-ID nooit omdat een entity wordt hernoemd, verplaatst of vervangen. Leg databaseconstraints, foreign keys, cascades en uniqueness expliciet vast. Gebruik Alembic en SQLitehardening overeenkomstig de bestaande Fase-1-standaard.

Fase 2A implementeert uitsluitend de backupbare configuratie-/mappingdatabase. Reserveer een duidelijke opslaggrens voor de in Fase 2C afzonderlijk te bouwen, van add-onbackups uit te sluiten telemetry-outbox; meng outboxrecords niet in de commissioningdatabase.

Bootstrap exact één lokale Site per Installation ID. Dwing af dat iedere actieve SourceBinding uniek is op `(sourceSystem, registryKind, registryId)` en nooit tegelijk aan twee ONE.OS-objecten hangt. Replacement beëindigt de oude actieve binding en maakt de nieuwe in één transactie; expliciete transfer, Pointmove, Asset split en merge moeten SourceBindingconflicten vooraf detecteren, atomisch weigeren of veilig oplossen zonder stable Point-ID of auditverlies.

## Deterministische importregels

Implementeer minimaal:

1. HA Floor → Structure type Floor.
2. HA Area → Space onder de bijbehorende Floor/Structure; een Area zonder Floor komt onder een zichtbare synthetische Unassigned Structure.
3. HA Device → één PhysicalDevice plus één voorlopig gelijknamig Asset. De Device-area bepaalt de Space. Zonder Device-area mag alleen een unanieme Entity-area worden gebruikt; meerdere Entity-areas plaatsen het voorlopige Asset in de synthetische Unassigned Space met een placement-conflictmelding totdat de installateur splitst of plaatst.
4. Entity met Device → Point onder het voorlopige Asset.
5. Standalone Entity → voorlopig Asset plus Point.
6. Entity zonder Area/Device/Floor blijft zichtbaar via een voorlopig Asset onder expliciete synthetische Unassigned Structure/Space-containers; sla geen containmentniveau over.
7. Nieuwe bronobjecten worden automatisch toegevoegd met HA-defaults, status “nieuw/onbeoordeeld” en cloud selection uit.
8. Herhaalde discovery is idempotent en maakt geen duplicaten.
9. Reconnect of reordered API-responses verandert stable ONE.OS-ID’s niet.
10. Verdwijnen markeert het object `Missing`; niet hard verwijderen.
11. Modelleer `sourceLifecycle = active | missing | archived`, `reviewStatus = unreviewed | reviewed`, `valueQuality = good | stale | invalid | unknown | unavailable` en `connectorPresence = online | reconnecting | offline` afzonderlijk. `unavailable` is een waardequality en niet hetzelfde als `missing`; een tijdelijke disconnect maakt geen bronobject Missing.
12. Een Missing Point blokkeert cloud control permission effectief, ook als de opgeslagen toggle eerder aan stond.
13. Een installateur kan een Missing Point aan een vervangende entity koppelen met behoud van Point-ID, overrides en auditreferentie.
14. Archiveren is expliciet en reversibel waar haalbaar.
15. Gebruik per registrytype de meest stabiele beschikbare bronidentiteit. Voor Entities is `entity_id` alleen mutabele metadata; gebruik waar beschikbaar integration/platform, `unique_id` en config-entrycontext als binding. Een entity rename behoudt hetzelfde Point. Delete/recreate met dezelfde `entity_id` maar andere stabiele bronidentiteit maakt een nieuw Point en laat het oude Missing totdat expliciete replacement plaatsvindt.
16. Inventariseer alle actieve registryentries en actuele states: ook Floors zonder Areas, Devices zonder Entities, disabled/hidden Entities, Entities zonder state, diagnostic/config-Entities en dangling verwijzingen. Zij blijven lokaal zichtbaar maar starten onbeoordeeld, ongeselecteerd en zonder bediening.
17. Een Entity-area die van de Device-area afwijkt verplaatst geen Point buiten zijn Asset; markeer een placement-conflict en bied een expliciete split aan. Een state zonder Entity-registryentry krijgt een tijdelijke, niet-cloudselecteerbare binding totdat een stabiele binding beschikbaar is of expliciet wordt aanvaard.
18. Een ontbrekende parent maakt actieve descendants niet automatisch Missing. Verplaats geërfd geplaatste descendants transactioneel naar Unassigned; bij een bewuste lokale plaatsing blokkeert een placement-conflict effectieve bediening totdat dit is opgelost.
19. Archiveer nooit stil cascaderend. Toon bij Structure/Space/Asset met actieve descendants een preview en vereis expliciete rehome- of cascadekeuze. Replacement behoudt alleen na expliciete semantische bevestiging en een conflictvrije binding het ONE.OS-ID.

## Live synchronisatie

Bouw een abstracte Home Assistant/Supervisor client met:

- initiële registry/config/states-snapshot;
- WebSocket state-eventsubscription;
- automatische reconnect met exponential backoff en jitter;
- reconciliation na reconnect;
- source-verified registry-update-events voor Floor, Area, Device en Entity waar de gepinde Core-versie die biedt, gedebounced naar één reconciliation;
- een configureerbare periodieke volledige registry/state-reconciliation met jitter als verplicht vangnet, ook bij een blijvend gezonde WebSocketverbinding;
- sequence/generationbescherming tegen oude events;
- expliciete connection health;
- gecontroleerde logging zonder payload- of secretlekken.

Gebruik in Fase 2A een fake boundary voor CI en lokale ontwikkeling. Bouw de productieclient als een technisch afgedwongen read-only adapter met exact de ADR-0012-listcommands, noodzakelijke gedocumenteerde GET-routes en expliciete read/subscription-WebSocketcommandtypes; leg versioned request/responsefixtures vast. Negeer onbekende responsevelden tolerant, maar faal gesloten als een verplicht veld of command ontbreekt. Bied geen generieke REST-request-, WebSocket-send- of servicecallmethode buiten de adapter aan. Blokkeer en test minimaal POST/PUT/PATCH/DELETE en muterende WebSockettypes zoals registry create/update/delete en `call_service`. De fake registreert iedere poging en laat tests onmiddellijk falen. De volledige suite moet aantonen dat nul HA/Supervisor-mutaties zijn geprobeerd.

## Pointdefaults, live preview en overrides

Voor ieder Point toont en bewaart de API voldoende informatie voor:

- raw bronstate;
- typed/genormaliseerde waarde;
- bronunit en canonieke unit;
- displayunit;
- friendly/source name en displayname;
- beschikbare source precision;
- ingest/update timestamps;
- `valueQuality`: minimaal good, stale, invalid, unknown en unavailable;
- `sourceLifecycle`: active, missing of archived;
- `reviewStatus`: unreviewed of reviewed;
- `connectorPresence`: online, reconnecting of offline;
- device class, state class en entity category;
- source provenance;
- override/inherit status per veld.

Defaults komen uit HA. Ondersteun in Fase 2A minimaal overrides voor displaynaam, displayunit, decimalen, ontologyclass, tags en typed Properties. Een unitoverride is alleen toegestaan bij een echte compatible conversie. Een onverenigbare unitcombinatie geeft een duidelijke validatiefout. Decimalen beïnvloeden alleen presentatie, nooit bron- of opgeslagen precision. Formatteer previews deterministisch in `nl-BE` en toon maximaal het gekozen aantal decimalen.

Iedere override heeft een reset naar de actuele HA-default. Een sourcewijziging synchroniseert automatisch wanneer het veld inherited is en veroorzaakt een zichtbare driftnotificatie wanneer een override bestaat.

## Assets en commissioning

De eerste import maakt één voorlopig Asset per HA Device. Maak UI/API-acties voor:

- Asset hernoemen;
- Asset verplaatsen naar een Space;
- Points verplaatsen tussen Assets;
- een Asset splitsen door geselecteerde Points naar een nieuw Asset te verplaatsen;
- twee Assets samenvoegen zonder SourceBindings te verliezen;
- ontologyclass en tags toekennen;
- typed Properties beheren.

Maak iedere mutatie transactioneel, gevalideerd en lokaal geaudit. Het PhysicalDevice blijft los van de functionele Assets.

## Cloudselectie en toekomstige bediening

Hoewel Fase 2A nog niets publiceert, moet lokale commissioning volledig voorbereid zijn:

- cloud selection standaard uit;
- tri-state selectie op Structure, Space, Asset en Point;
- parentselectie cascadeert naar bestaande kinderen;
- individuele uitzonderingen blijven mogelijk;
- nieuw ontdekte kinderen worden niet automatisch geselecteerd door een eerder geselecteerde parent;
- een parentactie schrijft in één geaudite bulkmutatie `include` of `exclude` naar de op dat moment bestaande descendant Points; include van onbeoordeelde Points vereist een expliciete gecombineerde review-en-selectiebevestiging en parent tri-state wordt alleen uit effectieve Pointstatus berekend;
- move/split/merge behouden intentie/reviewstatus; Missing bewaart beide voor audit maar publiceert geen waarde; Archived is effectief uit; replacement behoudt intentie maar zet reviewstatus op `unreviewed`;
- API kan de effectieve selectie en uitsluitend noodzakelijke ancestorcontext deterministisch berekenen;
- UI toont geselecteerd, gedeeltelijk en ongeselecteerd.

Home Assistant levert geen universeel CommandCapability-object. Bewaar daarom het relevante read-only bronbewijs—domein, supported features, selectors, min/max/step, modes, presets, opties en adapterinput—en projecteer dit met een expliciet geversioneerde domeinadapter naar ONE.OS. De projectie mag uitsluitend aantoonbaar ondersteunde mogelijkheden bevatten, nooit verruimen en is niet handmatig bewerkbaar; onbekend of ambigu betekent niet bedienbaar. Leid `technicallyControllable` automatisch af, maar zet `cloudControlEnabled` voor ieder nieuw Point standaard uit en verander die waarde nooit door cloudselectie. Bied voor normale gebouwbediening een afzonderlijke bewuste opt-in per Point en een expliciet gekozen control-policy voor bulkacties. High-riskcategorieën blijven geblokkeerd totdat een strengere veilige policy bestaat: locks, alarm control, toegangsdeur/garage/gate, scripts, automations, scenes met onbegrensde impact, onbekende buttons, reset/restart/update en EVCC-omzeilende laag-niveaufuncties. Toon bronbewijs, projectie en lokale permissiontoggle afzonderlijk, maar voer niets uit.

Bewaar adapter-/schemaversie en een hash van relevant bronbewijs. Iedere drift in acties, type, grenzen, opties of risico zet `cloudControlEnabled` atomisch uit en `capabilityReviewRequired = true`; meetdataselectie blijft afzonderlijk. Fase 2A bouwt en toont bronbewijs, projectie en lokale permissionconfiguratie; alleen Fase 2D bouwt commandontvangst, finale vertaling en uitvoering.

## Add-on UI

Bouw een professioneel, responsief desktop/tablet commissioningoppervlak zonder herkenbare Home Assistant-dashboardesthetiek.

### Overview

Toon minimaal:

- HA-connection health;
- laatste succesvolle discovery/reconciliation;
- aantallen Structures, Spaces, PhysicalDevices, Assets en Points;
- aantal nieuw/onbeoordeeld, selected, missing, unavailable en controllable;
- lokale databasestatus;
- duidelijke melding “Cloudpairing en datatransport volgen in Fase 2B/2C”.

### Inventory/Ontology

- zoekbare en filterbare boom;
- Structure → Space → Asset → Point;
- aparte zichtbaarheid van PhysicalDevice/source;
- tri-state cloudselectie;
- filters voor nieuw, missing, unavailable, selected, controllable, high-risk en zonder ontologyclass;
- drag/drop alleen waar toegankelijk en betrouwbaar; bied altijd een toetsenbord- en formalternatief;
- loading, empty en error states.

### Inspector

Toon minimaal:

- stable ONE.OS-ID;
- raw HA floor/area/device/entity-ID’s als commissioningmetadata;
- live raw en formatted waarde;
- timestamps en kwaliteit;
- HA-default versus ONE.OS-override;
- displaynaam, unit, decimalen;
- ontologyclass/tags;
- Properties;
- CommandCapability en permissiontoggle;
- source lifecycle;
- resetacties.

### Diagnostics

- connection/reconnectstatus;
- laatste syncresultaat en foutcategorie;
- veilige aantallen, geen volledige gevoelige payloads;
- lokale audit van commissioningmutaties;
- exporteerbare diagnostieksnapshot op basis van een vaste allowlist: schemaversie, softwareversie, architectuur, gehashte Installation ID, database-revision, connectorpresence, sync- en reconnecttimestamps/duur/foutcodes, objectaantallen per lifecycle/quality, opslagtotalen en aantallen audit/outboxrecords. Exporteer nooit raw HA-ID’s, objectnamen, states, attributes, Properties, URL’s, headers, tokens, cookies, certificaten, filesystempaden, stacktraces of vrije fouttekst.
- lokale auditregels bevatten actor user-ID, tijd, actie, stable ONE.OS-object-ID, revisie en gewijzigde veldnamen; diagnostiekexport bevat geen vrije before/after-waarden.

Voldoe aan WCAG AA, toetsenbordbediening, consistente focusstates, light/dark mode en het bestaande ONE.OS design system.

## Publieke API-seams

Ontwerp een kleine versieerbare same-origin commissioning-API. De precieze route-indeling mag aan het bestaande projectpatroon worden aangepast, maar publiek gedrag moet minimaal de volgende use-cases ondersteunen:

- health/connection status;
- inventorytree en filters;
- Pointdetail/live waarde;
- handmatige discovery/reconciliation;
- override create/reset;
- Asset split/merge/move;
- Property en ontology update;
- subtree selection met uitzonderingen;
- control permission toggle;
- Missing replacement/archive;
- diagnostics en auditlijst.

Gebruik optimistic concurrency of versies zodat twee browsermutaties geen stil dataverlies veroorzaken. Geef consistente typed foutresponses en lek geen interne tracebacks.

## Testseams — verplicht

### 1. Fake Home Assistant/Supervisor boundary

Maak fixtures/scenario’s voor:

- Floors, Areas, Devices, Entities en states;
- standalone en ongeplaatste entities;
- Floor zonder Area, Area zonder Floor, Device zonder Entity, disabled/hidden Entity, Entity zonder state, diagnostic/config-Entity, dangling binding en state zonder registryentry;
- Entity-area die afwijkt van Device-area en Device met conflicterende Entity-areas;
- device met meerdere entities;
- één PhysicalDevice dat later in meerdere Assets wordt gesplitst;
- live state events;
- unit/naam/capabilitywijziging;
- registrywijziging tijdens een blijvend gezonde WebSocketverbinding plus periodieke reconciliation als vangnet;
- disconnect/reconnect;
- unavailable versus missing;
- entity replacement;
- entity-ID rename met behoud van Point-ID en delete/recreate van dezelfde entity-ID met nieuwe bronidentiteit;
- duplicated/reordered snapshotdata;
- high-risk controllable entities.
- ontbrekend verplicht ADR-0012-command/veld en tolerant onbekend responseveld;
- canarytokens in names, states, attributes, URL’s, headers en fouttekst om diagnosticsredactie te bewijzen.

### 2. Add-on commissioning API

FastAPI-integratietests verifiëren via publieke routes:

- deterministische idempotente import;
- stable ID’s;
- new/missing/archive/replacement lifecycle;
- Missing parent met actieve descendants, rehome/placement-conflict en niet-stille archivepreview;
- override inheritance en drift;
- compatible/incompatible unitconversie;
- decimalen en nl-BE preview;
- Asset split/merge/move;
- tri-state cascade en uitzonderingen;
- afzonderlijke selectie-intentie/reviewstatus, effective-selectionberekening en transities bij move/split/merge/replacement/new/missing/archive;
- immutable CommandCapabilities;
- immutable bronbewijs, deterministische niet-verruimende capabilityprojectie en deny-by-default bij ambigue brondata;
- high-riskdefault;
- cloudselectie verandert cloudControlEnabled nooit en nieuwe Points starten altijd met control uit;
- capabilitydrift zet control uit en vereist capabilityreview zonder meetdataselectie te wijzigen;
- admin-only UI, reads en mutaties, inclusief non-admin/ontbrekende-header/lookupfout en fail-closed gedrag;
- directe backendtoegang, gespoofte proxyheaders, verkeerde/ontbrekende Origin, cross-site fetch, ontbrekend/ongeldig CSRF-token en ongeautoriseerde WebSocket/SSE-upgrade;
- `incompatible_home_assistant` bij ontbrekend ADR-0012-command of verplicht veld;
- nul pogingen tot HA/Supervisor-mutaties over de volledige suite;
- unieke actieve SourceBindings en transactionele replacement/split/mergeconflicten;
- diagnostiekexport bevat uitsluitend allowlistvelden en geen canarywaarde;
- persistentie na restart.

### 3. Zichtbare UI

Vitest/Testing Library verifieert:

- ontologytree;
- tri-state interactie;
- niet-Simon generieke testdata;
- live update in inspector;
- HA-default en override;
- reset;
- validation errors;
- loading/empty/error;
- missing/high-riskmeldingen;
- toetsenbordflow.

### 4. Browser journey

Maak een afzonderlijke `playwright.phase2a.config.*` zonder import of fallback naar de bestaande live config. De harness start zelf fake HA/Supervisor, add-onbackend en UI op willekeurige loopbackpoorten, een willekeurig Ingress-subpath en tijdelijke `/data`, en zet een verplichte niet-productie-marker. Laat de suite vóór enig request falen bij een RFC1918/live host, ontbrekende fake-marker of extern hostname. Journey:

1. open Overview;
2. start/observeer discovery;
3. open een Point en controleer live waarde;
4. zet displaynaam/decimalenoverride;
5. selecteer een subtree en maak een uitzondering;
6. splits een samengesteld Asset;
7. simuleer een nieuw en een verdwenen HA-object;
8. herstart backend/add-on;
9. verifieer stable ID’s en persistente configuratie.

Tests mogen nooit stil skippen bij ontbrekende verplichte variabelen.

### 5. Persistentierecovery

- verse Alembic-upgrade tot head;
- upgrade vanaf iedere in Fase 2A gemaakte revision;
- restart met bestaande database;
- foreign keys, WAL/busy timeout en relevante constraints;
- herstel na afgebroken reconciliation zonder half toegepaste boommutaties.
- cold backup/restore: stop backend, archiveer uitsluitend backupbare configuratie-/mappingdata, herstel naar een nieuwe tijdelijke `/data`, start opnieuw en verifieer mappings, stable ID’s, overrides, selectie en audit.

## Kwaliteitsgates

Voer minimaal uit en bewaar concrete output:

- Python dependency sync/lock;
- Ruff check en format check;
- volledige pytest-suite;
- Python production dependency audit;
- npm install/lockupdate;
- frontendtests;
- TypeScript typecheck;
- ESLint met nul warnings;
- productiebuild van de add-on-UI en container;
- npm production audit met expliciete beoordeling van resterende findings;
- Playwright Fase-2A journey;
- Home Assistant add-onconfigvalidatie volgens actuele tooling;
- multi-platform build voor `linux/amd64` en `linux/arm64` plus startup-/healthsmoke van beide images via een gecontroleerde CI/QEMU-runner;
- test dat de UI achter een niet-root Ingress-path werkt;
- git diff check;
- staged kandidaatbestandscan op een expliciete allowlist en secrets/artefactscan; gebruik nooit `git add -A`.

Wijzig vanuit deze repository geen bestaande Fase-1-portals, deploymentartefacten of centrale runtimecontracten. Contractwijzigingen voor de centrale applicatie horen later in een afzonderlijke PR in `Simon3tiw/one-os`. Exacte testtotalen alleen rapporteren wanneer werkelijk zichtbaar.

## Documentatie

Werk minimaal bij:

- architectuurdiagram en Fasegrenzen;
- domeinglossary indien tijdens implementatie nieuwe termen worden beslist;
- add-on lokale development- en buildinstructies;
- fake HA/Supervisor scenario’s;
- commissioninghandleiding voor discovery, overrides, selectie, missing/replacement en diagnostics;
- securitygrenzen en expliciete afwezigheid van cloud/servicecalls in Fase 2A;
- upgrade/backup/restore voor de lokale mappingdatabase.
- migratieplan voor de bestaande centrale legacyvelden naar Site/Structure/Space/Asset/Point vóór Fase 2B; Fase 2A mag het bestaande portalcontract niet stil breken.

Maak alleen nieuwe ADR’s voor moeilijk omkeerbare, verrassende trade-offs. Wijzig bestaande geaccepteerde ADR’s niet stilzwijgend.

## Onafhankelijke review en oplevering

Laat vóór commit minimaal twee onafhankelijke reviews uitvoeren:

1. security, Home Assistant add-onstandaarden, secrets, admin-only Ingress en read-onlygrens;
2. master-specconformiteit, datamodel, reconciliation, UX, tests en packaging.

Los blocking/high findings op, herhaal gerichte en volledige gates, bouw een kandidaatadd-onartefact en verifieer het werkelijk. Leg kandidaatdiff, bestand-allowlist, testbewijs en artefactdigest voor en stop voor een expliciet menselijk keuzemoment. Commit en push pas na die goedkeuring. Deploy nooit naar de live Home Assistant op `192.168.1.5` zonder een afzonderlijk expliciet keuzemoment en veilige installatiemethode; vergelijk na een goedgekeurde push lokale en remote SHA.

## Definition of Done

Fase 2A is alleen gereed wanneer:

- add-onpackage en container lokaal gevalideerd en gebouwd zijn;
- admin-only Ingress/fail-closed gedrag aantoonbaar is;
- volledige fake HA-discovery en live updates werken;
- de ADR-0012-compatibiliteitscheck, registry-events en periodieke reconciliation werken;
- alle bronobjecten zichtbaar zijn en stable ONE.OS-ID’s hebben;
- canonical ontology, Assets, Points, SourceBindings en overrides persistent werken;
- live raw/formatted values, units, decimalen en quality correct zichtbaar zijn;
- nieuwe, unavailable en missing lifecycle getest is;
- disabled/hidden/orphan/dangling/area-conflictgevallen en parent-Missing/archivegedrag getest zijn;
- tri-state cloudselectie lokaal volledig werkt maar niets publiceert;
- CommandCapabilities zichtbaar en immutable zijn, zonder servicecalls;
- de testrecorder nul muterende HA/Supervisor-calls rapporteert;
- diagnostiekexport de vaste allowlist en canary-redactietests doorstaat;
- alle vijf publieke testseams en kwaliteitsgates groen zijn;
- amd64 en aarch64 daadwerkelijk gebouwd en gestart zijn en cold backup/restore geslaagd is;
- de Fase-2A Playwright-run aantoonbaar uitsluitend loopback/fakes/tijdelijke data gebruikte;
- geen secrets, databases, runtimecertificaten of buildartefacten staged zijn;
- onafhankelijke rereview geen blockers oplevert;
- documentatie overeenkomt met werkelijk gedrag;
- live HA OS-deployment expliciet nog niet is uitgevoerd of afzonderlijk door de gebruiker is goedgekeurd.

Stop na Fase 2A en leg de concrete resultaten en openstaande Fase-2B-keuzes voor. Implementeer pairing, MQTT, cloudpublicatie of echte bediening niet vooruitlopend.
