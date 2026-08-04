# ONE.OS Home Assistant Edge Connector — master specification

## Status en besluitvorming

Deze specification is de overkoepelende product- en architectuurbasis voor de gefaseerde bouw van de ONE.OS Home Assistant OS add-on en de bijbehorende centrale cloudfuncties. De beslissingen in `CONTEXT.md` en ADR-0001 tot en met ADR-0012 zijn normatief. Waar oudere architectuurdocumentatie nog spreekt over een rigide `Building → Floor → Zone → Equipment`-model, een Home Assistant-token in de centrale backend of een uitsluitend centrale Home Assistant-adapter, vervangen deze specification en ADR’s die passages.

## Problem Statement

Een commerciële ONE.OS-installatie moet alle relevante gebouwdata en gecontroleerde bediening uit een lokale Home Assistant OS-installatie veilig beschikbaar kunnen maken in een centrale multi-tenant ONE.OS-omgeving. Bestaande Home Assistant-mechanismen leveren losse bouwstenen, maar geen complete productverbinding met commissioning, gebouwontology, expliciete cloudselectie, veilige pairing, duurzame offline buffering, command acknowledgements, tenantisolatie en audit.

De installateur configureert het gebouw eerst zorgvuldig in Home Assistant. ONE.OS moet alle Floors, Areas, Devices, Entities, metadata, actuele waarden en technische capabilities lokaal ontdekken en herkenbaar presenteren zonder Home Assistant te wijzigen. De installateur moet de geïmporteerde structuur kunnen verfijnen, weergave-instellingen kunnen overschrijven en op ieder boomniveau kunnen selecteren wat naar de cloud gaat. De cloud mag Home Assistant nooit rechtstreeks benaderen en mag nooit een Home Assistant-token ontvangen.

## Solution

ONE.OS levert een Home Assistant OS add-on met een admin-only Supervisor Ingress-UI. De add-on gebruikt de lokale Home Assistant/Supervisor API om de volledige broninventory en live states te lezen, vertaalt deze deterministisch naar `Site → Structure → Space → Asset → Point`, bewaart bronbindingen en ONE.OS-overrides lokaal, en toont actuele waarden en CommandCapabilities tijdens commissioning.

Na expliciete selectie koppelt de installateur de add-on met een centrale ONE.OS-server via een stabiele Installation ID en een eenmalige pairingcode. HTTPS verzorgt pairing, certificaatlifecycle, volledige snapshots van de geselecteerde cloudprojectie, resynchronisatie en herstel. MQTT 5 over TLS/mTLS verzorgt live telemetry, presence, commands en acknowledgements; MQTT over Secure WebSocket op poort 443 is fallback. De add-on houdt een begrensde persistente SQLite-outbox bij voor maximaal dertig dagen en standaard maximaal twee gigabyte.

Bediening gebruikt nooit vrije Home Assistant-servicecalls vanuit de cloud. Omdat Home Assistant geen universeel capabilityobject levert, bewaart de add-on relevant read-only bronbewijs en projecteert dit deterministisch via een versieerbare adapter naar een nooit ruimere ONE.OS CommandCapability. Deze niet-handmatig-bewerkbare projectie wordt gecombineerd met lokale commissioningtoestemming; pas daarna kan een later gestructureerd ONE.OS-command naar een concrete lokale Home Assistant-servicecall worden vertaald. Hoog-risicocategorieën zijn standaard uitgeschakeld. EVCC blijft bron van waarheid voor laadlogica.

## Canoniek domeinmodel

- **Tenant** — commerciële eigenaar/accountgrens in de centrale ONE.OS-omgeving.
- **Site** — beheerde klantlocatie of campus.
- **Structure** — recursief fysiek of logisch gebouwonderdeel. Een top-level Structure behoort aan precies één Site; een geneste Structure aan precies één parent Structure. Building, Floor, Roof, Facade, Parking, Grounds, Basement en Unassigned zijn types.
- **Space** — gebruiks-, verblijfs- of regelruimte binnen precies één Structure. Room, Zone, Office, Corridor, TechnicalRoom en Unassigned zijn types.
- **PhysicalDevice** — fysiek bronapparaat; kan meerdere Assets realiseren.
- **Asset** — herkenbare gebouwfunctie binnen precies één Space. Equipment, Meter, Sensor, Light, Blind, AirHandlingUnit en EVCharger zijn types.
- **Point** — stabiel ONE.OS-meet-, status-, instel- of stuurpunt van precies één Asset.
- **Property** — getypeerde aanvullende documentatie van een object.
- **SourceBinding** — technische koppeling naar Home Assistant floor-, area-, device- of entity-identiteit; nooit de publieke ONE.OS-identiteit.
- **CommandCapability** — deterministische, versieerbare en niet-verruimende projectie van immutable bewaard Home Assistant-bronbewijs naar technisch ondersteunde acties, opties en grenzen; niet handmatig bewerkbaar.
- **Cloud selection** — afzonderlijke commissioningkeuze die bepaalt welke subtree wordt gepubliceerd.
- **Cloud control permission** — afzonderlijke commissioningkeuze die bepaalt of een gepubliceerde CommandCapability vanuit de cloud mag worden gebruikt.

Het containmentmodel slaat geen niveaus over: `Site → Structure → Space → Asset → Point`. Structures mogen recursief zijn. Bij ontbrekende Home Assistant-plaatsing maakt de import zichtbare synthetische `Unassigned`-Structures en -Spaces in plaats van Assets of Points rechtstreeks hoger in de boom te hangen. PhysicalDevice is geen containmentniveau maar een afzonderlijke bronrepresentatie met relaties naar één of meer Assets.

De eerste semantische laag is Brick-compatible via ontologyclass-URI’s en tags. Volledige RDF-opslag of reasoning is geen vereiste voor de eerste release. RealEstateCore blijft een mogelijke interoperabiliteitslaag.

## Deterministische Home Assistant-import

- De lokale inventory omvat alle actieve Floor-, Area-, Device- en Entity-registryentries plus alle actuele states. Ook disabled/hidden Entities, Entities zonder state, Devices zonder Entity, diagnostic/config-Entities en dangling registryverwijzingen blijven lokaal zichtbaar; zij starten onbeoordeeld, ongeselecteerd en zonder cloudbediening.
- Iedere Home Assistant Floor wordt een Structure van type Floor, ook wanneer zij nog geen Areas bevat.
- Iedere Home Assistant Area wordt een Space onder de bijbehorende Floor-Structure. Zonder geldige Floor-binding komt zij onder de synthetische Unassigned Structure en krijgt zij zo nodig een placement-conflict.
- Ieder Home Assistant Device wordt één PhysicalDevice en krijgt initieel één voorlopig gelijknamig Asset, ook zonder Entities. De Device-area bepaalt de Asset-Space. Zonder Device-area wordt alleen een unanieme Entity-area gebruikt; bij meerdere of dangling Entity-areas komt het Asset in Unassigned met een placement-conflict.
- Iedere aan een Device gekoppelde Entity wordt een Point onder het voorlopige Asset. Een Entity-area die afwijkt van de Device-area verplaatst het Point niet buiten zijn Asset, maar markeert een placement-conflict en stelt een expliciete Asset-split voor.
- Een standalone Entity krijgt een eigen voorlopig Asset en Point in zijn Entity-area-Space of, zonder geldige plaatsing, in de synthetische Unassigned Space.
- Een state zonder Entity-registryentry krijgt een tijdelijke lokale SourceBinding op basis van de actuele state-identiteit, blijft onbeoordeeld en niet-cloudselecteerbaar totdat een stabielere registrybinding beschikbaar is of een installateur de uitzondering expliciet accepteert.
- Alle Home Assistant-objecten blijven zichtbaar in de lokale add-oninventory, ongeacht cloudselectie.
- Nieuwe bronobjecten worden automatisch met dezelfde defaults toegevoegd en blijven aanvankelijk ongeselecteerd voor cloudpublicatie.
- Assets kunnen handmatig worden gesplitst, samengevoegd, hernoemd, verplaatst en geclassificeerd zonder de PhysicalDevice- of SourceBindings te verliezen.
- Bronmetadata blijft synchroniseren zolang voor het specifieke veld geen ONE.OS-override bestaat.
- ONE.OS-overrides worden nooit teruggeschreven naar Home Assistant.
- SourceBindings gebruiken per registrytype de meest stabiele beschikbare bronidentiteit. Voor een Entity is de huidige `entity_id` alleen mutabele metadata; de binding gebruikt waar beschikbaar de combinatie van integration/platform, `unique_id` en config-entrycontext. Een entity rename behoudt daardoor het Point. Delete/recreate met dezelfde `entity_id` maar andere stabiele bronidentiteit maakt een nieuw Point en laat het oude Point Missing totdat expliciete replacement plaatsvindt.
- Een verdwenen bronobject wordt `Missing`, blokkeert bediening en blijft bewaard totdat een installateur het vervangt of archiveert.
- Status wordt niet in één enum samengeperst: `sourceLifecycle` is `active | missing | archived`, `reviewStatus` is `unreviewed | reviewed`, `valueQuality` is minimaal `good | stale | invalid | unknown | unavailable`, en `connectorPresence` is `online | reconnecting | offline`.
- Een tijdelijke disconnect verandert geen `sourceLifecycle`. Na de stale-drempel verandert alleen `valueQuality`; pas een succesvolle autoritatieve reconciliation waarin een eerder gebonden bron ontbreekt maakt die binding `missing`.
- Reappearance van dezelfde stabiele registrybinding herstelt `missing → active`; archivering is een expliciete installateuractie.
- `missing` en `archived` blokkeren bediening. Een geselecteerd Missing object publiceert alleen lifecycle/data-gapcontext en geen nieuwe meetwaarde; Archived wordt niet meer gepubliceerd. Connector offline behoudt de laatste waarde en lifecycle maar maakt presence en stale toestand zichtbaar.
- Een ontbrekende parent maakt actieve descendants niet automatisch Missing. Bij geërfde bronplaatsing worden actieve descendants transactioneel naar de passende synthetische Unassigned-container verplaatst; bij een bewuste ONE.OS-plaatsing ontstaat een placement-conflict en wordt effectieve bediening geblokkeerd totdat de installateur dit oplost.
- Replacement is per gelijk bronobjecttype toegestaan wanneer het doel nog geen actieve SourceBinding heeft. Alleen een expliciet bevestigde semantische replacement behoudt het ONE.OS-ID; anders ontstaat een nieuw object en blijft het oude Missing.
- Archivering van Structure, Space of Asset met actieve descendants vereist een preview en expliciete keuze om descendants eerst te verplaatsen of gecontroleerd mee te archiveren; er bestaat geen stille cascade-delete. Overrides, selectiehistoriek en audit blijven bewaard.

## Pointwaarden en presentatie

Ieder Point bewaart conceptueel drie gescheiden lagen:

1. de ongewijzigde bronstate en bronmetadata;
2. de genormaliseerde typed waarde, canonieke unit en kwaliteit;
3. de presentatieconfiguratie, waaronder displaynaam, displayunit en decimalen.

Defaults komen uit Home Assistant: friendly name, actuele state, unit of measurement, device class, state class, beschikbare precision, min/max/step, enumopties en ondersteunde features. Een displayoverride wijzigt de bronwaarde niet. Een unitwijziging vereist een echte compatibele conversie; alleen het label veranderen is verboden. Precision is presentatie en impliceert geen sensoraccuracy. Iedere override kan per veld worden teruggezet naar “Gebruik Home Assistant-standaard”. Brondrift wordt zichtbaar gemaakt en overschrijft een bewuste override niet.

## Cloudselectie

- Discovery is volledig lokaal; publicatie is expliciet.
- Standaard wordt niets gepubliceerd.
- Ieder Point bewaart afzonderlijk `selectionIntent = include | exclude | unset` en `reviewStatus = unreviewed | reviewed`. Effectieve publicatie vereist `include`, `reviewed` en een actieve bron; Structure-, Space- en Assetstatus zijn berekende tri-state aggregaties en geen blijvende impliciete inheritance-policy.
- Selecteren of uitsluiten op Structure-, Space- of Assetniveau is één geaudite bulkmutatie over de op dat moment bestaande descendant Points; individuele Pointuitzonderingen blijven mogelijk.
- De UI gebruikt tri-state checkboxes voor volledige, gedeeltelijke en geen selectie.
- Voor een geselecteerd Point worden de noodzakelijke bovenliggende Structures, Spaces en Assetmetadata automatisch meegestuurd.
- Een nieuw Home Assistant-object krijgt `selectionIntent = unset` en `reviewStatus = unreviewed` en erft nooit stilzwijgend een eerdere bulkkeuze van zijn parent. Een includeactie op een onbeoordeeld Point vereist een expliciete gecombineerde review-en-selectiebevestiging.
- Move, split en merge behouden selectie-intentie/reviewstatus maar herberekenen parentaggregaties. Missing bewaart beide voor audit maar publiceert geen meetwaarde; Archived is effectief uit. Replacement behoudt intentie maar zet reviewstatus terug op `unreviewed`, zodat publicatie geblokkeerd blijft tot nieuwe review.
- Niet-geselecteerde objecten verlaten de add-on niet.

## CommandCapabilities en bediening

- De add-on detecteert technische bedienbaarheid uit Home Assistant-domeinmetadata, supported features, selectors en relevante attributen.
- Relevant HA-bronbewijs wordt read-only bewaard; een versieerbare adapter maakt een deterministische CommandCapability-projectie die nooit breder mag zijn dan dat bewijs en niet handmatig gewijzigd kan worden.
- Onbekende, tegenstrijdige of onvoldoende onderbouwde brondata resulteert in `technicallyControllable = false` en vereist later adapterondersteuning, niet een handmatige capability-editor.
- `technicallyControllable` wordt automatisch afgeleid, maar `cloudControlEnabled` staat voor ieder nieuw Point standaard uit en wordt nooit impliciet door cloudselectie aangezet.
- De installateur kan normale gebouwbediening later bewust per Point of via een expliciet gekozen control-policy activeren; statuspublicatie blijft een volledig afzonderlijke keuze.
- Hoog-risico wordt wel ontdekt maar blijft geblokkeerd totdat een strengere veilige policy bestaat: locks, alarm control, toegangsdeuren/garage/gates, generieke scripts en automations, onbekende buttons, reset/restart/update en laag-niveauacties die EVCC kunnen omzeilen.
- De cloud verstuurt uitsluitend genormaliseerde capabilities en commands, nooit vrije `domain`, `service` of raw entity-ID’s.
- Commands bevatten minimaal command-ID, installation/site-binding, target Point-ID, capability, typed value, issued-at, expires-at/TTL en idempotencykey.
- De add-on controleert pairingstatus, topicidentity, Pointmapping, selection, cloud control permission, capability, type, grenzen, TTL en duplicate status vóór lokale uitvoering.
- De adapter bewaart schema-/adapterversie en een hash van relevant bronbewijs. Iedere inhoudelijke drift in acties, types, grenzen, opties of risico zet `cloudControlEnabled` atomisch uit en `capabilityReviewRequired = true`; bediening kan pas na nieuwe expliciete capabilityreview worden geactiveerd, terwijl reeds goedgekeurde meetdatapublicatie onafhankelijk kan doorgaan.
- Een MQTT- of protocolack is niet gelijk aan succesvolle fysieke uitvoering. Commandstatus onderscheidt minimaal received, rejected, executing, Home Assistant accepted, observed, failed en expired.
- Impactvolle acties vereisen centrale rolcontrole en bevestiging; de add-on blijft de finale lokale policy-enforcer.

## Pairing en device identity

- De installateur configureert de centrale HTTPS-server-URL in de add-on.
- De add-on genereert lokaal een stabiele Installation ID, een asymmetrisch keypair en een cryptografisch willekeurige eenmalige code van minimaal twaalf goed onderscheidbare tekens met korte TTL.
- De private key verlaat de add-on nooit.
- De add-on toont een kortlevende eenmalige pairingcode en de kopieerbare Installation ID.
- In ONE.OS Operations koppelt een platformbeheerder/installateur beide aan een Tenant en Site.
- De edge valideert het HTTPS-servercertificaat via normale PKI of een afzonderlijk bevestigde private trustbootstrap, registreert alleen zijn public key en bewijst bezit van de private key door een serverchallenge te ondertekenen.
- De server bewaart codes gehasht, rate-limit claims en voert iedere claim atomisch exact eenmaal uit; pas na geldige claim en proof-of-possession ontvangt de add-on een afzonderlijke intrekbare devicecredential/clientcertificaat.
- De UI toont daarna alleen identiteit, gekoppelde Tenant/Site, serverfingerprint, certificaatstatus en acties voor intrekken/opnieuw pairen.
- Een herbruikbaar ONE.OS-gebruikerswachtwoord of kopieerbaar permanent secret wordt niet in de add-on opgeslagen.

## Transport en betrouwbaarheid

- HTTPS: pairing, trust bootstrap, certificaatrotatie, volledige snapshots van uitsluitend de geselecteerde cloudprojectie, resync en herstel. Niet-geselecteerde inventory of raw HA-metadata verlaat de add-on nooit.
- MQTT 5 over TLS/mTLS: telemetry, quality, presence, configversiemeldingen, commands en command acknowledgements.
- MQTT over WSS op 443: fallback voor netwerken die native MQTT blokkeren.
- Iedere installatie krijgt alleen toegang tot de eigen versiegebonden topicnamespace.
- Iedere telemetryenvelop bevat minimaal `schemaVersion`, `installationId`, `siteId`, `pointId`, `bootId`, een binnen `(installationId, bootId)` strikt oplopende sequence, `messageId`, `observedAt`, `receivedAt`, `emittedAt`, `configVersion`, typed value, unit, valueQuality en sourceLifecycle. Unsupported schema’s worden expliciet geweigerd.
- QoS 1 wordt gecombineerd met message-ID’s, sequence numbers, applicatieacknowledgements en idempotency. Dedupe bewaart message-ID’s minimaal gedurende de maximale offlineperiode plus verwerkingsmarge; wall-clocktimestamps alleen bepalen nooit ordering.
- Na reconnect publiceert HTTPS eerst een geselecteerde snapshot met `snapshotId` en per boot/stream een capture-watermark. Records tot en met die watermark zijn alleen backfill/history en mogen de snapshot-current-state niet overschrijven; latere records worden in sequencevolgorde toegepast. Een nieuwe `bootId` voorkomt ambiguïteit na reboot of sequencereset.
- Uitvoerbare commands zijn nooit retained.
- De add-on opent uitsluitend outbound verbindingen; er is geen inbound poort naar Home Assistant of de add-on.
- Niet-bevestigde geselecteerde telemetry gaat eerst naar een afzonderlijke persistente SQLite-outbox; commissioningconfiguratie/mappings en audit staan fysiek gescheiden zodat de grote outbox volgens de actuele Home Assistant add-onbackupregels kan worden uitgesloten.
- Dertig dagen is een maximum, geen leveringsgarantie. De outbox heeft een harde applicatiequota van standaard twee gigabyte én bewaakt een gereserveerde vrije filesystemruimte; de kleinste grens wint.
- Binnen de effectieve twee-gigabytegrens geldt maximaal 1,6 GiB telemetry, 300 MiB commandstatus en 100 MiB gereserveerde gap/controlrecords; de connector bewaart daarnaast minimaal 256 MiB of tien procent van het volume—welke reserve groter is—als vrije filesystemruimte. Telemetry wordt als eerste gecompacteerd. Commandstatus blijft tot cloudbevestiging of maximaal dertig dagen; gaps maximaal 180 dagen. Wanneer commandstatus niet duurzaam kan worden toegelaten, wordt een nieuw cloudcommand vóór uitvoering geweigerd. De lokale auditdatabase heeft een eigen harde quota van 250 MiB en retentie van 180 dagen; als een vereist auditrecord niet atomisch past, wordt de bijbehorende commissioningmutatie of commanduitvoering geweigerd.
- Bij quota-, transactionele insert- of disk-fullproblemen wordt geen ongedocumenteerde best-effortwrite gedaan. De connector blijft lokaal read-only functioneren, rapporteert degraded storage health en verlengt per getroffen stream één gededupliceerd contiguous `data_gap`-bereik uit de gereserveerde controlruimte.
- SQLite gebruikt begrensde WAL, expliciete checkpoints en gecontroleerde incremental vacuum/compaction. Na limietverlies of restore zonder outbox volgt een geselecteerde snapshot/reconciliatie volgens de watermarkregels.
- Verlopen commands worden nooit later uitgevoerd.

## Add-on UX

De add-on-UI is een professionele desktop/tablet commissioninginterface via Supervisor Ingress en bevat ten minste:

1. **Overview** — Home Assistant-verbinding, discoverystatus, inventoryaantallen, geselecteerde aantallen, missing/unavailable, cloudstatus en outboxstatus.
2. **Inventory/Ontology** — zoekbare hiërarchische boom `Structure → Space → Asset → Point`, filters, tri-state selectie, nieuwe/onbeoordeelde items en drag/move/split/merge commissioningacties.
3. **Inspector** — bronidentiteit, live raw en formatted waarde, timestamps, kwaliteit, HA-defaults, overrides, ontologyclass/tags, Properties, SourceBindings, CommandCapability en cloud control permission.
4. **Pairing** — server-URL, Installation ID, eenmalige code, serverfingerprint, Tenant/Site en certificate status.
5. **Sync & Buffer** — laatste snapshots, sequence, pending records, ouderdom, opslaggebruik, datagaps en handmatige resync.
6. **Diagnostics & Audit** — veilige status, reconnectgeschiedenis en configuratiemutaties zonder secrets of gevoelige payloads.

Fase 2A implementeert alleen de lokale onderdelen van Overview, Inventory/Ontology, Inspector en lokale Diagnostics. Pairing en transport volgen in latere fases.

## User Stories

1. Als Home Assistant-beheerder wil ik de add-on via Supervisor Ingress openen, zodat geen aparte login of beheerpoort nodig is.
2. Als installateur wil ik alle Home Assistant Floors zien, zodat de gebouwstructuur volledig wordt overgenomen.
3. Als installateur wil ik alle Areas zien onder hun Floor, zodat ruimtes standaard correct geordend zijn.
4. Als installateur wil ik alle Devices en Entities zien, zodat geen brondata stil wordt overgeslagen.
5. Als installateur wil ik actuele waarden direct in de add-on zien, zodat ik mappings tijdens commissioning kan valideren.
6. Als installateur wil ik bronunit, formatted waarde en kwaliteit naast elkaar zien, zodat verkeerde metadata zichtbaar wordt.
7. Als installateur wil ik HA-naam, unit en precision als defaults gebruiken, zodat een goed ingerichte HA-installatie direct bruikbaar is.
8. Als installateur wil ik displaynaam, displayunit en decimalen in ONE.OS kunnen overschrijven, zodat de commerciële presentatie klopt.
9. Als installateur wil ik een override per veld naar HA-default herstellen, zodat ik zonder dataverlies kan terugkeren.
10. Als installateur wil ik dat ONE.OS-overrides Home Assistant nooit wijzigen, zodat de broninstallatie onafhankelijk blijft.
11. Als installateur wil ik één voorlopig Asset per HA Device, zodat de eerste import voorspelbaar is.
12. Als installateur wil ik standalone Entities als voorlopig Asset en Point zien, zodat ook helpers en berekende sensoren beschikbaar zijn.
13. Als installateur wil ik Assets splitsen en samenvoegen, zodat samengestelde fysieke apparaten als correcte gebouwfuncties kunnen worden gemodelleerd.
14. Als installateur wil ik Assets naar een andere Space verplaatsen, zodat onvolledige HA-plaatsing kan worden verfijnd.
15. Als installateur wil ik Brick-compatible ontologyclasses en tags toekennen, zodat data semantisch interoperabel wordt.
16. Als installateur wil ik Properties met typed waarden toevoegen, zodat onderhouds- en assetmetadata kan worden vastgelegd.
17. Als installateur wil ik cloudpublicatie op ieder boomniveau selecteren, zodat grote subtrees snel configureerbaar zijn.
18. Als installateur wil ik individuele kinderen van een geselecteerde subtree uitsluiten, zodat alleen gewenste data vertrekt.
19. Als securityverantwoordelijke wil ik dat standaard niets naar de cloud gaat, zodat publicatie altijd een bewuste commissioningactie is.
20. Als installateur wil ik nieuwe HA-objecten automatisch als onbeoordeeld zien, zodat latere uitbreidingen niet worden gemist.
21. Als operator wil ik een verdwenen entity als Missing zien, zodat een oud Point niet vals gezond lijkt.
22. Als installateur wil ik een Missing Point aan een vervangende entity koppelen, zodat historiek en ONE.OS-identiteit behouden blijven.
23. Als installateur wil ik een Missing object archiveren, zodat de actieve inventory overzichtelijk blijft zonder auditverlies.
24. Als installateur wil ik alle HA CommandCapabilities zien, zodat duidelijk is wat technisch bedienbaar is.
25. Als installateur wil ik normale cloudbediening afzonderlijk en bewust kunnen activeren, zodat datapublicatie nooit automatisch bediening vrijgeeft.
26. Als securityverantwoordelijke wil ik dat high-risk capabilities standaard uitstaan, zodat kritieke bediening niet automatisch wordt blootgesteld.
27. Als platformbeheerder wil ik een installatie met een kortlevende pairingcode claimen, zodat geen permanent gedeeld secret nodig is.
28. Als sitebeheerder wil ik een verloren of gecompromitteerde connector intrekken, zodat zijn cloudtoegang onmiddellijk stopt.
29. Als operator wil ik realtime telemetry zien, zodat de cloud de actuele gebouwstatus kent.
30. Als operator wil ik expliciete quality en timestamps zien, zodat stale of ongeldige data niet als actueel wordt geïnterpreteerd.
31. Als sitebeheerder wil ik maximaal dertig dagen offline telemetry kunnen bufferen, zodat tijdelijke internetuitval geen dataverlies veroorzaakt.
32. Als sitebeheerder wil ik storagegebruik en outboxouderdom zien, zodat een bufferprobleem tijdig zichtbaar wordt.
33. Als operator wil ik een data-gapmelding zien, zodat ontbrekende historie niet verborgen blijft.
34. Als operator wil ik cloudcommands met duidelijke status volgen, zodat ontvangst niet wordt verward met fysieke uitvoering.
35. Als securityverantwoordelijke wil ik dat verlopen of dubbele commands worden geweigerd, zodat reconnect geen oude actie uitvoert.
36. Als auditor wil ik pairing-, configuratie- en commandmutaties kunnen reconstrueren zonder secrets in logs.
37. Als EVCC-beheerder wil ik dat ONE.OS de EVCC-laadlogica niet omzeilt, zodat de lokale optimalisatie bron van waarheid blijft.
38. Als productbeheerder wil ik amd64- en aarch64-add-onimages, zodat gangbare Home Assistant OS-hardware wordt ondersteund.
39. Als beheerder wil ik backup en restore van mapping/configuratie, zodat een HA-migratie de commissioning niet vernietigt.
40. Als ontwikkelaar wil ik fake HA/Supervisor-testgrenzen, zodat CI nooit een live HA-token of echte apparatuur nodig heeft.

## Implementation Decisions

- De add-on leeft in de afzonderlijke private repository `Simon3tiw/one-os-home-assistant-addon`; centrale portal/backendwijzigingen blijven in `Simon3tiw/one-os`.
- De repositories delen geen source tree of secrets. Interoperabiliteit loopt via expliciet versieerbare JSON Schema/OpenAPI-contracten en gecontroleerde contracttests; design tokens mogen als versieerbaar artefact worden gekopieerd zonder een runtime-afhankelijkheid op de centrale monorepo.
- Add-onbackend: Python 3.13, FastAPI, SQLAlchemy, Alembic en asyncio.
- Add-onfrontend: React, TypeScript, Vite, TanStack Query en het gedeelde ONE.OS-design system.
- Add-onpersistentie: SQLite onder de persistente add-ondata; runtime- en secretbestanden worden nooit gecommit.
- Packaging ondersteunt minimaal amd64 en aarch64 en volgt de actuele officiële Home Assistant add-onstandaard.
- De add-on gebruikt Supervisor Ingress en het in ADR-0012 begrensde source-verified Core WebSocket-contract; minimaal Home Assistant `2025.1.0` wordt in packaging afgedwongen. De browser ziet nooit Supervisor- of Home Assistant-tokens.
- Alleen HA-administrators mogen de commissioning-UI of gevoelige read- en mutatie-API’s gebruiken. `panel_admin: true` beperkt de zichtbare panelentry maar is niet de autorisatiegrens: de add-on accepteert alleen verkeer van de gedocumenteerde Supervisor Ingress-proxy, vereist de niet-spoofbare door Supervisor geïnjecteerde remote user-ID en verifieert die server-side via Home Assistant als actieve gebruiker met `system-admin`-groepslidmaatschap. Ontbrekende identity of lookupfouten falen gesloten; het Supervisor-token blijft uitsluitend backend-side. Alleen een minimale payloadvrije containerhealthcheck mag hiervan worden uitgezonderd.
- Mutaties vereisen JSON, een exact toegestane same-origin `Origin`, `Sec-Fetch-Site: same-origin` en een kortlevend per gebruiker uitgegeven CSRF-token in een custom header. WebSocket/SSE-upgrades valideren bronproxy, Origin en actuele adminstatus opnieuw; directe backendtoegang, wildcard-CORS en cross-origin credentials zijn verboden.
- De lokale database bevat precies één bootstrap-Site per Installation ID. Een actieve SourceBinding is uniek op `(sourceSystem, registryKind, registryId)` en kan nooit tegelijk aan twee ONE.OS-objecten hangen. Replacement beëindigt de oude actieve binding en maakt de nieuwe atomisch; transfer, split en merge weigeren conflicten en bewaren audit en stable Point-ID’s.
- Add-on en centrale backend delen versieerbare domein- en protocolschema’s, maar delen geen secrets.
- Stable ONE.OS-ID’s worden bij import gegenereerd en veranderen niet wanneer een SourceBinding verandert.
- Synchronisatie is reconciliation, niet destructieve mirror: create/update/missing/archive zijn expliciete states.
- Operations Portal blijft het centrale beheeroppervlak voor Tenant/Site-pairing; de add-on beheert lokale discovery, mapping en publicatiekeuze.
- De cloud bewaart geen raw HA-credential en exposeert geen raw HA-servicecallinterface.
- Alle units zijn expliciet; numerieke API-waarden blijven nummers en formatting gebeurt deterministisch met Belgische `nl-BE`-presentatie.
- Fase 2A voert geen echte servicecalls, pairing of cloudpublicatie uit.

## Compatibiliteit en centrale contractmigratie

- Fase 2A introduceert nieuwe versieerbare edge-/commissioningschema’s naast het bestaande Fase-1 `BuildingRuntime`; zij vervangt of breekt het portalcontract niet stilzwijgend.
- Legacyvelden `buildingId`, `zoneId` en `equipmentId` blijven uitsluitend in een duidelijk deprecated Fase-1-compatibilityadapter. `sourceEntityId` mag nooit in een nieuw publiek of cloudschema voorkomen en `writable` wordt vervangen door afzonderlijke capability- en permissionvelden.
- Vóór eerste cloudsync in Fase 2B krijgen centrale database en `/api/v1` een expliciete Alembic/API-migratie naar Site, Structure, Space, Asset en Point, met backfill, tijdelijke versioned readcompatibiliteit en contracttests die raw HA-identiteit in responses en berichten verbieden.
- Alleen de edge vertaalt een genormaliseerd command naar Home Assistant. De centrale backend kent geen raw entity-ID, domein/servicepaar of Home Assistant-credential.

## Testing Decisions

Tests verifiëren publiek waarneembaar gedrag aan zo weinig mogelijk seams en vermijden implementatiedetailtests.

1. **Fake Home Assistant/Supervisor boundary:** een deterministische fake implementeert exact de geallowliste ADR-0012-commands en levert de volledige inventorymatrix, registry-events, actuele states, state_changed-events, capabilitywijzigingen, reconnects en verdwenen bronnen. Een periodieke volledige reconciliation blijft verplicht als vangnet.
2. **Add-on commissioning API:** FastAPI-integratietests verifiëren discovery, reconciliation, stable ID’s, overrides, unitvalidatie, cascade-selectie, live kwaliteit en lifecycle via publieke routes.
3. **Zichtbare add-on-UI:** Vitest/Testing Library verifieert ontologyboom, tri-state selectie, Point inspector, HA-defaults, formattingpreview, live updates, loading, empty, error en statusweergave.
4. **Browser journey:** Playwright draait op een Ingress-achtige base path en verifieert eerste startup, discovery, Pointinspectie, override, cascade-selectie en persistentie na restart.
5. **Persistentierecovery:** echte Alembic-upgrade op een lege database en restart tegen bestaande SQLite-data; geen opslagmock als primaire regressiegrens.

Aanvullend per fase: Ruff, formatting, pytest, dependency-audit, TypeScript typecheck, ESLint, frontendtests, productiebuild, Playwright, add-onconfigvalidatie, multi-platform build en startup-smoke voor amd64 én aarch64, secrets/artefactscan en—vanaf Fase 2A—cold backup/restore van de mappingdatabase. Fase 2E voegt de echte Supervisorinstallatie-, upgrade- en backup/restoreproef toe.

## Delivery Phases

### Fase 2A — Add-on en lokale commissioning

Bouw add-on packaging, admin-only Ingress, de gepinde read-only ADR-0012-adapter, local inventory/periodieke reconciliation, canonical ontology, live values, formatting en overrides, cloudselectionconfiguratie, missing lifecycle, lokale diagnostics en alle vijf testseams. Geen cloudverkeer en geen servicecalls.

### Fase 2B — Pairing en inventorysync

Bouw centrale installationregistratie, Tenant/Site-claim, Installation ID, eenmalige pairingcode, lokale keygeneratie, certificate lifecycle, Operations Portal-flow en HTTPS inventory/configuratiesnapshot met intrekken en opnieuw pairen.

### Fase 2C — Telemetry en offlinewerking

Bouw MQTT 5/mTLS, WSS-fallback, versieerbare telemetryenvelopes, topic-ACL’s, presence, SQLite-outbox, acknowledgements, dertig dagen/twee gigabyte beleid, reconnect, gaps en HTTPS-resync.

### Fase 2D — Gecontroleerde bediening

Bouw centrale rollen/bevestiging, commandmodel, add-on policy enforcement, immutable HA CommandCapabilities, high-riskdefaults, idempotency/TTL, lokale servicecallvertaling, commandstatus, observed-state acknowledgement, audit en EVCC-grens.

### Fase 2E — Productieoplevering

Bouw multi-archrelease, add-onrepositorymetadata, signing/provenance waar haalbaar, echte HA OS-installatie- en upgradetest, backup/restore, rollback, volledige securityreview, end-to-end liveproef en operationeel runbook.

Iedere fase eindigt met expliciete review, testbewijs, deploymentbewijs waar van toepassing en een menselijk keuzemoment vóór de volgende fase.

## Out of Scope

- Home Assistant publiek ontsluiten of in een ONE.OS-iframe tonen.
- Home Assistant-tokens naar browser of cloud sturen.
- HA-metadata of configuratie vanuit ONE.OS terugschrijven.
- Vrije cloudgestuurde `call_service`-requests.
- Volledige RDF-triplestore of semantic reasoning in de eerste release.
- Automatische AI-groepering zonder installateurbevestiging.
- EVCC vervangen als laadcontroller.
- Nieuwe veldbusimplementaties voor BACnet, Modbus of KNX binnen Fase 2A–2D; deze volgen later achter dezelfde Point/SourceBinding-grens.
- De bestaande EMS-app wijzigen.

## Further Notes

- De add-on-UI is een commissioningproduct, niet het Customer Portal.
- Raw HA-ID’s zijn lokaal zichtbaar voor installateurs maar geen publiek cloudcontract.
- Mock/fake-data moet overal zichtbaar als testdata zijn gemarkeerd.
- Secrets, databases, runtimecertificaten, logs en screenshots met pairingcodes zijn uitgesloten van Git.
- Het bestaande onderzoeksdocument over HA-cloudconnectoropties is de bron voor de transportkeuze.
