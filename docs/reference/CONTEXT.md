# ONE.OS projectcontext

## Domeintaal

Gebruik in code, tests en productteksten consequent: Tenant, Site, Structure, Space, Asset, PhysicalDevice, Point, Property, Alarm, Command, CommandCapability, EdgeDevice, Integration en SourceBinding.

Een **Site** is één beheerde klantlocatie of campus en bevat één of meer Structures.

Een **Structure** is een fysiek of logisch gebouwonderdeel en kan andere Structures bevatten. Building, Floor, Roof, Facade, Grounds, Parking en Basement zijn Structure-types. Een top-level Structure behoort aan precies één Site; een geneste Structure aan precies één parent Structure.

Een **Space** is een gebruiks-, verblijfs- of regelruimte binnen precies één Structure. Room, Zone, Office, Corridor, TechnicalRoom en Unassigned zijn Space-types.

Een **Asset** is een herkenbare gebouwfunctie binnen precies één Space. Equipment, Meter, Sensor, Light, Blind, AirHandlingUnit en EVCharger zijn Asset-types.

Een **PhysicalDevice** is het fysieke bronapparaat. Eén PhysicalDevice kan meerdere Assets realiseren en is daarom niet hetzelfde als een Asset.

Een **Point** is een stabiel ONE.OS-meet-, status-, instel- of stuurpunt van precies één Asset.

Een **CommandCapability** is de versieerbare, deterministische en nooit-verruimende ONE.OS-projectie van immutable bewaard bronbewijs over technisch ondersteunde acties en grenzen voor een Point. De projectie is niet handmatig bewerkbaar; toestemming om haar vanuit de cloud te gebruiken is een afzonderlijke commissioningkeuze.

Een **Property** is getypeerde aanvullende metadata waarmee een Site, Structure, Space, Asset of Point wordt gedocumenteerd.

Een **SourceBinding** koppelt een stabiel ONE.OS-object aan zijn technische bron. Een Home Assistant-entity-ID, device-ID, area-ID of floor-ID is uitsluitend bronmetadata in deze adapter- en commissioninglaag en nooit de publieke identiteit van een ONE.OS-object.

## Testseams

### Centrale Fase-1-applicatie

De overeengekomen publieke testgrenzen voor de bestaande Customer en Operations Portals zijn:

1. FastAPI HTTP-routes voor health, auth en runtime.
2. Het kleine `BuildingRuntime`-contract.
3. Zichtbaar gedrag van gedeelde UI- en portalcomponenten.
4. Browser-E2E voor login, portaalnavigatie, thema en logout.

### Home Assistant Edge Connector

De afzonderlijke publieke testgrenzen voor Fase 2A zijn:

1. De gesloten fake/real Home Assistant- en Supervisor-adapter.
2. De versieerbare same-origin commissioning-API.
3. Zichtbaar gedrag van de add-on-UI.
4. Een volledig geïsoleerde browserjourney achter een willekeurig Ingress-subpath.
5. Echte SQLite/Alembic-persistentierecovery en cold backup/restore.

Tests verifiëren gedrag aan deze grenzen en niet de interne implementatie. Centrale en edge-seams worden niet samengevoegd; iedere fase draait daarnaast alle bestaande regressiegates.

## Fase 1

Fase 1 gebruikt uitsluitend `MockBuildingRuntime`. Er wordt nog geen Home Assistant-token verwerkt en er worden geen servicecalls uitgevoerd.
