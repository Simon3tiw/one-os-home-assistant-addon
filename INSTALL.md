# ONE.OS Edge Connector — handmatige installatie

Deze repository is **privé**. Home Assistant Supervisor kan een private
GitHub-repository doorgaans niet zonder credentials als custom
add-onrepository clonen. Gebruik daarom de handmatig geïnstalleerde
bundel hieronder.

## 1. Bundel bouwen

Op een machine met deze repository (lokaal of via een groene CI-run):

```bash
./scripts/build-release-bundle.sh "$PWD/dist-bundle"
```

Dit levert:

- `dist-bundle/one-os-edge-addon-bundle.tar.gz`
- `dist-bundle/one-os-edge-addon-bundle.tar.gz.sha256`

Verifieer de checksum vóór installatie:

```bash
cd dist-bundle
sha256sum -c one-os-edge-addon-bundle.tar.gz.sha256
```

De GitHub Actions-workflow (`release-bundle`-job in `.github/workflows/ci.yml`)
bouwt dezelfde bundel automatisch bij elke groene run op `main` en
`feat/**`-branches, en publiceert die als downloadbaar workflow-artefact.

## 2. Bundel uitpakken op de Home Assistant-host

Home Assistant OS/Supervised leest lokale apps/add-ons uit de map
`/addons` (of het geconfigureerde `addons`-pad in `share`). Gebruik voor zowel
een eerste installatie als een update de checksummed bundle zelf als de
overdrachtseenheid:

```bash
set -euo pipefail
bundle=dist-bundle/one-os-edge-addon-bundle.tar.gz
checksum=dist-bundle/one-os-edge-addon-bundle.tar.gz.sha256
(cd dist-bundle && sha256sum -c one-os-edge-addon-bundle.tar.gz.sha256)

ssh root@homeassistant.local 'set -eu
transfer=/addons/.one_os_edge.v042.transfer
new=/addons/.one_os_edge.v042.new
test ! -e "$transfer"
test ! -e "$new"
install -d -m 0700 "$transfer"'

scp "$bundle" "$checksum" \
  root@homeassistant.local:/addons/.one_os_edge.v042.transfer/

ssh root@homeassistant.local 'set -eu
transfer=/addons/.one_os_edge.v042.transfer
new=/addons/.one_os_edge.v042.new
cd "$transfer"
sha256sum -c one-os-edge-addon-bundle.tar.gz.sha256
tar -xzf one-os-edge-addon-bundle.tar.gz -C "$transfer"
test -f "$transfer/one_os_edge/config.yaml"
mv "$transfer/one_os_edge" "$new"
rm -- one-os-edge-addon-bundle.tar.gz one-os-edge-addon-bundle.tar.gz.sha256 README.md INSTALL.md
cd /addons
rmdir "$transfer"'

ssh root@homeassistant.local 'set -eu
new=/addons/.one_os_edge.v042.new
target=/addons/one_os_edge
previous=/addons/.one_os_edge.v042.previous
test -f "$new/config.yaml"
if [ ! -e "$target" ] && [ -e "$previous" ]; then
  mv "$previous" "$target"
fi
had_previous=false
if [ -e "$target" ]; then
  test ! -e "$previous"
  mv "$target" "$previous"
  had_previous=true
fi
if ! mv "$new" "$target"; then
  if [ "$had_previous" = true ]; then
    mv "$previous" "$target"
  fi
  exit 1
fi'
```

Deze procedure werkt zowel bij een afwezige target als bij een update. Een bestaande
add-onsourcedirectory blijft na een geslaagde swap staan als
`/addons/.one_os_edge.v042.previous`; verwijder die pas nadat installatie, startup en
de verificaties uit sectie 6 zijn geslaagd. Als de verbinding of het proces tussen
de twee finale renames wordt onderbroken, voer dan alleen het laatste `ssh`-blok
opnieuw uit: het herstelt eerst `.previous`, valideert de reeds checksummed `.new`
en herhaalt vervolgens de swap. De persistente add-ondata in `/data` wordt hierbij
niet aangeraakt.

De doelstructuur moet zijn:

```text
/addons/one_os_edge/
├── config.yaml
├── Dockerfile
├── requirements.lock
├── alembic.ini
├── rootfs/
└── backend/, frontend/
```

## 3. App installeren in Home Assistant

1. Instellingen → Add-ons → Add-on Store.
2. Rechtsboven → vernieuwen (⋮ → Check for updates / Reload).
3. "ONE.OS Edge Connector" verschijnt onder Lokale add-ons.
4. Installeren, daarna starten.
5. Open het paneel via Instellingen → Add-ons → ONE.OS Edge Connector →
   OPEN WEB UI (Ingress; vereist een ingelogde Home Assistant-admin).

## 4. Vereisten

- Home Assistant ≥ `2025.1.0`.
- Architectuur `amd64` of `aarch64` (Supervisor bouwt de container lokaal
  vanaf de meegeleverde `Dockerfile`/`config.yaml`; een voorgebouwde
  registry-image is niet vereist voor installatie via deze route).
- Voldoende schijfruimte voor een lokale containerbuild (frontend- en
  Python-dependencies worden tijdens de eerste installatie gebouwd).

## 5. Updaten

Een upgrade vanaf `0.3.0` is een blocking, fail-closed datamigratie:

1. Stop de bestaande ONE.OS Edge Connector-add-on. Laat hem gestopt tot de
   nieuwe bytes volledig in `/addons/one_os_edge/` staan.
2. Maak via Home Assistant een verse back-up van de gestopte add-ondata. De
   private `identity/`-map is bewust uitgesloten en verlaat het apparaat niet;
   verwijder of overschrijf `/data` daarom nooit tijdens de upgrade.
3. Overschrijf de add-onmap met de geverifieerde nieuwe bundel en vernieuw de
   add-on store. Controleer vóór starten dat de getoonde versie de bedoelde
   release is.
4. Start de add-on één keer. Vóór enige databasepublicatie valideert de runtime
   de private identity cross-store tegen de publieke SQLite-state. Bij mismatch
   weigert startup fail-closed en blijft de brondatabase ongewijzigd: niet
   opnieuw proberen, `/data` niet verwijderen en eerst de logs veiligstellen.
5. Beschouw de upgrade pas als geslaagd nadat `/health` groen is en diagnostiek
   databaseRevision `0021` rapporteert.

Bestaande data in `/data` (SQLite-database, overrides en audit) blijft behouden
zolang die map niet wordt verwijderd.

### Expliciet identityherstel na een cold-backuprestore

Gebruik dit uitsluitend wanneer startup exact `identity_missing_after_restore`
rapporteert en de oorspronkelijke private identity aantoonbaar niet herstelbaar
is. Dit is een operator-geautoriseerde identityrotatie, geen gewone upgrade:

1. Houd de add-on gestopt en maak een verse cold backup.
2. Controleer dat de te installeren release deze recoveryroute bevat.
3. Zet in de add-onconfiguratie alleen `identity_recovery_authorized: true` en
   laat telemetry-, telemetry-authority- en soakopties uit.
4. Start één keer. De runtime accepteert uitsluitend exact revision `0009`, de
   gesloten `identity_missing_after_restore`-shape, een afwezige/lege private
   identitydirectory en een clean single-file SQLitebron zonder `-wal` of `-shm`.
   Als sidecars aanwezig zijn, blijft de volledige databaseset ongewijzigd en
   stopt recovery fail-closed; verwijder die bestanden niet handmatig maar stop,
   maak een cold backup en diagnoseer de onschone shutdown. Elke andere afwijking
   stopt eveneens vóór publicatie.
5. Controleer `/health`, databaseRevision `0021`, identitystatus `unpaired` en
   afwezigheid van oude pairingstate.
6. Stop de add-on, zet `identity_recovery_authorized` onmiddellijk terug op
   `false` en start opnieuw.
7. Start daarna een volledig nieuwe initial pairing via de normale Ingress-UI.
   Gebruik geen repair-mode: de oude Central-installationbinding bestaat niet
   meer. Controleer na ACK de nieuwe credential-, certificaat-, SPKI-, tenant-
   en sitebinding aan beide zijden.

Verwijder nooit handmatig SQLite-, WAL-/SHM- of identitybestanden als alternatief
voor deze route.

## 6. Verifiëren na installatie

- `/health`-endpoint van de add-on retourneert `{"status":"ok"}` via het
  Supervisor-proxypad.
- Het paneel toont "SYSTEEMOVERZICHT" met live tellingen na "Nu ontdekken".
- Diagnostiek-tabblad toont `"databaseRevision": "0021"` en een gevulde
  auditlog na de eerste commissioning-actie.
