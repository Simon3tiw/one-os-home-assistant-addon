# ONE.OS Edge Connector — handmatige installatie

Deze repository is **privé**. Home Assistant Supervisor kan een private
GitHub-repository doorgaans niet zonder credentials als custom
add-onrepository clonen. Gebruik daarom de handmatig geïnstalleerde
bundel hieronder.

## 1. Bundel bouwen

Op een machine met deze repository (lokaal of via een groene CI-run):

```bash
./scripts/build-release-bundle.sh
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
`/addons` (of het geconfigureerde `addons`-pad in `share`). Kopieer de
uitgepakte `one_os_edge/`-map daarheen, bijvoorbeeld via Samba, SSH of
de Home Assistant Terminal/SSH-add-on:

```bash
tar -xzf one-os-edge-addon-bundle.tar.gz -C /tmp/one-os-staging
scp -r /tmp/one-os-staging/one_os_edge root@homeassistant.local:/addons/one_os_edge
```

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

Herhaal stap 1–3 met een nieuwe bundel: overschrijf de map
`/addons/one_os_edge/`, vernieuw de add-on store en herinstalleer/herstart
de app. Bestaande data in `/data` (SQLite-database, overrides, audit)
blijft behouden zolang die map niet wordt verwijderd.

## 6. Verifiëren na installatie

- `/health`-endpoint van de add-on retourneert `{"status":"ok"}` via het
  Supervisor-proxypad.
- Het paneel toont "SYSTEEMOVERZICHT" met live tellingen na "Nu ontdekken".
- Diagnostiek-tabblad toont `databaseRevision: 0002` en een gevulde
  auditlog na de eerste commissioning-actie.
