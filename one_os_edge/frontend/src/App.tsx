import {useEffect, useMemo, useRef, useState} from 'react'
import {ApiClient} from './api'
import type {Asset, AuditEntry, Diagnostics, Inventory, Overview, Point, Property, Space, Structure} from './api'
import {Modal} from './Modal'

type Section = 'overview' | 'inventory' | 'diagnostics'
type SelectionDialog = {kind: 'point' | 'asset' | 'space' | 'structure'; id: string; name: string}
type ArchiveDialog = {kind: 'assets' | 'spaces' | 'structures'; id: string; name: string; revision: number}
type SplitDialog = {asset: Asset}
type MergeDialog = {asset: Asset; targets: Asset[]}

const BRICK_BASE = 'https://brickschema.org/schema/Brick#'
const ONTOLOGY_OPTIONS = [
  ['Temperatuursensor', `${BRICK_BASE}Temperature_Sensor`],
  ['Relatieve-vochtigheidssensor', `${BRICK_BASE}Relative_Humidity_Sensor`],
  ['CO₂-sensor', `${BRICK_BASE}CO2_Sensor`],
  ['Vermogenssensor', `${BRICK_BASE}Power_Sensor`],
  ['Energiemeter', `${BRICK_BASE}Energy_Sensor`],
  ['Bezettingssensor', `${BRICK_BASE}Occupancy_Sensor`],
  ['Verlichtingssterktesensor', `${BRICK_BASE}Illuminance_Sensor`],
  ['Druksensor', `${BRICK_BASE}Pressure_Sensor`],
  ['Luchtdebietsensor', `${BRICK_BASE}Air_Flow_Sensor`],
  ['Waterdebietsensor', `${BRICK_BASE}Water_Flow_Sensor`],
  ['Spanningssensor', `${BRICK_BASE}Voltage_Sensor`],
  ['Stroomsensor', `${BRICK_BASE}Current_Sensor`],
  ['Frequentiesensor', `${BRICK_BASE}Frequency_Sensor`],
  ['Temperatuursetpoint', `${BRICK_BASE}Temperature_Setpoint`],
  ['Aan/uit-status', `${BRICK_BASE}On_Off_Status`],
  ['Alarm', `${BRICK_BASE}Alarm`],
] as const

function ontologyLabel(uri: string | null) {
  if (!uri) return 'Nog niet geclassificeerd'
  const known = ONTOLOGY_OPTIONS.find((option) => option[1] === uri)
  if (known) return known[0]
  const tail = uri.split(/[/#]/).filter(Boolean).at(-1)
  return tail?.replaceAll('_', ' ') ?? uri
}

function ontologyChoice(value: string | null | undefined) {
  if (!value) return ''
  return ONTOLOGY_OPTIONS.some(([, uri]) => uri === value) ? value : '__custom__'
}

function flattenAssets(inventory: Inventory): Asset[] {
  return inventory.structures
    .filter((structure) => structure.sourceLifecycle === 'active')
    .flatMap((structure) =>
      structure.spaces
        .filter((space) => space.sourceLifecycle === 'active')
        .flatMap((space) => space.assets.filter((asset) => asset.sourceLifecycle === 'active')),
    )
}

function spaceOptions(inventory: Inventory) {
  return inventory.structures
    .filter((structure) => structure.sourceLifecycle === 'active')
    .flatMap((structure) =>
      structure.spaces
        .filter((space) => space.sourceLifecycle === 'active')
        .map((space) => ({id: space.id, label: `${structure.name} / ${space.name}`})),
    )
}

function assetOptions(inventory: Inventory) {
  return inventory.structures
    .filter((structure) => structure.sourceLifecycle === 'active')
    .flatMap((structure) =>
      structure.spaces
        .filter((space) => space.sourceLifecycle === 'active')
        .flatMap((space) =>
          space.assets
            .filter((asset) => asset.sourceLifecycle === 'active')
            .map((asset) => ({
              id: asset.id,
              label: `${structure.name} / ${space.name} / ${asset.name}`,
            })),
        ),
    )
}

function pointLocationPath(inventory: Inventory, point: Point | null) {
  if (!point) return ''
  for (const structure of inventory.structures) {
    for (const space of structure.spaces) {
      if (space.assets.some((asset) => asset.id === point.assetId)) {
        return [inventory.site?.name, structure.name, space.name].filter(Boolean).join(' / ')
      }
    }
  }
  return inventory.site?.name ?? 'Niet toegewezen'
}

function matchesQuery(text: string, query: string) {
  return text.toLowerCase().includes(query.toLowerCase())
}

function filterInventory(inventory: Inventory, query: string, onlyUnreviewed: boolean, onlySelected: boolean): Structure[] {
  return inventory.structures
    .map((structure) => ({
      ...structure,
      spaces: structure.spaces
        .map((space) => ({
          ...space,
          assets: space.assets
            .map((asset) => ({
              ...asset,
              points: asset.points.filter((point) => {
                if (onlyUnreviewed && point.reviewStatus !== 'unreviewed') return false
                if (onlySelected && !point.effectiveSelected) return false
                if (!query) return true
                return (
                  matchesQuery(point.display.name.value, query) ||
                  matchesQuery(point.source.registryId, query)
                )
              }),
            }))
            .filter(
              (asset) =>
                asset.points.length > 0 ||
                (!onlyUnreviewed && !onlySelected && matchesQuery(asset.name, query)),
            ),
        }))
        .filter((space) => space.assets.length > 0),
    }))
    .filter((structure) => structure.spaces.length > 0)
}

export function App() {
  const clientRef = useRef<ApiClient | null>(null)
  if (!clientRef.current) clientRef.current = new ApiClient()
  const client = clientRef.current

  const [overview, setOverview] = useState<Overview | null>(null)
  const [inventory, setInventory] = useState<Inventory | null>(null)
  const [loadError, setLoadError] = useState('')
  const [actionError, setActionError] = useState('')
  const [section, setSection] = useState<Section>('overview')
  const [query, setQuery] = useState('')
  const [onlyUnreviewed, setOnlyUnreviewed] = useState(false)
  const [onlySelected, setOnlySelected] = useState(false)
  const [selected, setSelected] = useState<Point | null>(null)
  const [properties, setProperties] = useState<Property[]>([])
  const [audit, setAudit] = useState<AuditEntry[]>([])
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null)
  const [selectionDialog, setSelectionDialog] = useState<SelectionDialog | null>(null)
  const [archiveDialog, setArchiveDialog] = useState<ArchiveDialog | null>(null)
  const [splitDialog, setSplitDialog] = useState<SplitDialog | null>(null)
  const [mergeDialog, setMergeDialog] = useState<MergeDialog | null>(null)
  const [theme, setTheme] = useState<'light' | 'dark'>('dark')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        await client.init()
        const [o, i] = await Promise.all([client.overview(), client.inventory()])
        if (cancelled) return
        setOverview(o)
        setInventory(i)
      } catch (e) {
        if (!cancelled) setLoadError(String(e))
      }
    }
    load()
    const timer = window.setInterval(() => {
      client
        .inventory()
        .then((i) => !cancelled && setInventory(i))
        .catch(() => {})
      client
        .overview()
        .then((o) => !cancelled && setOverview(o))
        .catch(() => {})
    }, 10000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!selected) {
      setProperties([])
      return
    }
    client.properties('point', selected.id).then(setProperties).catch(() => setProperties([]))
  }, [selected, client])

  useEffect(() => {
    if (section === 'diagnostics') {
      client.diagnostics().then(setDiagnostics).catch(() => {})
      client.audit().then(setAudit).catch(() => {})
    }
  }, [section, client])

  async function refreshInventory(authoritativePoint?: Point) {
    const i = await client.inventory()
    setInventory(i)
    if (authoritativePoint) {
      setSelected(authoritativePoint)
    } else if (selected) {
      const fresh = i.flatPoints.find((p) => p.id === selected.id)
      if (fresh) setSelected(fresh)
    }
  }

  async function moveAsset(asset: Asset, spaceId: string) {
    if (spaceId === asset.spaceId) return
    setBusy(true)
    try {
      await client.moveAsset(asset.id, asset.revision, spaceId)
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function movePoint(assetId: string) {
    if (!selected || assetId === selected.assetId) return
    setBusy(true)
    try {
      const updated = await client.movePoint(selected.id, selected.revision, assetId)
      await refreshInventory(updated)
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function runReconcile() {
    setBusy(true)
    try {
      await client.reconcile()
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const visibleStructures = useMemo(
    () => (inventory ? filterInventory(inventory, query, onlyUnreviewed, onlySelected) : []),
    [inventory, query, onlyUnreviewed, onlySelected],
  )

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    document.documentElement.dataset.theme = next
  }

  async function confirmSelection(review: boolean) {
    if (!selectionDialog) return
    setBusy(true)
    try {
      await client.select(selectionDialog.kind, selectionDialog.id, 'include', review)
      setSelectionDialog(null)
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function excludeSelection(kind: string, id: string) {
    setBusy(true)
    try {
      await client.select(kind, id, 'exclude', false)
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function saveOverrides(form: {
    displayName?: string
    displayUnit?: string
    decimals?: number
    ontologyClass?: string
  }) {
    if (!selected) return
    setBusy(true)
    try {
      const updated = await client.overrides(selected.id, selected.revision, form)
      await refreshInventory(updated)
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function resetField(field: string) {
    if (!selected) return
    setBusy(true)
    try {
      const updated = await client.resetOverride(selected.id, field, selected.revision)
      await refreshInventory(updated)
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function toggleControl(enabled: boolean) {
    if (!selected) return
    setBusy(true)
    try {
      const updated = await client.control(selected.id, selected.revision, enabled)
      await refreshInventory(updated)
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function acceptTemporary() {
    if (!selected) return
    setBusy(true)
    try {
      const updated = await client.acceptTemporaryBinding(selected.id, selected.revision)
      await refreshInventory(updated)
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function addProperty(key: string, valueType: string, value: unknown) {
    if (!selected) return
    setBusy(true)
    try {
      const created = await client.createProperty('point', selected.id, key, valueType, value)
      setProperties((prev) => [...prev, created])
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function removeProperty(propertyId: string, revision: number) {
    setBusy(true)
    try {
      await client.deleteProperty(propertyId, revision)
      setProperties((prev) => prev.filter((p) => p.id !== propertyId))
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function performSplit(name: string, pointIds: string[]) {
    if (!splitDialog) return
    setBusy(true)
    try {
      await client.splitAsset(splitDialog.asset.id, splitDialog.asset.revision, name, pointIds)
      setSplitDialog(null)
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function performMerge(otherAssetId: string) {
    if (!mergeDialog) return
    setBusy(true)
    try {
      await client.mergeAsset(mergeDialog.asset.id, mergeDialog.asset.revision, otherAssetId)
      setMergeDialog(null)
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function performArchive(action: 'rehome' | 'cascade') {
    if (!archiveDialog) return
    setBusy(true)
    try {
      await client.archive(archiveDialog.kind, archiveDialog.id, archiveDialog.revision, action)
      setArchiveDialog(null)
      await refreshInventory()
    } catch (e) {
      setActionError(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (loadError) {
    return (
      <main className="state">
        <h1>Kan commissioning-gegevens niet laden</h1>
        <p role="alert">{loadError}</p>
        <button onClick={() => location.reload()}>Opnieuw proberen</button>
      </main>
    )
  }
  if (!overview || !inventory) {
    return (
      <main className="state" aria-busy="true">
        <div className="spinner" />
        <p>Lokale inventaris laden…</p>
      </main>
    )
  }

  return (
    <>
      <div id="app-root" className="shell">
      <header>
        <div>
          <b className="wordmark">ONE.OS</b>
          <span>Edge commissioning</span>
        </div>
        <div className="header-actions">
          <span className={`presence ${overview.connectorPresence}`}>{overview.connectorPresence}</span>
          <button onClick={toggleTheme} aria-label="Wissel kleurthema">
            {theme === 'dark' ? 'Licht' : 'Donker'}e modus
          </button>
        </div>
      </header>
      <aside>
        <nav aria-label="Commissioning-secties">
          <a
            className={section === 'overview' ? 'active' : ''}
            href="#overview"
            onClick={() => setSection('overview')}
          >
            Overzicht
          </a>
          <a
            className={section === 'inventory' ? 'active' : ''}
            href="#inventory"
            onClick={() => setSection('inventory')}
          >
            Inventaris &amp; ontologie
          </a>
          <a
            className={section === 'diagnostics' ? 'active' : ''}
            href="#diagnostics"
            onClick={() => setSection('diagnostics')}
          >
            Diagnostiek
          </a>
        </nav>
        <div className="phase">
          Fase 2A
          <br />
          <small>Alleen lokale commissioning</small>
        </div>
      </aside>
      <main>
        {actionError && (
          <div className="notice" role="alert">
            Actie niet uitgevoerd: {actionError}
            <button type="button" onClick={() => setActionError('')}>
              Sluiten
            </button>
          </div>
        )}
        {section === 'overview' && (
          <section id="overview">
            <div className="eyebrow">SYSTEEMOVERZICHT</div>
            <h1>Home Assistant-inventaris</h1>
            <p>{overview.phaseNotice}</p>
            <div className="cards">
              {Object.entries(overview.counts).map(([k, v]) => (
                <article key={k}>
                  <span>{k}</span>
                  <strong>{v}</strong>
                </article>
              ))}
            </div>
          </section>
        )}
        {section === 'inventory' && (
          <section id="inventory" className="workspace">
            <div className="inventory">
              <div className="section-head">
                <div>
                  <div className="eyebrow">ONTOLOGIE</div>
                  <h2>Inventaris</h2>
                </div>
                <button onClick={runReconcile} disabled={busy}>
                  Nu ontdekken
                </button>
              </div>
              <div className="filters">
                <label className="search">
                  Zoek in inventaris
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Naam of bron…"
                  />
                </label>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={onlyUnreviewed}
                    onChange={(e) => setOnlyUnreviewed(e.target.checked)}
                  />
                  Alleen niet-beoordeeld
                </label>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={onlySelected}
                    onChange={(e) => setOnlySelected(e.target.checked)}
                  />
                  Alleen geselecteerd
                </label>
              </div>
              {visibleStructures.length === 0 && <p className="empty">Geen overeenkomende objecten.</p>}
              <div className="tree">
                <div className="site-root">
                  <div className="site-row">
                    <span className="node-kind">SI</span>
                    <b>{inventory.site?.name ?? 'Lokale Site'}</b>
                    <small>Site · {visibleStructures.length} structuren</small>
                  </div>
                {visibleStructures.map((s) => (
                  <StructureNode
                    key={s.id}
                    structure={s}
                    expandMatches={Boolean(query || onlyUnreviewed || onlySelected)}
                    selectedPointId={selected?.id ?? null}
                    onSelectPoint={setSelected}
                    onIncludePoint={(point) =>
                      setSelectionDialog({kind: 'point', id: point.id, name: point.display.name.value})
                    }
                    onExcludePoint={(point) => excludeSelection('point', point.id)}
                    spaceOptions={spaceOptions(inventory)}
                    onMoveAsset={moveAsset}
                    onSelectAsset={(asset) =>
                      setSelectionDialog({kind: 'asset', id: asset.id, name: asset.name})
                    }
                    onExcludeAsset={(asset) => excludeSelection('asset', asset.id)}
                    onSelectSpace={(space) =>
                      setSelectionDialog({kind: 'space', id: space.id, name: space.name})
                    }
                    onSelectStructure={(structure) =>
                      setSelectionDialog({kind: 'structure', id: structure.id, name: structure.name})
                    }
                    onSplit={(asset) => setSplitDialog({asset})}
                    onMerge={(asset) =>
                      setMergeDialog({asset, targets: flattenAssets(inventory).filter((a) => a.id !== asset.id)})
                    }
                    onArchiveAsset={(asset) =>
                      setArchiveDialog({kind: 'assets', id: asset.id, name: asset.name, revision: asset.revision})
                    }
                  />
                ))}
                </div>
              </div>
            </div>
            <Inspector
              point={selected}
              properties={properties}
              busy={busy}
              locationPath={pointLocationPath(inventory, selected)}
              assetOptions={assetOptions(inventory)}
              onMovePoint={movePoint}
              onSave={saveOverrides}
              onReset={resetField}
              onControl={toggleControl}
              onAcceptTemporary={acceptTemporary}
              onAddProperty={addProperty}
              onRemoveProperty={removeProperty}
            />
          </section>
        )}
        {section === 'diagnostics' && <DiagnosticsPanel diagnostics={diagnostics} audit={audit} />}
      </main>
      </div>
      {selectionDialog && (
        <Modal title="Beoordelen en selecteren" onClose={() => setSelectionDialog(null)}>
          <h2>Beoordelen en selecteren</h2>
          <p>
            {`Het includeren van "${selectionDialog.name}" beoordeelt en selecteert de bestaande Points. Nieuw ontdekte Points blijven onbeoordeeld.`}
          </p>
          <div>
            <button onClick={() => setSelectionDialog(null)}>Annuleren</button>
            <button onClick={() => confirmSelection(true)} disabled={busy}>
              Beoordelen en selecteren
            </button>
          </div>
        </Modal>
      )}
      {archiveDialog && (
        <ArchiveModal
          dialog={archiveDialog}
          busy={busy}
          onClose={() => setArchiveDialog(null)}
          onConfirm={performArchive}
        />
      )}
      {splitDialog && (
        <SplitModal dialog={splitDialog} busy={busy} onClose={() => setSplitDialog(null)} onConfirm={performSplit} />
      )}
      {mergeDialog && (
        <MergeModal dialog={mergeDialog} busy={busy} onClose={() => setMergeDialog(null)} onConfirm={performMerge} />
      )}
    </>
  )
}

function StructureNode({
  structure,
  expandMatches,
  selectedPointId,
  onSelectPoint,
  onIncludePoint,
  onExcludePoint,
  spaceOptions,
  onMoveAsset,
  onSelectAsset,
  onExcludeAsset,
  onSelectSpace,
  onSelectStructure,
  onSplit,
  onMerge,
  onArchiveAsset,
}: {
  structure: Structure
  expandMatches: boolean
  selectedPointId: string | null
  onSelectPoint: (p: Point) => void
  onIncludePoint: (p: Point) => void
  onExcludePoint: (p: Point) => void
  spaceOptions: {id: string; label: string}[]
  onMoveAsset: (asset: Asset, spaceId: string) => void
  onSelectAsset: (a: Asset) => void
  onExcludeAsset: (a: Asset) => void
  onSelectSpace: (s: Space) => void
  onSelectStructure: (s: Structure) => void
  onSplit: (a: Asset) => void
  onMerge: (a: Asset) => void
  onArchiveAsset: (a: Asset) => void
}) {
  const [expandedSpaces, setExpandedSpaces] = useState<Set<string>>(() => new Set())
  const [expandedAssets, setExpandedAssets] = useState<Set<string>>(() => new Set())

  function toggleSpace(spaceId: string) {
    setExpandedSpaces((current) => {
      const next = new Set(current)
      if (next.has(spaceId)) next.delete(spaceId)
      else next.add(spaceId)
      return next
    })
  }

  function toggleAsset(assetId: string) {
    setExpandedAssets((current) => {
      const next = new Set(current)
      if (next.has(assetId)) next.delete(assetId)
      else next.add(assetId)
      return next
    })
  }

  return (
    <div className="node structure">
      <h3>
        <input
          type="checkbox"
          aria-label={`Selecteer ${structure.name}`}
          checked={structure.selectionState === 'selected'}
          ref={(el) => {
            if (el) el.indeterminate = structure.selectionState === 'partial'
          }}
          onChange={() => onSelectStructure(structure)}
        />
        <span>ST</span>
        {structure.name}
        <small>{structure.type}</small>
      </h3>
      {structure.spaces.map((sp) => (
        <div key={sp.id} className="node space">
          <div className="space-row">
            <button
              type="button"
              className="space-disclosure"
              aria-expanded={expandMatches || expandedSpaces.has(sp.id)}
              aria-controls={`space-assets-${sp.id}`}
              aria-label={`Ruimte ${sp.name} ${expandMatches || expandedSpaces.has(sp.id) ? 'inklappen' : 'uitklappen'}`}
              disabled={expandMatches}
              onClick={() => toggleSpace(sp.id)}
            >
              <svg aria-hidden="true" viewBox="0 0 16 16">
                <path d="m5 3 5 5-5 5" />
              </svg>
            </button>
            <input
              type="checkbox"
              aria-label={`Selecteer ${sp.name}`}
              checked={sp.selectionState === 'selected'}
              ref={(el) => {
                if (el) el.indeterminate = sp.selectionState === 'partial'
              }}
              onChange={() => onSelectSpace(sp)}
            />
            <span className="node-kind">SP</span>
            <b>{sp.name}</b>
            <small>
              {sp.type} · {sp.assets.length} {sp.assets.length === 1 ? 'device' : 'devices'}
            </small>
          </div>
          {(expandMatches || expandedSpaces.has(sp.id)) && <div className="space-assets" id={`space-assets-${sp.id}`}>
          {sp.assets.map((a) => (
            <div key={a.id} className="node asset">
              <div className="asset-row">
                <button
                  type="button"
                  className="asset-disclosure"
                  aria-expanded={expandMatches || expandedAssets.has(a.id)}
                  aria-controls={`asset-points-${a.id}`}
                  aria-label={`${expandMatches || expandedAssets.has(a.id) ? 'Inklappen' : 'Uitklappen'} ${a.name}`}
                  disabled={expandMatches}
                  onClick={() => toggleAsset(a.id)}
                >
                  <svg aria-hidden="true" viewBox="0 0 16 16">
                    <path d="m5 3 5 5-5 5" />
                  </svg>
                </button>
                <label className="cloud-selection">
                  <input
                    type="checkbox"
                    aria-label={`Selecteer ${a.name} voor ONE.OS Cloud`}
                    checked={a.selectionState === 'selected'}
                    ref={(el) => {
                      if (el) el.indeterminate = a.selectionState === 'partial'
                    }}
                    onChange={() => (a.selectionState === 'selected' ? onExcludeAsset(a) : onSelectAsset(a))}
                  />
                  <span>Cloud</span>
                  <small>{a.selectionState === 'selected' ? 'aan' : a.selectionState === 'partial' ? 'deels' : 'uit'}</small>
                </label>
                <b>{a.name}</b>
                <small>
                  {a.type} · {a.physicalDeviceId ? 'Fysiek apparaat gekoppeld' : 'Standalone'} · {a.points.length}{' '}
                  {a.points.length === 1 ? 'point' : 'points'}
                </small>
                {(expandMatches || expandedAssets.has(a.id)) && (
                  <div className="asset-actions">
                    <label className="asset-placement">
                      Ruimte voor device {a.name}
                      <select value={a.spaceId} onChange={(e) => onMoveAsset(a, e.target.value)}>
                        {spaceOptions.map((option) => (
                          <option key={option.id} value={option.id}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button type="button" onClick={() => onSplit(a)} disabled={a.points.length < 2}>
                      Splitsen
                    </button>
                    <button type="button" onClick={() => onMerge(a)}>
                      Samenvoegen
                    </button>
                    <button type="button" onClick={() => onArchiveAsset(a)}>
                      Archiveren
                    </button>
                  </div>
                )}
              </div>
              {(expandMatches || expandedAssets.has(a.id)) && (
                <div className="asset-points" id={`asset-points-${a.id}`}>
                  {a.points.map((p) => (
                    <div className="point-row" key={p.id}>
                      <label className="point-cloud-toggle">
                        <input
                          type="checkbox"
                          className="point-cloud-selection"
                          aria-label={`Includeer ${p.display.name.value} in ONE.OS Cloud`}
                          checked={p.effectiveSelected}
                          onChange={() => (p.effectiveSelected ? onExcludePoint(p) : onIncludePoint(p))}
                        />
                        <span aria-hidden="true">Cloud</span>
                      </label>
                      <button
                        className={`point ${selectedPointId === p.id ? 'selected' : ''}`}
                        onClick={() => onSelectPoint(p)}
                      >
                        <span className={`dot ${p.valueQuality}`} />
                        <span>
                          {p.display.name.value}
                          <small>{p.source.registryId}</small>
                          <span className="ontology-name">{ontologyLabel(p.ontologyClass)}</span>
                        </span>
                        <em>{p.value.formatted}</em>
                        {p.sourceLifecycle !== 'active' && <mark>{p.sourceLifecycle}</mark>}
                        {p.capability.highRisk && <mark>hoog risico</mark>}
                        {p.bindingStability === 'temporary' && <mark>tijdelijk</mark>}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          </div>}
        </div>
      ))}
    </div>
  )
}

function Inspector({
  point,
  properties,
  busy,
  locationPath,
  assetOptions,
  onMovePoint,
  onSave,
  onReset,
  onControl,
  onAcceptTemporary,
  onAddProperty,
  onRemoveProperty,
}: {
  point: Point | null
  properties: Property[]
  busy: boolean
  locationPath: string
  assetOptions: {id: string; label: string}[]
  onMovePoint: (assetId: string) => void
  onSave: (form: {displayName?: string; displayUnit?: string; decimals?: number; ontologyClass?: string}) => void
  onReset: (field: string) => void
  onControl: (enabled: boolean) => void
  onAcceptTemporary: () => void
  onAddProperty: (key: string, valueType: string, value: unknown) => void
  onRemoveProperty: (id: string, revision: number) => void
}) {
  const [propertyKey, setPropertyKey] = useState('')
  const [propertyValue, setPropertyValue] = useState('')
  const [selectedOntology, setSelectedOntology] = useState(() => ontologyChoice(point?.ontologyClass))
  const [customOntology, setCustomOntology] = useState(() =>
    ontologyChoice(point?.ontologyClass) === '__custom__' ? (point?.ontologyClass ?? '') : '',
  )

  useEffect(() => {
    const choice = ontologyChoice(point?.ontologyClass)
    setSelectedOntology(choice)
    setCustomOntology(choice === '__custom__' ? (point?.ontologyClass ?? '') : '')
  }, [point?.id, point?.ontologyClass])

  if (!point) {
    return (
      <aside className="inspector" aria-label="Point inspector">
        <div className="empty inspector-empty">
          <span>↖</span>
          <h2>Selecteer een Point</h2>
          <p>Inspecteer bronbewijs, live waarden, overrides en commissioningstatus.</p>
        </div>
      </aside>
    )
  }

  function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const form = new FormData(e.currentTarget)
    const nextOntology =
      selectedOntology === '__custom__' ? customOntology.trim() : selectedOntology || undefined
    const payload: {displayName?: string; displayUnit?: string; decimals?: number; ontologyClass?: string} = {
      displayName: String(form.get('displayName') ?? ''),
      displayUnit: String(form.get('displayUnit') ?? '') || undefined,
      decimals: Number(form.get('decimals')),
    }
    if (nextOntology && nextOntology !== point?.ontologyClass) payload.ontologyClass = nextOntology
    onSave(payload)
  }

  return (
    <aside className="inspector" aria-label="Point inspector">
      <div className="eyebrow">POINT INSPECTOR</div>
      <h2>{point.display.name.value}</h2>
      <code>{point.id}</code>
      <p className="location-path">{locationPath}</p>
      <div className="live">
        <span>Live waarde</span>
        <strong>{point.value.formatted}</strong>
        <small>
          {point.value.quality} · raw {point.value.raw}
        </small>
      </div>
      {point.bindingStability === 'temporary' && !point.temporaryAccepted && (
        <div className="notice">
          <p>Deze binding is tijdelijk en moet expliciet worden geaccepteerd voordat selectie mogelijk is.</p>
          <button onClick={onAcceptTemporary} disabled={busy}>
            Tijdelijke binding accepteren
          </button>
        </div>
      )}
      <label className="point-placement">
        Device en locatie
        <select value={point.assetId} onChange={(e) => onMovePoint(e.target.value)} disabled={busy}>
          {assetOptions.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <form onSubmit={submit}>
        <label>
          Pointnaam
          <input
            key={`${point.id}:${point.revision}:displayName`}
            name="displayName"
            defaultValue={point.display.name.value}
          />
          <small>{point.display.name.provenance}</small>
        </label>
        {point.display.name.provenance === 'one_os_override' && (
          <button
            type="button"
            aria-label="Pointnaam terugzetten naar bron"
            onClick={() => onReset('displayName')}
          >
            Terugzetten naar bron
          </button>
        )}
        <label>
          Weergave-eenheid
          <input
            key={`${point.id}:${point.revision}:displayUnit`}
            name="displayUnit"
            defaultValue={point.display.unit.value ?? ''}
          />
          <small>{point.display.unit.provenance}</small>
        </label>
        {point.display.unit.provenance === 'one_os_override' && (
          <button
            type="button"
            aria-label="Weergave-eenheid terugzetten naar bron"
            onClick={() => onReset('displayUnit')}
          >
            Terugzetten naar bron
          </button>
        )}
        <label>
          Decimalen
          <input
            key={`${point.id}:${point.revision}:decimals`}
            name="decimals"
            type="number"
            min="0"
            max="6"
            defaultValue={point.display.decimals.value ?? 2}
          />
        </label>
        {point.display.decimals.provenance === 'one_os_override' && (
          <button type="button" aria-label="Decimalen terugzetten naar bron" onClick={() => onReset('decimals')}>
            Terugzetten naar bron
          </button>
        )}
        <label>
          Ontologyklasse
          <select value={selectedOntology} onChange={(e) => setSelectedOntology(e.target.value)}>
            {!point.ontologyClass && <option value="">Nog niet geclassificeerd</option>}
            {ONTOLOGY_OPTIONS.map(([label, uri]) => (
              <option key={uri} value={uri}>
                {label}
              </option>
            ))}
            <option value="__custom__">Anders…</option>
          </select>
          <small>Brick-compatible URI; los van Site, Floor en Room.</small>
          <small>
            {point.ontologyClassProvenance === 'one_os_override'
              ? 'Handmatig aangepast in ONE.OS'
              : point.ontologyClassProvenance === 'home_assistant_inferred'
                ? 'Automatisch afgeleid uit Home Assistant'
                : 'Geen automatische classificatie beschikbaar'}
          </small>
        </label>
        {selectedOntology === '__custom__' && (
          <label>
            Eigen ontology-URI
            <input
              type="url"
              required
              value={customOntology}
              onChange={(e) => setCustomOntology(e.target.value)}
              placeholder="https://example.com/ontology#PointClass"
            />
          </label>
        )}
        {point.ontologyClassProvenance === 'one_os_override' && (
          <button type="button" onClick={() => onReset('ontologyClass')}>
            Ontologyklasse terugzetten
          </button>
        )}
        <button type="submit" disabled={busy}>
          Overrides opslaan
        </button>
      </form>
      <dl>
        <dt>Bronlevenscyclus</dt>
        <dd>{point.sourceLifecycle}</dd>
        <dt>Selectie</dt>
        <dd>
          {point.reviewStatus} / {point.selectionIntent}
        </dd>
        <dt>Commandocapability</dt>
        <dd>
          {point.capability.actions.join(', ') || 'Alleen lezen'}
          {point.capability.highRisk ? ' — hoog risico' : ''}
        </dd>
        <dt>Cloudbediening</dt>
        <dd>
          {point.cloudControlEnabled ? 'Ingeschakeld' : 'Uitgeschakeld'}
          {' '}
          <button
            type="button"
            disabled={busy || (!point.cloudControlEnabled && !point.capability.technicallyControllable)}
            onClick={() => onControl(!point.cloudControlEnabled)}
          >
            {point.cloudControlEnabled ? 'Uitschakelen' : 'Inschakelen'}
          </button>
        </dd>
      </dl>
      <section className="properties">
        <h3>Eigenschappen</h3>
        <ul>
          {properties.map((p) => (
            <li key={p.id}>
              <span>{p.key}</span>
              <code>{JSON.stringify(p.value)}</code>
              <button type="button" onClick={() => onRemoveProperty(p.id, p.revision)}>
                Verwijderen
              </button>
            </li>
          ))}
        </ul>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (!propertyKey) return
            onAddProperty(propertyKey, 'string', propertyValue)
            setPropertyKey('')
            setPropertyValue('')
          }}
        >
          <label>
            Sleutel
            <input value={propertyKey} onChange={(e) => setPropertyKey(e.target.value)} />
          </label>
          <label>
            Waarde
            <input value={propertyValue} onChange={(e) => setPropertyValue(e.target.value)} />
          </label>
          <button type="submit">Eigenschap toevoegen</button>
        </form>
      </section>
    </aside>
  )
}

function ArchiveModal({
  dialog,
  busy,
  onClose,
  onConfirm,
}: {
  dialog: ArchiveDialog
  busy: boolean
  onClose: () => void
  onConfirm: (action: 'rehome' | 'cascade') => void
}) {
  return (
    <Modal title="Archiveren" onClose={onClose}>
      <h2>{`"${dialog.name}" archiveren`}</h2>
      <p>Kies of onderliggende objecten worden verplaatst (rehome) of mee worden gearchiveerd (cascade).</p>
      <div>
        <button onClick={onClose}>Annuleren</button>
        <button onClick={() => onConfirm('rehome')} disabled={busy}>
          Verplaatsen (rehome)
        </button>
        <button onClick={() => onConfirm('cascade')} disabled={busy}>
          Cascaderen
        </button>
      </div>
    </Modal>
  )
}

function SplitModal({
  dialog,
  busy,
  onClose,
  onConfirm,
}: {
  dialog: SplitDialog
  busy: boolean
  onClose: () => void
  onConfirm: (name: string, pointIds: string[]) => void
}) {
  const [name, setName] = useState('')
  const [chosen, setChosen] = useState<string[]>([])
  return (
    <Modal title="Asset splitsen" onClose={onClose}>
      <h2>{`"${dialog.asset.name}" splitsen`}</h2>
      <label>
        Naam nieuw asset
        <input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      </label>
      <fieldset>
        <legend>Te verplaatsen Points</legend>
        {dialog.asset.points.map((p) => (
          <label key={p.id}>
            <input
              type="checkbox"
              checked={chosen.includes(p.id)}
              onChange={(e) =>
                setChosen((prev) => (e.target.checked ? [...prev, p.id] : prev.filter((id) => id !== p.id)))
              }
            />
            {p.display.name.value}
          </label>
        ))}
      </fieldset>
      <div>
        <button onClick={onClose}>Annuleren</button>
        <button onClick={() => onConfirm(name, chosen)} disabled={busy || !name || chosen.length === 0}>
          Splitsen
        </button>
      </div>
    </Modal>
  )
}

function MergeModal({
  dialog,
  busy,
  onClose,
  onConfirm,
}: {
  dialog: MergeDialog
  busy: boolean
  onClose: () => void
  onConfirm: (otherAssetId: string) => void
}) {
  const [target, setTarget] = useState('')
  return (
    <Modal title="Assets samenvoegen" onClose={onClose}>
      <h2>{`"${dialog.asset.name}" samenvoegen met`}</h2>
      <label>
        Ander asset
        <select value={target} onChange={(e) => setTarget(e.target.value)} autoFocus>
          <option value="">Kies…</option>
          {dialog.targets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </label>
      <div>
        <button onClick={onClose}>Annuleren</button>
        <button onClick={() => onConfirm(target)} disabled={busy || !target}>
          Samenvoegen
        </button>
      </div>
    </Modal>
  )
}

function DiagnosticsPanel({diagnostics, audit}: {diagnostics: Diagnostics | null; audit: AuditEntry[]}) {
  return (
    <section id="diagnostics">
      <div className="eyebrow">DIAGNOSTIEK</div>
      <h1>Systeemstatus &amp; audit</h1>
      {diagnostics && (
        <div className="cards">
          <article>
            <span>Softwareversie</span>
            <strong>{diagnostics.softwareVersion}</strong>
          </article>
          <article>
            <span>Architectuur</span>
            <strong>{diagnostics.architecture}</strong>
          </article>
          <article>
            <span>Databaserevisie</span>
            <strong>{diagnostics.databaseRevision}</strong>
          </article>
          <article>
            <span>Connector</span>
            <strong>{diagnostics.connectorPresence}</strong>
          </article>
          <article>
            <span>Laatste synchronisatie</span>
            <strong>{diagnostics.lastSync.status}</strong>
          </article>
          <article>
            <span>Audit records</span>
            <strong>{diagnostics.storage.auditRecords}</strong>
          </article>
        </div>
      )}
      <h2>Auditlog</h2>
      <table>
        <thead>
          <tr>
            <th>Tijd</th>
            <th>Actor</th>
            <th>Actie</th>
            <th>Object</th>
          </tr>
        </thead>
        <tbody>
          {audit.map((entry, i) => (
            <tr key={i}>
              <td>{entry.at}</td>
              <td>{entry.actorId}</td>
              <td>{entry.action}</td>
              <td>{entry.objectId}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
