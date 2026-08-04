import {useEffect, useMemo, useRef, useState} from 'react'
import {ApiClient} from './api'
import type {Asset, AuditEntry, Diagnostics, Inventory, Overview, Point, Property, Space, Structure} from './api'
import {Modal} from './Modal'

type Section = 'overview' | 'inventory' | 'diagnostics'
type SelectionDialog = {kind: 'asset' | 'space' | 'structure'; id: string; name: string}
type ArchiveDialog = {kind: 'assets' | 'spaces' | 'structures'; id: string; name: string; revision: number}
type SplitDialog = {asset: Asset}
type MergeDialog = {asset: Asset; targets: Asset[]}

function flattenAssets(inventory: Inventory): Asset[] {
  return inventory.structures.flatMap((s) => s.spaces.flatMap((sp) => sp.assets))
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
  const [error, setError] = useState('')
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
        if (!cancelled) setError(String(e))
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

  async function runReconcile() {
    setBusy(true)
    try {
      await client.reconcile()
      await refreshInventory()
    } catch (e) {
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function saveOverrides(form: {
    displayName?: string
    displayUnit?: string
    decimals?: number
  }) {
    if (!selected) return
    setBusy(true)
    try {
      const updated = await client.overrides(selected.id, selected.revision, form)
      await refreshInventory(updated)
    } catch (e) {
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
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
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return (
      <main className="state">
        <h1>Kan commissioning-gegevens niet laden</h1>
        <p role="alert">{error}</p>
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
                {visibleStructures.map((s) => (
                  <StructureNode
                    key={s.id}
                    structure={s}
                    selectedPointId={selected?.id ?? null}
                    onSelectPoint={setSelected}
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
            <Inspector
              point={selected}
              properties={properties}
              busy={busy}
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
  selectedPointId,
  onSelectPoint,
  onSelectAsset,
  onExcludeAsset,
  onSelectSpace,
  onSelectStructure,
  onSplit,
  onMerge,
  onArchiveAsset,
}: {
  structure: Structure
  selectedPointId: string | null
  onSelectPoint: (p: Point) => void
  onSelectAsset: (a: Asset) => void
  onExcludeAsset: (a: Asset) => void
  onSelectSpace: (s: Space) => void
  onSelectStructure: (s: Structure) => void
  onSplit: (a: Asset) => void
  onMerge: (a: Asset) => void
  onArchiveAsset: (a: Asset) => void
}) {
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
          <h4>
            <input
              type="checkbox"
              aria-label={`Selecteer ${sp.name}`}
              checked={sp.selectionState === 'selected'}
              ref={(el) => {
                if (el) el.indeterminate = sp.selectionState === 'partial'
              }}
              onChange={() => onSelectSpace(sp)}
            />
            <span>SP</span>
            {sp.name}
            <small>{sp.type}</small>
          </h4>
          {sp.assets.map((a) => (
            <div key={a.id} className="node asset">
              <div className="asset-row">
                <input
                  type="checkbox"
                  aria-label={`Selecteer ${a.name}`}
                  checked={a.selectionState === 'selected'}
                  ref={(el) => {
                    if (el) el.indeterminate = a.selectionState === 'partial'
                  }}
                  onChange={() => (a.selectionState === 'selected' ? onExcludeAsset(a) : onSelectAsset(a))}
                />
                <b>{a.name}</b>
                <small>{a.type} · {a.physicalDeviceId ? 'Fysiek apparaat gekoppeld' : 'Standalone'}</small>
                <div className="asset-actions">
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
              </div>
              {a.points.map((p) => (
                <button
                  className={`point ${selectedPointId === p.id ? 'selected' : ''}`}
                  key={p.id}
                  onClick={() => onSelectPoint(p)}
                >
                  <span className={`dot ${p.valueQuality}`} />
                  <span>
                    {p.display.name.value}
                    <small>{p.source.registryId}</small>
                  </span>
                  <em>{p.value.formatted}</em>
                  {p.sourceLifecycle !== 'active' && <mark>{p.sourceLifecycle}</mark>}
                  {p.capability.highRisk && <mark>hoog risico</mark>}
                  {p.bindingStability === 'temporary' && <mark>tijdelijk</mark>}
                </button>
              ))}
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function Inspector({
  point,
  properties,
  busy,
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
  onSave: (form: {displayName?: string; displayUnit?: string; decimals?: number}) => void
  onReset: (field: string) => void
  onControl: (enabled: boolean) => void
  onAcceptTemporary: () => void
  onAddProperty: (key: string, valueType: string, value: unknown) => void
  onRemoveProperty: (id: string, revision: number) => void
}) {
  const [propertyKey, setPropertyKey] = useState('')
  const [propertyValue, setPropertyValue] = useState('')

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
    onSave({
      displayName: String(form.get('displayName') ?? ''),
      displayUnit: String(form.get('displayUnit') ?? '') || undefined,
      decimals: Number(form.get('decimals')),
    })
  }

  return (
    <aside className="inspector" aria-label="Point inspector">
      <div className="eyebrow">POINT INSPECTOR</div>
      <h2>{point.display.name.value}</h2>
      <code>{point.id}</code>
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
      <form onSubmit={submit}>
        <label>
          Weergavenaam
          <input name="displayName" defaultValue={point.display.name.value} />
          <small>{point.display.name.provenance}</small>
        </label>
        {point.display.name.provenance === 'one_os_override' && (
          <button type="button" onClick={() => onReset('displayName')}>
            Terugzetten naar bron
          </button>
        )}
        <label>
          Weergave-eenheid
          <input name="displayUnit" defaultValue={point.display.unit.value ?? ''} />
          <small>{point.display.unit.provenance}</small>
        </label>
        {point.display.unit.provenance === 'one_os_override' && (
          <button type="button" onClick={() => onReset('displayUnit')}>
            Terugzetten naar bron
          </button>
        )}
        <label>
          Decimalen
          <input name="decimals" type="number" min="0" max="6" defaultValue={point.display.decimals.value ?? 2} />
        </label>
        {point.display.decimals.provenance === 'one_os_override' && (
          <button type="button" onClick={() => onReset('decimals')}>
            Terugzetten naar bron
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
