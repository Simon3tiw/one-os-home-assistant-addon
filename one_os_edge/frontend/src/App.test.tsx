import {afterEach, describe, expect, it, vi} from 'vitest'
import {cleanup, render, screen, waitFor, within} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {App} from './App'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function makePoint(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 'p1',
    revision: 1,
    assetId: 'a1',
    source: {registryId: 'sensor.demo_temperature'},
    sourceLifecycle: 'active',
    reviewStatus: 'unreviewed',
    selectionIntent: 'unset',
    effectiveSelected: false,
    valueQuality: 'good',
    cloudControlEnabled: false,
    capabilityReviewRequired: false,
    bindingStability: 'stable',
    temporaryAccepted: false,
    placementOverride: false,
    placementConflict: false,
    ontologyClass: 'https://brickschema.org/schema/Brick#Temperature_Sensor',
    ontologyClassProvenance: 'home_assistant_inferred',
    display: {
      name: {value: 'Demo temperature', provenance: 'home_assistant'},
      unit: {value: '°C', provenance: 'home_assistant'},
      decimals: {value: null, provenance: 'home_assistant'},
    },
    value: {raw: '20.42', formatted: '20,42 °C', quality: 'good', updatedAt: null},
    capability: {actions: [], highRisk: false, technicallyControllable: false, immutable: true},
    ...overrides,
  }
}

function makeInventory(point = makePoint()) {
  return {
    site: {id: 'site1', name: 'Demo site'},
    structures: [
      {
        id: 's1',
        name: 'Ground floor',
        type: 'Floor',
        revision: 1,
        sourceLifecycle: 'active',
        selectionState: 'partial',
        spaces: [
          {
            id: 'sp1',
            name: 'Office',
            type: 'Room',
            revision: 1,
            sourceLifecycle: 'active',
            selectionState: 'partial',
            assets: [
              {
                id: 'a1',
                spaceId: 'sp1',
                name: 'Office multisensor',
                type: 'Equipment',
                revision: 1,
                sourceLifecycle: 'active',
                placementOverride: false,
                placementConflict: false,
                selectionState: 'partial',
                physicalDeviceId: 'dev1',
                points: [point],
              },
            ],
          },
          {
            id: 'sp2',
            name: 'Storage',
            type: 'Room',
            revision: 1,
            sourceLifecycle: 'active',
            selectionState: 'unselected',
            assets: [
              {
                id: 'a2',
                spaceId: 'sp2',
                name: 'Storage controller',
                type: 'Equipment',
                revision: 1,
                sourceLifecycle: 'active',
                placementOverride: false,
                placementConflict: false,
                selectionState: 'unselected',
                physicalDeviceId: 'dev2',
                points: [],
              },
            ],
          },
        ],
      },
    ],
    flatPoints: [point],
    counts: {structures: 1, spaces: 1, physicalDevices: 1, assets: 1, points: 1},
  }
}

function mockApi(point = makePoint(), inventory = makeInventory(point)) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (url.endsWith('/session')) return new Response(JSON.stringify({csrfToken: 'test'}))
      if (url.endsWith('/overview'))
        return new Response(
          JSON.stringify({
            connectorPresence: 'online',
            lastSync: null,
            counts: inventory.counts,
            phaseNotice: 'Cloud pairing and data transport follow in Phase 2B/2C',
            database: 'healthy',
          }),
        )
      if (url.endsWith('/inventory')) return new Response(JSON.stringify(inventory))
      if (url.includes('/properties/point/')) {
        if (method === 'POST') {
          const body = JSON.parse(String(init?.body))
          return new Response(
            JSON.stringify({id: 'prop1', revision: 1, ownerKind: 'point', ownerId: point.id, ...body}),
          )
        }
        return new Response(JSON.stringify([]))
      }
      if (url.includes('/points/p1') && url.includes('/control'))
        return new Response(JSON.stringify({...point, cloudControlEnabled: true}))
      if (url.includes('/points/p1') && url.includes('/accept-temporary-binding'))
        return new Response(JSON.stringify({...point, temporaryAccepted: true}))
      if (url.includes('/points/p1')) return new Response(JSON.stringify(point))
      if (url.includes('/selection/')) return new Response(JSON.stringify({state: 'selected'}))
      if (url.includes('/overrides'))
        return new Response(
          JSON.stringify({
            ...point,
            display: {...point.display, name: {value: 'Supply temperature', provenance: 'one_os_override'}},
          }),
        )
      if (url.endsWith('/diagnostics/export'))
        return new Response(
          JSON.stringify({
            schemaVersion: '1.0',
            softwareVersion: '0.1.4',
            architecture: 'amd64',
            installationHash: 'hash',
            databaseRevision: '0003',
            connectorPresence: 'online',
            lastSync: {at: null, status: 'never'},
            counts: inventory.counts,
            storage: {auditRecords: 0, configurationBytes: 0},
          }),
        )
      if (url.endsWith('/audit')) return new Response(JSON.stringify([]))
      return new Response('{}')
    }),
  )
}

async function openOfficeRoom(u: ReturnType<typeof userEvent.setup>) {
  await u.click(await screen.findByText('Inventaris & ontologie'))
  await u.click(await screen.findByRole('button', {name: 'Ruimte Office uitklappen'}))
}

async function openDemoPoint(u: ReturnType<typeof userEvent.setup>) {
  await openOfficeRoom(u)
  await u.click(await screen.findByRole('button', {name: 'Uitklappen Office multisensor'}))
  await u.click(await screen.findByRole('button', {name: /Demo temperature/}))
}

describe('commissioning UI', () => {
  it('renders overview and the searchable ontology tree', async () => {
    mockApi()
    render(<App />)
    expect(await screen.findByText('Home Assistant-inventaris')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Inventaris & ontologie'))
    expect(await screen.findByText('Ground floor')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', {name: 'Ruimte Office uitklappen'}))
    expect(screen.getByText('Office multisensor')).toBeInTheDocument()
  })

  it('collapses rooms by default and reveals their devices as a tree branch', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await u.click(await screen.findByText('Inventaris & ontologie'))

    const expandRoom = await screen.findByRole('button', {name: 'Ruimte Office uitklappen'})
    expect(expandRoom).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('Office multisensor')).not.toBeInTheDocument()

    await u.click(expandRoom)
    expect(screen.getByRole('button', {name: 'Ruimte Office inklappen'})).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByText('Office multisensor')).toBeInTheDocument()

    await u.click(screen.getByRole('button', {name: 'Ruimte Office inklappen'}))
    expect(screen.queryByText('Office multisensor')).not.toBeInTheDocument()
  })

  it('collapses device points by default and toggles them with an accessible disclosure', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openOfficeRoom(u)

    const expand = await screen.findByRole('button', {name: 'Uitklappen Office multisensor'})
    expect(expand).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('button', {name: /Demo temperature/})).not.toBeInTheDocument()

    await u.click(expand)
    expect(screen.getByRole('button', {name: 'Inklappen Office multisensor'})).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByRole('button', {name: /Demo temperature/})).toBeInTheDocument()

    await u.click(screen.getByRole('button', {name: 'Inklappen Office multisensor'}))
    expect(screen.queryByRole('button', {name: /Demo temperature/})).not.toBeInTheDocument()
  })

  it('shows the canonical ontology label on every Point and its provenance in the inspector', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    expect(screen.getByText('Temperatuursensor', {selector: '.ontology-name'})).toBeInTheDocument()
    expect(screen.getByText('Automatisch afgeleid uit Home Assistant')).toBeInTheDocument()
    expect(screen.queryByRole('button', {name: 'Ontologyklasse terugzetten'})).not.toBeInTheDocument()
  })

  it('shows ontology reset only for a manual ONE.OS override', async () => {
    const point = makePoint({ontologyClassProvenance: 'one_os_override'})
    mockApi(point)
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    expect(screen.getByRole('button', {name: 'Ontologyklasse terugzetten'})).toBeInTheDocument()
  })

  it('filters the tree by search query', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await u.click(await screen.findByText('Inventaris & ontologie'))
    await screen.findByText('Ground floor')
    const search = screen.getByLabelText(/Zoek in inventaris/)
    await u.type(search, 'nonexistent')
    expect(await screen.findByText('Geen overeenkomende objecten.')).toBeInTheDocument()
  })

  it('opens an accessible inspector and saves an override', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)
    expect((await screen.findAllByText('20,42 °C')).length).toBeGreaterThan(0)
    const name = screen.getByLabelText(/Pointnaam/)
    await u.clear(name)
    await u.type(name, 'Supply temperature')
    await u.click(screen.getByRole('button', {name: 'Overrides opslaan'}))
    expect(await screen.findByDisplayValue('Supply temperature')).toBeInTheDocument()
    await waitFor(() => {
      const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).includes('/points/p1/overrides'))
      const body = JSON.parse(String(call?.[1]?.body))
      expect(body).not.toHaveProperty('ontologyClass')
    })
  })

  it('moves a device to an existing Floor and Room with a persistent API mutation', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openOfficeRoom(u)

    expect(screen.getByText('Demo site')).toBeInTheDocument()
    await u.click(screen.getByRole('button', {name: 'Uitklappen Office multisensor'}))
    await u.selectOptions(screen.getByLabelText('Ruimte voor device Office multisensor'), 'sp2')

    await waitFor(() => {
      const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).includes('/assets/a1'))
      expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({revision: 1, spaceId: 'sp2'})
    })
  })

  it('moves a Point to an existing device while showing its location path', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    expect(screen.getByText('Demo site / Ground floor / Office')).toBeInTheDocument()
    await u.selectOptions(screen.getByLabelText('Device en locatie'), 'a2')

    await waitFor(() => {
      const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).includes('/points/p1/placement'))
      expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({revision: 1, assetId: 'a2'})
    })
  })

  it('stores a controlled Brick ontology class together with a custom point name', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    const ontology = screen.getByLabelText(/Ontologyklasse/)
    expect(within(ontology).queryByRole('option', {name: 'Nog niet geclassificeerd'})).not.toBeInTheDocument()
    await u.selectOptions(ontology, 'https://brickschema.org/schema/Brick#CO2_Sensor')
    const name = screen.getByLabelText(/Pointnaam/)
    await u.clear(name)
    await u.type(name, 'Aanvoertemperatuur')
    await u.click(screen.getByRole('button', {name: 'Overrides opslaan'}))

    await waitFor(() => {
      const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).includes('/points/p1/overrides'))
      expect(call).toBeDefined()
      expect(JSON.parse(String(call?.[1]?.body))).toMatchObject({
        revision: 1,
        displayName: 'Aanvoertemperatuur',
        ontologyClass: 'https://brickschema.org/schema/Brick#CO2_Sensor',
      })
    })
  })

  it('excludes missing Spaces and Assets from placement targets', async () => {
    const point = makePoint()
    const inventory = makeInventory(point)
    inventory.structures[0].spaces[1].sourceLifecycle = 'missing'
    inventory.structures[0].spaces[1].assets[0].sourceLifecycle = 'missing'
    mockApi(point, inventory)
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    expect(within(screen.getByLabelText('Device en locatie')).queryByText(/Storage controller/)).not.toBeInTheDocument()
    expect(screen.queryByRole('option', {name: /Storage/})).not.toBeInTheDocument()
  })

  it('supports an explicit custom ontology URI through Anders', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    await u.selectOptions(screen.getByLabelText(/Ontologyklasse/), '__custom__')
    await u.type(screen.getByLabelText('Eigen ontology-URI'), 'https://example.com/ontology#Custom_Point')
    await u.click(screen.getByRole('button', {name: 'Overrides opslaan'}))

    await waitFor(() => {
      const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).includes('/points/p1/overrides'))
      expect(JSON.parse(String(call?.[1]?.body)).ontologyClass).toBe(
        'https://example.com/ontology#Custom_Point',
      )
    })
  })

  it('supports keyboard tri-state selection with explicit review', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openOfficeRoom(u)
    const box = await screen.findByRole('checkbox', {name: /Selecteer Office multisensor voor ONE\.OS Cloud/})
    box.focus()
    await u.keyboard('[Space]')
    expect(screen.getByRole('dialog', {name: 'Beoordelen en selecteren'})).toBeInTheDocument()
    await u.click(screen.getByRole('button', {name: 'Beoordelen en selecteren'}))
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/selection/asset/a1'),
        expect.objectContaining({method: 'POST'}),
      ),
    )
  })

  it('traps focus in the selection dialog and restores focus on Escape', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openOfficeRoom(u)
    const trigger = await screen.findByRole('checkbox', {name: /Selecteer Office multisensor voor ONE\.OS Cloud/})
    trigger.focus()
    await u.keyboard('[Space]')
    const dialog = screen.getByRole('dialog', {name: 'Beoordelen en selecteren'})
    expect(dialog).toBeInTheDocument()
    const appRoot = document.getElementById('app-root')
    expect(appRoot).toHaveAttribute('inert')
    await u.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(appRoot).not.toHaveAttribute('inert')
    await waitFor(() => expect(document.activeElement).toBe(trigger))
  })

  it('cycles focus forward and backward with Tab inside the dialog', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openOfficeRoom(u)
    const trigger = await screen.findByRole('checkbox', {name: /Selecteer Office multisensor voor ONE\.OS Cloud/})
    trigger.focus()
    await u.keyboard('[Space]')
    const dialog = screen.getByRole('dialog', {name: 'Beoordelen en selecteren'})
    const buttons = within(dialog).getAllByRole('button')
    const first = buttons[0]
    const last = buttons[buttons.length - 1]
    last.focus()
    await u.tab()
    expect(document.activeElement).toBe(first)
    await u.tab({shift: true})
    expect(document.activeElement).toBe(last)
  })

  it('shows and toggles cloud control when technically controllable', async () => {
    const controllablePoint = makePoint({
      capability: {actions: ['set_temperature'], highRisk: false, technicallyControllable: true, immutable: false},
    })
    mockApi(controllablePoint)
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)
    const toggle = screen.getByRole('button', {name: 'Inschakelen'})
    expect(toggle).not.toBeDisabled()
    await u.click(toggle)
    await waitFor(() => expect(screen.getByRole('button', {name: 'Uitschakelen'})).toBeInTheDocument())
  })

  it('requires accepting a temporary binding before it can proceed', async () => {
    const temporaryPoint = makePoint({bindingStability: 'temporary', temporaryAccepted: false})
    mockApi(temporaryPoint)
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)
    expect(screen.getByText(/tijdelijk en moet expliciet worden geaccepteerd/)).toBeInTheDocument()
    await u.click(screen.getByRole('button', {name: 'Tijdelijke binding accepteren'}))
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/accept-temporary-binding'),
        expect.objectContaining({method: 'POST'}),
      ),
    )
  })

  it('adds a property to the selected point', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)
    await u.type(screen.getByLabelText('Sleutel'), 'note')
    await u.type(screen.getByLabelText('Waarde'), 'hello')
    await u.click(screen.getByRole('button', {name: 'Eigenschap toevoegen'}))
    expect(await screen.findByText('note')).toBeInTheDocument()
  })

  it('renders diagnostics and audit sections', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await u.click(await screen.findByText('Diagnostiek'))
    expect(await screen.findByText('Systeemstatus & audit')).toBeInTheDocument()
    expect(await screen.findByText('0.1.4')).toBeInTheDocument()
  })
})
