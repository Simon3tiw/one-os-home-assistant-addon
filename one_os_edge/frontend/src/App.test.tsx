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
        ],
      },
    ],
    flatPoints: [point],
    counts: {structures: 1, spaces: 1, physicalDevices: 1, assets: 1, points: 1},
  }
}

function mockApi(point = makePoint()) {
  const inventory = makeInventory(point)
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
            softwareVersion: '0.1.3',
            architecture: 'amd64',
            installationHash: 'hash',
            databaseRevision: '0002',
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

async function openDemoPoint(u: ReturnType<typeof userEvent.setup>) {
  await u.click(await screen.findByText('Inventaris & ontologie'))
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
    expect(screen.getByText('Office multisensor')).toBeInTheDocument()
  })

  it('collapses device points by default and toggles them with an accessible disclosure', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await u.click(await screen.findByText('Inventaris & ontologie'))

    const expand = await screen.findByRole('button', {name: 'Uitklappen Office multisensor'})
    expect(expand).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('button', {name: /Demo temperature/})).not.toBeInTheDocument()

    await u.click(expand)
    expect(screen.getByRole('button', {name: 'Inklappen Office multisensor'})).toHaveAttribute('aria-expanded', 'true')
    expect(await screen.findByRole('button', {name: /Demo temperature/})).toBeInTheDocument()

    await u.click(screen.getByRole('button', {name: 'Inklappen Office multisensor'}))
    expect(screen.queryByRole('button', {name: /Demo temperature/})).not.toBeInTheDocument()
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
    const name = screen.getByLabelText(/Weergavenaam/)
    await u.clear(name)
    await u.type(name, 'Supply temperature')
    await u.click(screen.getByRole('button', {name: 'Overrides opslaan'}))
    expect(await screen.findByDisplayValue('Supply temperature')).toBeInTheDocument()
  })

  it('supports keyboard tri-state selection with explicit review', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await u.click(await screen.findByText('Inventaris & ontologie'))
    const box = await screen.findByRole('checkbox', {name: /Selecteer Office multisensor/})
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
    await u.click(await screen.findByText('Inventaris & ontologie'))
    const trigger = await screen.findByRole('checkbox', {name: /Selecteer Office multisensor/})
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
    await u.click(await screen.findByText('Inventaris & ontologie'))
    const trigger = await screen.findByRole('checkbox', {name: /Selecteer Office multisensor/})
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
    expect(await screen.findByText('0.1.3')).toBeInTheDocument()
  })
})
