import {afterEach, describe, expect, it, vi} from 'vitest'
import {cleanup, render, screen, waitFor, within} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {App} from './App'
import {ApiClient, parseCentralDiscoveryResult} from './api'

describe('Central discovery runtime contract', () => {
  const base = {
    status: 'reachable',
    revision: 1,
    service: 'one-os-central',
    schemaVersion: '1.0',
  }

  it.each([
    {pairingSupported: false, phase: '2B.1-sandbox-foundation'},
    {pairingSupported: true, phase: '2B.2-secure-pairing'},
    {pairingSupported: true, phase: '2B.3-selected-configuration-sync'},
  ])('accepts a closed valid capability tuple', (capability) => {
    expect(parseCentralDiscoveryResult({...base, ...capability})).toEqual({...base, ...capability})
  })

  it.each([
    {...base, pairingSupported: false, phase: '2B.3-selected-configuration-sync'},
    {...base, pairingSupported: true, phase: '2B.1-sandbox-foundation'},
    {...base, pairingSupported: true, phase: '2B.3-selected-configuration-sync', extra: true},
    {...base, revision: -1, pairingSupported: true, phase: '2B.3-selected-configuration-sync'},
    {...base, service: 'other', pairingSupported: true, phase: '2B.3-selected-configuration-sync'},
  ])('rejects malformed or mismatched discovery', (document) => {
    expect(() => parseCentralDiscoveryResult(document)).toThrow('central_discovery_protocol_error')
  })
})

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

function mockApi(
  point = makePoint(),
  inventory = makeInventory(point),
  destinationTestDelay?: Promise<void>,
) {
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
            phaseNotice: 'Secure pairing and configuration sync are active; telemetry follows in Phase 2C',
            database: 'healthy',
          }),
        )
      if (url.endsWith('/inventory')) return new Response(JSON.stringify(inventory))
      if (url.endsWith('/pairing/status')) {
        return new Response(JSON.stringify({installationId: 'installation-test', status: 'unpaired'}))
      }
      if (url.endsWith('/central-destination')) {
        if (method === 'PUT') {
          const body = JSON.parse(String(init?.body))
          return new Response(JSON.stringify({
            configured: true,
            revision: 1,
            origin: body.origin,
            certificateFingerprint: body.certificateFingerprint.replaceAll(':', '').toLowerCase(),
            configuredAt: '2026-08-05T12:00:00+00:00',
            status: 'configured',
          }))
        }
        return new Response(JSON.stringify({
          configured: false,
          revision: 0,
          origin: null,
          certificateFingerprint: null,
          configuredAt: null,
          status: 'not_configured',
        }))
      }
      if (url.endsWith('/central-destination/test')) {
        await destinationTestDelay
        return new Response(
          JSON.stringify({
            status: 'reachable',
            revision: 1,
            service: 'one-os-central',
            schemaVersion: '1.0',
            pairingSupported: true,
            phase: '2B.3-selected-configuration-sync',
          }),
        )
      }
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
            softwareVersion: '0.4.1',
            architecture: 'amd64',
            installationHash: 'hash',
            databaseRevision: '0004',
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
  it('sends Point override resets as authenticated JSON mutations', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(new Response(JSON.stringify({csrfToken: 'csrf-reset'})))
        .mockResolvedValueOnce(new Response(JSON.stringify(makePoint()))),
    )
    const client = new ApiClient()
    await client.init()

    await client.resetOverride('p1', 'displayName', 2)

    const [, init] = vi.mocked(fetch).mock.calls[1]
    const headers = new Headers(init?.headers)
    expect(init?.method).toBe('DELETE')
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('X-CSRF-Token')).toBe('csrf-reset')
  })

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

  it('keeps the loaded inventory visible when a placement mutation fails', async () => {
    mockApi()
    const regularFetch = vi.mocked(fetch).getMockImplementation()!
    vi.mocked(fetch).mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes('/assets/a1')) {
        return new Response(JSON.stringify({error: {code: 'same_origin_required'}}), {status: 403})
      }
      return regularFetch(input, init)
    })
    const u = userEvent.setup()
    render(<App />)
    await openOfficeRoom(u)
    await u.click(screen.getByRole('button', {name: 'Uitklappen Office multisensor'}))
    await u.selectOptions(screen.getByLabelText('Ruimte voor device Office multisensor'), 'sp2')

    expect(await screen.findByRole('alert')).toHaveTextContent('same_origin_required')
    expect(screen.getByRole('heading', {name: 'Inventaris'})).toBeInTheDocument()
    expect(screen.queryByRole('heading', {name: 'Kan commissioning-gegevens niet laden'})).not.toBeInTheDocument()
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

  it('includes an individual Point in ONE.OS Cloud through its own checkbox', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)
    await openDemoPoint(u)

    await u.click(screen.getByRole('checkbox', {name: 'Includeer Demo temperature in ONE.OS Cloud'}))
    expect(screen.getByRole('dialog', {name: 'Beoordelen en selecteren'})).toBeInTheDocument()
    await u.click(screen.getByRole('button', {name: 'Beoordelen en selecteren'}))

    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/selection/point/p1'),
        expect.objectContaining({method: 'POST'}),
      ),
    )
    const call = vi.mocked(fetch).mock.calls.find(([url]) => String(url).includes('/selection/point/p1'))
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({intent: 'include', review: true})
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
    expect(await screen.findByText('0.4.1')).toBeInTheDocument()
  })

  it('configures and tests the pinned ONE.OS Central destination in Dutch', async () => {
    mockApi()
    const u = userEvent.setup()
    render(<App />)

    await u.click(await screen.findByText('ONE.OS Central'))
    expect(await screen.findByText('Niet geconfigureerd')).toBeInTheDocument()
    expect(await screen.findByRole('heading', {name: 'Edge pairing'})).toBeInTheDocument()
    expect(await screen.findByText('unpaired')).toBeInTheDocument()
    await u.type(screen.getByLabelText('Serveradres'), 'https://central.example:8443')
    await u.type(screen.getByLabelText('Certificaatfingerprint (SHA-256)'), 'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA')
    await u.click(screen.getByRole('button', {name: 'Bestemming opslaan'}))

    expect(await screen.findByText('Geconfigureerd')).toBeInTheDocument()
    await u.click(screen.getByRole('button', {name: 'Verbinding testen'}))
    expect(await screen.findByText('Bereikbaar')).toBeInTheDocument()

    const serverAddress = screen.getByLabelText('Serveradres')
    await u.clear(serverAddress)
    await u.type(serverAddress, 'https://unsaved.example:8443')
    expect(await screen.findByText('Niet opgeslagen')).toBeInTheDocument()
    expect(screen.getByRole('button', {name: 'Verbinding testen'})).toBeDisabled()

    const putCall = vi.mocked(fetch).mock.calls.find(([url, init]) =>
      String(url).endsWith('/central-destination') && init?.method === 'PUT',
    )
    expect(JSON.parse(String(putCall?.[1]?.body))).toMatchObject({
      revision: 0,
      origin: 'https://central.example:8443',
    })
    expect(vi.mocked(fetch).mock.calls.some(([url]) => String(url).includes('/inventory/publish'))).toBe(false)
  })

  it('locks destination drafts while a connection test is pending', async () => {
    let releaseTest: () => void = () => {}
    const pendingTest = new Promise<void>((resolve) => {
      releaseTest = resolve
    })
    const point = makePoint()
    mockApi(point, makeInventory(point), pendingTest)
    const u = userEvent.setup()
    render(<App />)

    await u.click(await screen.findByText('ONE.OS Central'))
    await u.type(screen.getByLabelText('Serveradres'), 'https://central.example:8443')
    await u.type(screen.getByLabelText('Certificaatfingerprint (SHA-256)'), 'AA'.repeat(32))
    await u.click(screen.getByRole('button', {name: 'Bestemming opslaan'}))

    const pendingClick = u.click(screen.getByRole('button', {name: 'Verbinding testen'}))
    await waitFor(() => expect(screen.getByLabelText('Serveradres')).toBeDisabled())
    expect(screen.getByLabelText('Certificaatfingerprint (SHA-256)')).toBeDisabled()

    releaseTest()
    await pendingClick
    expect(await screen.findByText('Bereikbaar')).toBeInTheDocument()
    expect(screen.getByLabelText('Serveradres')).not.toBeDisabled()
  })

  it('uses the authenticated JSON mutation helper for destination PUT', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn()
        .mockResolvedValueOnce(new Response(JSON.stringify({csrfToken: 'csrf-destination'})))
        .mockResolvedValueOnce(new Response(JSON.stringify({configured: true, revision: 1}))),
    )
    const client = new ApiClient()
    await client.init()
    await client.saveCentralDestination(0, 'https://central.example', 'aa'.repeat(32))

    const [, init] = vi.mocked(fetch).mock.calls[1]
    expect(init?.method).toBe('PUT')
    expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe('csrf-destination')
    expect(new Headers(init?.headers).get('Content-Type')).toBe('application/json')
  })
})
