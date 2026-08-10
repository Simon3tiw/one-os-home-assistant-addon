import {cleanup, render, screen} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {afterEach, expect, test, vi} from 'vitest'

import type {ApiClient, PairingStatus} from './api'
import {PairingPanel} from './PairingPanel'

afterEach(cleanup)

function client(initial: PairingStatus) {
  let status = initial
  return {
    pairingStatus: vi.fn(async () => status),
    pairingCode: vi.fn(async () => ({code: '0123-4567-89AB-CDEF-GHJK', expiresAt: '2030-01-01T12:10:00Z'})),
    startPairing: vi.fn(async () => status),
    refreshPairing: vi.fn(async () => {
      status = {...status, status: 'paired'}
      return status
    }),
    resetPairing: vi.fn(async () => undefined),
    cancelPairing: vi.fn(async () => ({...status, status: 'cancelled'})),
    rotatePairingKey: vi.fn(async () => ({...status, status: 'registering'})),
    replaceIdentityAfterRestore: vi.fn(async () => status),
  } as unknown as ApiClient
}

const baseStatus: PairingStatus = {
  installationId: '00000000-0000-4000-8000-000000000002',
  status: 'pop_verified',
  codeExpiresAt: '2030-01-01T12:10:00Z',
}

test('toont pairingcode alleen na expliciete actie en wist hem na terminale refresh', async () => {
  const api = client(baseStatus)
  const user = userEvent.setup()
  render(<PairingPanel client={api} />)

  expect(await screen.findByText('pop_verified')).toBeInTheDocument()
  expect(screen.queryByText('0123-4567-89AB-CDEF-GHJK')).not.toBeInTheDocument()
  await user.click(screen.getByRole('button', {name: 'Pairingcode tonen'}))
  expect(await screen.findByText('0123-4567-89AB-CDEF-GHJK')).toBeInTheDocument()
  await user.click(screen.getByRole('button', {name: 'Status vernieuwen'}))
  expect(await screen.findByText('paired')).toBeInTheDocument()
  expect(screen.queryByText('0123-4567-89AB-CDEF-GHJK')).not.toBeInTheDocument()
})

test('biedt restore uitsluitend als bevestigde repair en verbergt lokale reset', async () => {
  const api = client({...baseStatus, status: 'identity_missing_after_restore'})
  const user = userEvent.setup()
  render(<PairingPanel client={api} />)

  const repair = await screen.findByRole('button', {name: /repair en sleutelrotatie starten/i})
  expect(repair).toBeDisabled()
  await user.click(screen.getByRole('checkbox', {name: /identity vervangen/i}))
  await user.click(repair)
  expect(api.rotatePairingKey).toHaveBeenCalledTimes(1)

  expect(screen.queryByRole('button', {name: 'Lokale pairingstate resetten'})).not.toBeInTheDocument()
  expect(api.resetPairing).not.toHaveBeenCalled()
})

test.each(['paired', 'revoked', 'compromised', 'expired', 'cancelled'])(
  'biedt voor %s uitsluitend een expliciet bevestigde repair/keyrotatie',
  async (pairingStatus) => {
    const api = client({...baseStatus, status: pairingStatus, credentialId: 'credential'})
    const user = userEvent.setup()
    render(<PairingPanel client={api} />)

    const rotate = await screen.findByRole('button', {name: /repair en sleutelrotatie starten/i})
    expect(rotate).toBeDisabled()
    await user.click(screen.getByRole('checkbox', {name: /identity vervangen/i}))
    await user.click(rotate)

    expect(api.rotatePairingKey).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', {name: 'Lokale pairingstate resetten'})).not.toBeInTheDocument()
    expect(screen.queryByText('0123-4567-89AB-CDEF-GHJK')).not.toBeInTheDocument()
  },
)

test.each(['unpaired', 'expired', 'cancelled'])(
  'biedt lokale reset alleen voor niet-identiteitsstate %s',
  async (pairingStatus) => {
    const api = client({...baseStatus, status: pairingStatus, credentialId: undefined})
    const user = userEvent.setup()
    render(<PairingPanel client={api} />)

    const reset = await screen.findByRole('button', {name: 'Lokale pairingstate resetten'})
    expect(reset).toBeDisabled()
    await user.click(screen.getByRole('checkbox', {name: /veilige lokale reset/i}))
    await user.click(reset)
    expect(api.resetPairing).toHaveBeenCalledTimes(1)
  },
)

test('cancel vereist expliciete bevestiging en toont geen serverdetail bij fouten', async () => {
  const api = client(baseStatus)
  vi.mocked(api.cancelPairing).mockRejectedValueOnce(new Error('bootstrapToken=secret'))
  const user = userEvent.setup()
  render(<PairingPanel client={api} />)

  const cancel = await screen.findByRole('button', {name: 'Pairingsessie annuleren'})
  expect(cancel).toBeDisabled()
  await user.click(screen.getByRole('checkbox', {name: /sessie annuleren/i}))
  await user.click(cancel)

  expect(await screen.findByRole('alert')).toHaveTextContent('Pairingactie niet uitgevoerd. Probeer opnieuw.')
  expect(screen.queryByText(/bootstrapToken=secret/)).not.toBeInTheDocument()
})
