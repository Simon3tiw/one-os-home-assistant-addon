import {useEffect, useState} from 'react'

import type {ApiClient, PairingStatus} from './api'

const terminalStatuses = new Set([
  'paired',
  'revoked',
  'compromised',
  'cancelled',
  'expired',
  'failed',
  'identity_missing_after_restore',
])
const repairStatuses = new Set([
  'paired',
  'revoked',
  'compromised',
  'cancelled',
  'expired',
  'identity_missing_after_restore',
])
const resetStatuses = new Set(['unpaired', 'cancelled', 'expired'])
const cancellableStatuses = new Set(['registered', 'pop_verified', 'claimed'])

export function PairingPanel({client}: {client: ApiClient}) {
  const [status, setStatus] = useState<PairingStatus | null>(null)
  const [code, setCode] = useState<{value: string; expiresAt: string} | null>(null)
  const [confirmedReset, setConfirmedReset] = useState(false)
  const [confirmedCancel, setConfirmedCancel] = useState(false)
  const [confirmedRepair, setConfirmedRepair] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const identityBearing = Boolean(
    status?.credentialId
    || status?.certificateSha256
    || ['paired', 'revoked', 'compromised', 'identity_missing_after_restore'].includes(status?.status ?? ''),
  )

  async function loadStatus() {
    const next = await client.pairingStatus()
    setStatus(next)
    if (terminalStatuses.has(next.status)) setCode(null)
    return next
  }

  useEffect(() => {
    let active = true
    client.pairingStatus()
      .then((next) => {
        if (active) setStatus(next)
      })
      .catch(() => {
        if (active) setError('Pairingstatus kon niet veilig worden geladen.')
      })
    return () => {
      active = false
      setCode(null)
    }
  }, [client])

  async function action(operation: () => Promise<PairingStatus | void>) {
    setBusy(true)
    setError('')
    try {
      const next = await operation()
      setCode(null)
      setConfirmedReset(false)
      setConfirmedCancel(false)
      setConfirmedRepair(false)
      if (next) setStatus(next)
      else await loadStatus()
    } catch {
      setCode(null)
      setError('Pairingactie niet uitgevoerd. Probeer opnieuw.')
    } finally {
      setBusy(false)
    }
  }

  async function showCode() {
    setBusy(true)
    setError('')
    try {
      const next = await client.pairingCode()
      setCode({value: next.code, expiresAt: next.expiresAt})
    } catch {
      setCode(null)
      setError('Pairingcode kon niet veilig worden geladen.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="pairing-panel" aria-labelledby="edge-pairing-title">
      <div className="eyebrow">BEVEILIGDE DEVICE-IDENTITEIT</div>
      <h2 id="edge-pairing-title">Edge pairing</h2>
      <p>De pairingcode wordt alleen op verzoek getoond en blijft uitsluitend tijdelijk in deze pagina.</p>
      {error && <p role="alert">{error}</p>}
      {!status ? (
        <p aria-busy="true">Pairingstatus laden…</p>
      ) : (
        <>
          <dl>
            <div><dt>Status</dt><dd>{status.status}</dd></div>
            <div><dt>Installation</dt><dd>{status.installationId}</dd></div>
            {status.tenantId && <div><dt>Tenant</dt><dd>{status.tenantId}</dd></div>}
            {status.siteId && <div><dt>Site</dt><dd>{status.siteId}</dd></div>}
            {status.credentialId && <div><dt>Credential</dt><dd>{status.credentialId}</dd></div>}
            {status.certificateSha256 && <div><dt>Certificaatfingerprint</dt><dd>{status.certificateSha256}</dd></div>}
            {status.certificateNotAfter && <div><dt>Certificaat geldig tot</dt><dd>{status.certificateNotAfter}</dd></div>}
          </dl>

          {code && (
            <div role="status" className="pairing-code">
              <strong className="pairing-code-value">{code.value}</strong>
              <span>Geldig tot {code.expiresAt}</span>
            </div>
          )}

          <div className="destination-actions">
            {status.status === 'unpaired' && (
              <button type="button" disabled={busy} onClick={() => action(() => client.startPairing())}>
                Initial pairing starten
              </button>
            )}
            {status.status === 'pop_verified' && (
              <button type="button" disabled={busy} onClick={showCode}>Pairingcode tonen</button>
            )}
            {!terminalStatuses.has(status.status) && (
              <button type="button" disabled={busy} onClick={() => action(() => client.refreshPairing())}>
                Status vernieuwen
              </button>
            )}
            {repairStatuses.has(status.status) && identityBearing && (
              <>
                <label>
                  <input
                    type="checkbox"
                    checked={confirmedRepair}
                    onChange={(event) => setConfirmedRepair(event.target.checked)}
                  />
                  Ik bevestig identity vervangen; de oude identity blijft behouden tot de nieuwe ACK slaagt.
                </label>
                <button
                  type="button"
                  disabled={busy || !confirmedRepair}
                  onClick={() => action(() => client.rotatePairingKey())}
                >
                  Repair en sleutelrotatie starten
                </button>
              </>
            )}
            {cancellableStatuses.has(status.status) && (
              <>
                <label>
                  <input
                    type="checkbox"
                    checked={confirmedCancel}
                    onChange={(event) => setConfirmedCancel(event.target.checked)}
                  />
                  Ik bevestig sessie annuleren.
                </label>
                <button
                  type="button"
                  disabled={busy || !confirmedCancel}
                  onClick={() => action(() => client.cancelPairing())}
                >
                  Pairingsessie annuleren
                </button>
              </>
            )}
          </div>

          {resetStatuses.has(status.status) && !identityBearing && (
            <div className="danger-zone">
              <label>
                <input
                  type="checkbox"
                  checked={confirmedReset}
                  onChange={(event) => setConfirmedReset(event.target.checked)}
                />
                Ik bevestig de veilige lokale reset van deze niet-identiteitsstate.
              </label>
              <button
                type="button"
                disabled={busy || !confirmedReset}
                onClick={() => action(() => client.resetPairing())}
              >
                Lokale pairingstate resetten
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}
