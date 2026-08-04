export type Provenance = {value: string | null; provenance: string}

export type Point = {
  id: string
  revision: number
  assetId: string
  source: {registryId: string; stableKey: string}
  sourceLifecycle: string
  reviewStatus: string
  selectionIntent: string
  effectiveSelected: boolean
  valueQuality: string
  cloudControlEnabled: boolean
  capabilityReviewRequired: boolean
  bindingStability: string
  temporaryAccepted: boolean
  placementOverride: boolean
  placementConflict: boolean
  display: {
    name: {value: string; provenance: string}
    unit: Provenance
    decimals: {value: number | null; provenance: string}
  }
  value: {raw: string; formatted: string; quality: string; updatedAt: string | null}
  capability: {
    actions: string[]
    highRisk: boolean
    technicallyControllable: boolean
    immutable: boolean
  }
}

export type Asset = {
  id: string
  name: string
  type: string
  revision: number
  sourceLifecycle: string
  placementOverride: boolean
  placementConflict: boolean
  selectionState: 'selected' | 'partial' | 'unselected'
  physicalDeviceId: string | null
  points: Point[]
}

export type Space = {
  id: string
  name: string
  type: string
  revision: number
  sourceLifecycle: string
  selectionState: 'selected' | 'partial' | 'unselected'
  assets: Asset[]
}

export type Structure = {
  id: string
  name: string
  type: string
  revision: number
  sourceLifecycle: string
  selectionState: 'selected' | 'partial' | 'unselected'
  spaces: Space[]
}

export type Inventory = {
  structures: Structure[]
  flatPoints: Point[]
  counts: Record<string, number>
}

export type Overview = {
  connectorPresence: string
  lastSync: string | null
  counts: Record<string, number>
  phaseNotice: string
  database: string
}

export type Property = {
  id: string
  revision: number
  ownerKind: string
  ownerId: string
  key: string
  valueType: string
  value: unknown
}

export type AuditEntry = {
  actorId: string
  at: string
  action: string
  objectId: string
  revision: number
  fields: string[]
}

export type Diagnostics = {
  schemaVersion: string
  softwareVersion: string
  architecture: string
  installationHash: string
  databaseRevision: string
  connectorPresence: string
  lastSync: {at: string | null; status: string}
  counts: Record<string, number>
  storage: {auditRecords: number; configurationBytes: number}
}

const base = (path: string) => `./api/v1${path}`

export class ApiClient {
  private csrfToken = ''

  constructor(private onUnauthorized?: () => void) {}

  async init(): Promise<void> {
    const session = await this.get<{csrfToken: string}>('/session')
    this.csrfToken = session.csrfToken
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(base(path), init)
    if (response.status === 401 || response.status === 403) {
      this.onUnauthorized?.()
    }
    if (!response.ok) {
      const body = await response.json().catch(() => ({}))
      const code = body?.detail?.code ?? body?.error?.code ?? `HTTP ${response.status}`
      throw new Error(code)
    }
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>(path)
  }

  private mutating<T>(path: string, method: string, body?: unknown): Promise<T> {
    return this.request<T>(path, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': this.csrfToken,
        'Sec-Fetch-Site': 'same-origin',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  }

  post<T>(path: string, body?: unknown): Promise<T> {
    return this.mutating<T>(path, 'POST', body)
  }

  patch<T>(path: string, body?: unknown): Promise<T> {
    return this.mutating<T>(path, 'PATCH', body)
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>(path, {
      method: 'DELETE',
      headers: {'X-CSRF-Token': this.csrfToken, 'Sec-Fetch-Site': 'same-origin'},
    })
  }

  overview() {
    return this.get<Overview>('/overview')
  }

  inventory() {
    return this.get<Inventory>('/inventory')
  }

  point(id: string) {
    return this.get<Point>(`/points/${id}`)
  }

  reconcile() {
    return this.post('/reconcile', {})
  }

  select(kind: string, id: string, intent: string, review: boolean) {
    return this.post<{state: string}>(`/selection/${kind}/${id}`, {intent, review})
  }

  overrides(
    pointId: string,
    revision: number,
    body: {
      displayName?: string
      displayUnit?: string
      decimals?: number
      ontologyClass?: string
      tags?: string[]
    },
  ) {
    return this.patch<Point>(`/points/${pointId}/overrides`, {revision, ...body})
  }

  resetOverride(pointId: string, field: string, revision: number) {
    return this.delete<Point>(`/points/${pointId}/overrides/${field}?revision=${revision}`)
  }

  control(pointId: string, revision: number, enabled: boolean) {
    return this.patch<Point>(`/points/${pointId}/control`, {revision, enabled})
  }

  movePoint(pointId: string, revision: number, assetId: string) {
    return this.patch<Point>(`/points/${pointId}/placement`, {revision, assetId})
  }

  acceptTemporaryBinding(pointId: string, revision: number) {
    return this.post<Point>(`/points/${pointId}/accept-temporary-binding`, {revision})
  }

  updateAsset(
    assetId: string,
    revision: number,
    body: {name?: string; type?: string; spaceId?: string},
  ) {
    return this.patch(`/assets/${assetId}`, {revision, ...body})
  }

  splitAsset(assetId: string, revision: number, name: string, pointIds: string[]) {
    return this.post<{assetId: string}>(`/assets/${assetId}/split`, {revision, name, pointIds})
  }

  mergeAsset(assetId: string, revision: number, otherAssetId: string) {
    return this.post<{assetId: string}>(`/assets/${assetId}/merge`, {revision, otherAssetId})
  }

  properties(kind: string, ownerId: string) {
    return this.get<Property[]>(`/properties/${kind}/${ownerId}`)
  }

  createProperty(kind: string, ownerId: string, key: string, valueType: string, value: unknown) {
    return this.post<Property>(`/properties/${kind}/${ownerId}`, {key, valueType, value})
  }

  updateProperty(propertyId: string, revision: number, valueType: string, value: unknown) {
    return this.patch<Property>(`/properties/${propertyId}`, {revision, valueType, value})
  }

  deleteProperty(propertyId: string, revision: number) {
    return this.delete(`/properties/${propertyId}?revision=${revision}`)
  }

  audit() {
    return this.get<AuditEntry[]>('/audit')
  }

  diagnostics() {
    return this.get<Diagnostics>('/diagnostics/export')
  }

  archivePreview(kind: string, id: string) {
    return this.get<{activeDescendants: number; allowedActions: string[]}>(
      `/lifecycle/${kind}/${id}/archive-preview`,
    )
  }

  archive(kind: string, id: string, revision: number, action: 'rehome' | 'cascade') {
    return this.post(`/lifecycle/${kind}/${id}/archive`, {revision, action})
  }
}
