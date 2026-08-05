import {expect, test} from '@playwright/test'

test('portrait inventory uses the full viewport without clipped horizontal content', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844})
  await page.goto('./')
  await page.getByText('Inventaris & ontologie').click()
  const roomDisclosure = page.getByRole('button', {name: /Ruimte Office uitklappen/})
  const roomTarget = await roomDisclosure.boundingBox()
  expect(roomTarget?.width).toBeGreaterThanOrEqual(44)
  expect(roomTarget?.height).toBeGreaterThanOrEqual(44)
  await roomDisclosure.click()
  await page.locator('.site-row b').evaluate((element) => {
    element.textContent = 'ONE.OS zeer lange Home Assistant sitenaam zonder natuurlijke korte afbreking voor mobiel commissioninggebruik'
  })

  const disclosure = page.getByRole('button', {name: /Uitklappen Office multisensor/})
  await expect(disclosure).toBeVisible()
  await expect(disclosure).toHaveAttribute('aria-expanded', 'false')
  await expect(page.locator('.asset-points')).toHaveCount(0)

  const workspace = page.locator('#inventory')
  await expect(workspace).toBeVisible()
  const layout = await workspace.evaluate((element) => {
    const rect = element.getBoundingClientRect()
    return {
      left: rect.left,
      right: rect.right,
      width: rect.width,
      viewportWidth: document.documentElement.clientWidth,
      pageWidth: document.documentElement.scrollWidth,
    }
  })

  expect(layout.left).toBeGreaterThanOrEqual(0)
  expect(layout.right).toBeLessThanOrEqual(layout.viewportWidth)
  expect(layout.width).toBeGreaterThanOrEqual(layout.viewportWidth - 32)
  expect(layout.pageWidth).toBeLessThanOrEqual(layout.viewportWidth)

  const navigationFits = await page.locator('nav a').evaluateAll((links) =>
    links.every((link) => {
      const rect = link.getBoundingClientRect()
      return rect.left >= 0 && rect.right <= document.documentElement.clientWidth
    }),
  )
  expect(navigationFits).toBe(true)

  const deviceTarget = await disclosure.boundingBox()
  expect(deviceTarget?.width).toBeGreaterThanOrEqual(44)
  expect(deviceTarget?.height).toBeGreaterThanOrEqual(44)
  await disclosure.click()
  const mobilePointSelection = page.getByRole('checkbox', {name: /Includeer Room temperature in ONE.OS Cloud/})
  const mobilePointSelectionTarget = mobilePointSelection.locator('..')
  await expect(mobilePointSelectionTarget).toHaveJSProperty('tagName', 'LABEL')
  const pointSelectionBox = await mobilePointSelectionTarget.boundingBox()
  expect(pointSelectionBox?.width).toBeGreaterThanOrEqual(44)
  expect(pointSelectionBox?.height).toBeGreaterThanOrEqual(44)
  await page.getByRole('button', {name: /Room temperature/}).click()
  const expandedPageWidth = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }))
  expect(expandedPageWidth.scroll).toBeLessThanOrEqual(expandedPageWidth.client)
})

test('isolated non-root commissioning journey against a real backend process', async ({page}) => {
  await page.goto('./')
  await expect(page.getByRole('heading', {name: 'Home Assistant-inventaris'})).toBeVisible()

  await page.getByText('Inventaris & ontologie').click()
  await page.getByRole('button', {name: 'Nu ontdekken'}).click()
  await expect(page.getByText('Ground floor')).toBeVisible()

  await page.getByRole('button', {name: /Ruimte Office uitklappen/}).click()
  await page.getByRole('button', {name: /Uitklappen Office multisensor/}).click()
  await page.getByRole('button', {name: /Room temperature/}).click()
  await expect(page.getByText(/21,24 °C|21,2 °C/).last()).toBeVisible()
  await expect(page.getByText('Temperatuursensor', {exact: true}).first()).toBeVisible()
  await expect(page.getByText('Automatisch afgeleid uit Home Assistant')).toBeVisible()

  const nameField = page.getByLabel(/Pointnaam/)
  await expect(nameField).toBeVisible()
  await nameField.fill('Persistent fixture')
  await page.getByRole('button', {name: 'Overrides opslaan'}).click()
  await expect(page.getByLabel(/Pointnaam/)).toHaveValue('Persistent fixture', {timeout: 15000})

  const pointCloudSelection = page.getByRole('checkbox', {name: /Includeer Persistent fixture in ONE.OS Cloud/})
  await pointCloudSelection.click()
  await expect(page.getByRole('dialog', {name: 'Beoordelen en selecteren'})).toBeVisible()
  await page.getByRole('button', {name: 'Beoordelen en selecteren'}).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  const deviceCloudSelection = page.getByRole('checkbox', {name: /Selecteer Office multisensor voor ONE.OS Cloud/})
  await expect(deviceCloudSelection).not.toBeChecked()
  await expect(deviceCloudSelection).toHaveJSProperty('indeterminate', true)

  // Reload against the same real, still-running backend process: the
  // override, selection and stable Point identity must survive a full
  // browser reload driven entirely by server state (no client cache).
  await page.reload()
  await page.getByText('Inventaris & ontologie').click()
  await page.getByRole('button', {name: /Ruimte Office uitklappen/}).click()
  await page.getByRole('button', {name: /Uitklappen Office multisensor/}).click()
  await expect(page.getByText('Persistent fixture')).toBeVisible()
  const persistedPointSelection = page.getByRole('checkbox', {name: /Includeer Persistent fixture in ONE.OS Cloud/})
  await expect(persistedPointSelection).toBeChecked()
  await persistedPointSelection.click()
  await expect(persistedPointSelection).not.toBeChecked()
  await page.reload()
  await page.getByText('Inventaris & ontologie').click()
  await page.getByRole('button', {name: /Ruimte Office uitklappen/}).click()
  await page.getByRole('button', {name: /Uitklappen Office multisensor/}).click()
  await expect(page.getByRole('checkbox', {name: /Includeer Persistent fixture in ONE.OS Cloud/})).not.toBeChecked()
  await expect(page.getByRole('checkbox', {name: /Selecteer Office multisensor voor ONE.OS Cloud/})).toHaveJSProperty(
    'indeterminate',
    false,
  )
  await page.getByRole('button', {name: /Persistent fixture/}).click()
  await expect(page.getByRole('textbox', {name: /Pointnaam/})).toHaveValue('Persistent fixture')
  await expect(page.getByText('Automatisch afgeleid uit Home Assistant')).toBeVisible()
  await page.getByRole('button', {name: 'Pointnaam terugzetten naar bron'}).click()
  await expect(page.getByRole('textbox', {name: /Pointnaam/})).toHaveValue('Room temperature')

  await page.getByText('Diagnostiek').click()
  await expect(page.getByText('Systeemstatus & audit')).toBeVisible()
  await expect(page.getByRole('cell', {name: 'point.override', exact: true})).toBeVisible()
  await expect(page.getByRole('cell', {name: 'point.override.reset', exact: true})).toBeVisible()
  await expect(page.getByRole('cell', {name: 'selection.bulk'})).toHaveCount(2)
})
