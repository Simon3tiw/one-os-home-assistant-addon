import {expect, test} from '@playwright/test'

test('isolated non-root commissioning journey against a real backend process', async ({page}) => {
  await page.goto('./')
  await expect(page.getByRole('heading', {name: 'Home Assistant-inventaris'})).toBeVisible()

  await page.getByText('Inventaris & ontologie').click()
  await page.getByRole('button', {name: 'Nu ontdekken'}).click()
  await expect(page.getByText('Ground floor')).toBeVisible()

  await page.getByRole('button', {name: /Room temperature/}).click()
  await expect(page.getByText(/21,24 °C|21,2 °C/).last()).toBeVisible()

  const nameField = page.getByLabel(/Weergavenaam/)
  await nameField.fill('Persistent fixture')
  await page.getByRole('button', {name: 'Overrides opslaan'}).click()
  await expect(page.getByLabel(/Weergavenaam/)).toHaveValue('Persistent fixture')

  await page.getByRole('checkbox', {name: /Selecteer Office multisensor/}).click()
  await expect(page.getByRole('dialog', {name: 'Beoordelen en selecteren'})).toBeVisible()
  await page.getByRole('button', {name: 'Beoordelen en selecteren'}).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)

  // Reload against the same real, still-running backend process: the
  // override, selection and stable Point identity must survive a full
  // browser reload driven entirely by server state (no client cache).
  await page.reload()
  await page.getByText('Inventaris & ontologie').click()
  await expect(page.getByText('Persistent fixture')).toBeVisible()
  await page.getByRole('button', {name: /Persistent fixture/}).click()
  await expect(page.getByLabel(/Weergavenaam/)).toHaveValue('Persistent fixture')

  await page.getByText('Diagnostiek').click()
  await expect(page.getByText('Systeemstatus & audit')).toBeVisible()
  await expect(page.getByRole('cell', {name: 'point.override'})).toBeVisible()
  await expect(page.getByRole('cell', {name: 'selection.bulk'})).toBeVisible()
})
