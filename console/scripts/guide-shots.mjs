// Step-by-step guide screenshots against a FRESH server (first-run setup included).
// Usage: KESTREL_URL=https://localhost:9443 SETUP_CODE=… ADMIN_EMAIL=… ADMIN_PASSWORD=… \
//        CHROMIUM_PATH=… OUT_DIR=website/public/img/guide DOWNLOAD_DIR=… \
//        node console/scripts/guide-shots.mjs [setup|wizard|devices]
// Writes <step>-dark.png / <step>-light.png. "setup" runs the first-run setup once.
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'

const url = process.env.KESTREL_URL ?? 'https://localhost:9443'
const out = process.env.OUT_DIR ?? 'website/public/img/guide'
const stage = process.argv[2] ?? 'setup'
mkdirSync(out, { recursive: true })
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH })

async function ctxFor(theme) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, colorScheme: theme, acceptDownloads: true })
  await ctx.addInitScript((t) => { try { localStorage.setItem('kestrel-theme', t) } catch {} }, theme)
  return ctx
}
async function shot(page, name, theme, opts = {}) {
  await page.waitForTimeout(700)
  await page.screenshot({ path: `${out}/${name}-${theme}.png`, ...opts })
  console.log('shot', name, theme)
}
async function login(page) {
  await page.goto(`${url}/`, { waitUntil: 'networkidle' })
  await page.fill('#email', process.env.ADMIN_EMAIL)
  await page.fill('#password', process.env.ADMIN_PASSWORD)
  await page.getByRole('button', { name: /sign in/i }).click()
  await page.getByText('Overview', { exact: true }).first().waitFor({ timeout: 30000 })
  await page.waitForTimeout(1500)
}

if (stage === 'setup') {
  // The setup form, filled in, in both themes; then create the organisation once.
  let setupPage
  for (const theme of ['dark', 'light']) {
    const ctx = await ctxFor(theme)
    const page = await ctx.newPage()
    await page.goto(`${url}/`, { waitUntil: 'networkidle' })
    await page.fill('#setup-code', process.env.SETUP_CODE)
    await page.fill('#org', 'Harbourline Logistics')
    await page.fill('#name', 'Priya Raman')
    await page.fill('#setup-email', process.env.ADMIN_EMAIL)
    await page.fill('#setup-pw', process.env.ADMIN_PASSWORD)
    await page.fill('#setup-pw2', process.env.ADMIN_PASSWORD)
    await shot(page, '01-setup', theme)
    if (theme === 'light') setupPage = page
    else await ctx.close()
  }
  await setupPage.getByRole('button', { name: /create organisation/i }).click()
  await setupPage.getByText('Overview', { exact: true }).first().waitFor({ timeout: 30000 })
  console.log('organisation created')
}

if (stage === 'setup' || stage === 'wizard') {
  for (const theme of ['dark', 'light']) {
    const ctx = await ctxFor(theme)
    const page = await ctx.newPage()
    await login(page)
    await shot(page, '02-overview-empty', theme)
    await page.goto(`${url}/devices`, { waitUntil: 'networkidle' })
    await shot(page, '03-devices-empty', theme)
    await page.getByRole('button', { name: /install agent/i }).first().click()
    await page.waitForTimeout(1000)
    await shot(page, '04-wizard-profile', theme)
    await page.getByRole('button', { name: /^next$/i }).click()
    await page.waitForTimeout(800)
    await shot(page, '05-wizard-guardrails', theme)
    await page.getByRole('button', { name: /^next$/i }).click()
    await page.waitForTimeout(800)
    await shot(page, '06-wizard-token', theme)
    // Create the token (button text varies: Create / Create installer / Create token).
    await page.getByRole('button', { name: /^create/i }).last().click()
    await page.waitForTimeout(2500)
    await shot(page, '07-wizard-result', theme)
    if (theme === 'dark' && process.env.DOWNLOAD_DIR) {
      const dl = page.waitForEvent('download', { timeout: 15000 })
      await page.getByRole('button', { name: /download/i }).first().click()
      const d = await dl
      const target = `${process.env.DOWNLOAD_DIR}/${d.suggestedFilename()}`
      await d.saveAs(target)
      console.log('downloaded', target)
    }
    await ctx.close()
  }
}

if (stage === 'devices') {
  for (const theme of ['dark', 'light']) {
    const ctx = await ctxFor(theme)
    const page = await ctx.newPage()
    await login(page)
    await page.goto(`${url}/devices`, { waitUntil: 'networkidle' })
    await page.waitForTimeout(1500)
    await shot(page, '12-devices-online', theme)
    const first = page.locator('table tbody tr').first()
    if (await first.count()) {
      await first.click()
      await page.waitForTimeout(2500)
      await shot(page, '13-device-page', theme)
    }
    await ctx.close()
  }
}
await browser.close()
