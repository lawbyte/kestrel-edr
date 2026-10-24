// Docs screenshots for evidence capture (ST-02 / ST-04), against the mock dev server.
// Usage: npm run dev:mock (or BASE_URL=http://localhost:5199 with another port), then
//   CHROMIUM_PATH=… OUT_DIR=website/public/img/console node console/scripts/screenshots-evidence.mjs
// Downloads ask for the MFA step-up once in the mock. Writes evidence-panel-*, evidence-collect-*, evidence-password-* and evidence-policy-* in dark and light.
import { chromium } from 'playwright'
import { mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../../website/public/img/console/', import.meta.url))
mkdirSync(OUT, { recursive: true })
const executablePath = [process.env.CHROMIUM_PATH].filter(Boolean).find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath })

/** Incident ids holding a stored bundle and a ready (no error) bundle, read from the mock API inside the page. */
async function findIncidents(page) {
  return page.evaluate(async () => {
    const r = await fetch('/api/incidents?limit=500&status=open,in_progress,resolved,dismissed')
    const list = (await r.json()).items
    const out = {}
    for (const i of list) {
      const ev = (await (await fetch(`/api/incidents/${i.id}/evidence`)).json()).items
      if (!out.stored && ev.some((b) => b.status === 'stored')) out.stored = i.id
      if (!out.ready && ev.some((b) => b.status === 'ready_on_device' && !b.last_error)) out.ready = i.id
    }
    return out
  })
}

/** ONLY=evidence-collect,evidence-password re-takes just those shots. */
const ONLY = process.env.ONLY ? process.env.ONLY.split(',') : null

async function shoot(theme, name, prepare, { height = 900, element } = {}) {
  if (ONLY && !ONLY.includes(name)) return
  const ctx = await browser.newContext({ viewport: { width: 1440, height }, deviceScaleFactor: 1, colorScheme: theme })
  await ctx.addInitScript((t) => {
    try {
      localStorage.setItem('kestrel-theme', t)
      sessionStorage.setItem('kestrel-demo-banner', '0')
    } catch {
      /* ignore */
    }
  }, theme)
  const page = await ctx.newPage()
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.goto(`${BASE}/?autologin=1`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(400)
  const ids = await findIncidents(page)
  const target = await prepare(page, ids)
  await page.waitForTimeout(600)
  const file = join(OUT, `${name}-${theme}.png`)
  if (element || target) await (target ?? page.locator(element)).screenshot({ path: file })
  else await page.screenshot({ path: file })
  console.log(file, errors.length ? `ERRORS: ${errors.join(' | ')}` : '')
  await ctx.close()
}

const panel = (page) => page.locator('section[aria-label="Evidence capture"]')

for (const theme of ['dark', 'light']) {
  // Stored bundle expanded: summary, secrets, staged files, capture.
  await shoot(
    theme,
    'evidence-panel',
    async (page, ids) => {
      await page.goto(`${BASE}/incidents/${ids.stored}?autologin=1`, { waitUntil: 'networkidle' })
      const p = panel(page)
      await p.waitFor()
      await p.locator('button[aria-expanded="false"]').first().click()
      await p.getByRole('region', { name: 'Secrets it read' }).waitFor()
      await p.scrollIntoViewIfNeeded()
      return p
    },
    { height: 2600 },
  )
  // Bundle on the PC with the Collect confirmation.
  await shoot(theme, 'evidence-collect', async (page, ids) => {
    await page.goto(`${BASE}/incidents/${ids.ready}?autologin=1`, { waitUntil: 'networkidle' })
    const p = panel(page)
    await p.waitFor()
    await p.scrollIntoViewIfNeeded()
    await p.getByRole('button', { name: /Collect evidence/ }).first().click()
    await page.getByRole('dialog').waitFor()
  })
  // Download: the password shown once.
  await shoot(theme, 'evidence-password', async (page, ids) => {
    await page.goto(`${BASE}/incidents/${ids.stored}?autologin=1`, { waitUntil: 'networkidle' })
    const p = panel(page)
    await p.waitFor()
    await p.scrollIntoViewIfNeeded()
    await p.getByRole('button', { name: /^Download$/ }).click()
    await page.getByRole('button', { name: /Create download/ }).click()
    // The mock admin has MFA: confirm a code once (any 6 digits except 000000).
    const code = page.getByLabel('Authenticator code')
    if (await code.waitFor({ timeout: 3000 }).then(() => true, () => false)) {
      await code.fill('123456')
      await page.getByRole('button', { name: /Confirm/ }).click()
    }
    await page.getByLabel('Archive password').waitFor()
  })
  // Policy section.
  await shoot(
    theme,
    'evidence-policy',
    async (page) => {
      await page.goto(`${BASE}/policies/pol-default?autologin=1`, { waitUntil: 'networkidle' })
      const s = page.locator('section#evidence')
      await s.waitFor()
      await s.scrollIntoViewIfNeeded()
      return s
    },
    { height: 1400 },
  )
}
await browser.close()
