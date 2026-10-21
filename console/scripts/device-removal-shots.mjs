// Docs screenshots for "Remove device" (remote uninstall), against the mock dev server.
// Usage: npm run dev:mock (or BASE_URL=http://localhost:5199 with another port), then
//   CHROMIUM_PATH=… OUT_DIR=website/public/img/console node console/scripts/device-removal-shots.mjs
// Writes device-remove-dialog-* and devices-removal-* in dark and light.
import { chromium } from 'playwright'
import { mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../../website/public/img/console/', import.meta.url))
mkdirSync(OUT, { recursive: true })
const executablePath = [process.env.CHROMIUM_PATH].filter(Boolean).find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath })

async function shoot(theme, name, prepare) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: theme })
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
  await page.waitForTimeout(500)
  await prepare(page)
  await page.waitForTimeout(600)
  const file = join(OUT, `${name}-${theme}.png`)
  await page.screenshot({ path: file })
  console.log(file, errors.length ? `ERRORS: ${errors.join(' | ')}` : '')
  await ctx.close()
}

for (const theme of ['dark', 'light']) {
  await shoot(theme, 'device-remove-dialog', async (page) => {
    // An online laptop with a current agent (announces agent.uninstall).
    await page.goto(`${BASE}/devices?autologin=1&q=SAL-LT-011`, { waitUntil: 'networkidle' })
    await page.click('[data-row-id] >> nth=0 >> td >> nth=0')
    await page.waitForSelector('text=Danger zone')
    await page.getByRole('button', { name: 'Remove device', exact: true }).click()
    await page.waitForSelector('#remove-host')
    await page.fill('#remove-host', 'sal-lt-011')
    await page.fill('#remove-comment', 'Laptop returned to IT, ticket IT-4502')
  })
  await shoot(theme, 'devices-removal', async (page) => {
    await page.goto(`${BASE}/devices?autologin=1&q=MKT&removed=1`, { waitUntil: 'networkidle' })
    await page.waitForSelector('text=MKT-LT-014')
  })
}
await browser.close()
