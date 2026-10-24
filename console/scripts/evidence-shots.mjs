// Docs screenshots of the explained evidence view (DPAPI, QUIC and DNS rows expanded), against the mock dev server.
// Usage: npm run dev:mock (or BASE_URL=http://localhost:5199 with another port), then
//   CHROMIUM_PATH=… OUT_DIR=website/public/img/console node console/scripts/evidence-shots.mjs
// Writes incident-evidence-dark.png and incident-evidence-light.png.
import { chromium } from 'playwright'
import { mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../../website/public/img/console/', import.meta.url))
mkdirSync(OUT, { recursive: true })
const executablePath = [process.env.CHROMIUM_PATH].filter(Boolean).find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath })

for (const theme of ['dark', 'light']) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 2200 }, deviceScaleFactor: 1, colorScheme: theme })
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
  await page.goto(`${BASE}/incidents?autologin=1&status=open,in_progress,resolved,dismissed&q=ENG-LT-011`, { waitUntil: 'networkidle' })
  await page.waitForSelector('[data-row-id]')
  const id = await page.$$eval('[data-row-id]', (els) => (els.find((el) => el.textContent?.includes('Xeno')) ?? els[0]).getAttribute('data-row-id'))
  await page.goto(`${BASE}/incidents/${id}?autologin=1`, { waitUntil: 'networkidle' })
  await page.getByRole('tab', { name: /Evidence/ }).click()
  for (const text of ['Decrypted the "Chromium" key', 'QUIC (UDP)', 'Resolved pastebin.com']) {
    await page.locator('tr[aria-expanded]', { hasText: text }).first().click()
  }
  await page.waitForTimeout(500)
  const panel = page.locator('[role="tabpanel"][data-state="active"]').first()
  const file = join(OUT, `incident-evidence-${theme}.png`)
  await panel.screenshot({ path: file })
  console.log(file, errors.length ? `ERRORS: ${errors.join(' | ')}` : '')
  await ctx.close()
}
await browser.close()
