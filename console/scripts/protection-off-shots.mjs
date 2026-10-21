// Docs screenshots for the local "turn protection off" feature, against the mock dev server.
// Usage: npm run dev:mock (or BASE_URL=http://localhost:5199 with another port), then
//   CHROMIUM_PATH=… OUT_DIR=website/public/img/console node console/scripts/protection-off-shots.mjs
// Writes device-protection-off-*, policy-local-turnoff-* and devices-paused-* in dark and light.
import { chromium } from 'playwright'
import { mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../../website/public/img/console/', import.meta.url))
mkdirSync(OUT, { recursive: true })
const executablePath = [process.env.CHROMIUM_PATH].filter(Boolean).find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath })

async function shoot(theme, name, prepare, clip) {
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
  await page.screenshot({ path: file, ...(clip ? { clip: await clip(page) } : {}) })
  console.log(file, errors.length ? `ERRORS: ${errors.join(' | ')}` : '')
  await ctx.close()
}

const openDevice = async (page) => {
  await page.goto(`${BASE}/devices?autologin=1&status=paused`, { waitUntil: 'networkidle' })
  await page.click('[data-row-id] >> nth=0 >> td >> nth=0')
  await page.waitForSelector('text=Sensor health')
}

for (const theme of ['dark', 'light']) {
  await shoot(theme, 'device-protection-off', openDevice)
  await shoot(theme, 'devices-paused', async (page) => {
    await page.goto(`${BASE}/devices?autologin=1&q=MKT`, { waitUntil: 'networkidle' })
    await page.waitForSelector('[data-row-id]')
  })
  await shoot(
    theme,
    'policy-local-turnoff',
    async (page) => {
      await page.goto(`${BASE}/policies/pol-default?autologin=1`, { waitUntil: 'networkidle' })
      await page.waitForSelector('#local-pause')
      await page.$eval('#local-pause', (el) => el.scrollIntoView({ block: 'start' }))
      await page.waitForTimeout(300)
    },
    async (page) => {
      const b = await page.$eval('#local-pause', (el) => {
        const r = el.getBoundingClientRect()
        return { x: r.x, y: r.y, width: r.width, height: r.height }
      })
      return { x: Math.max(0, b.x - 24), y: Math.max(0, b.y - 16), width: Math.min(1440 - Math.max(0, b.x - 24), b.width + 48), height: Math.min(900 - Math.max(0, b.y - 16), b.height + 32) }
    },
  )
}
await browser.close()
