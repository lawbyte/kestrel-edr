// Screenshots of key screens against the mock dev server, in dark and light.
// Usage: npm run dev:mock (port 5173) in another shell, then `npm run screenshots`.
// Env: BASE_URL (default http://localhost:5173), CHROMIUM_PATH (optional system Chromium).
import { chromium } from 'playwright'
import { mkdirSync, existsSync } from 'node:fs'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = new URL('../screenshots/', import.meta.url).pathname
mkdirSync(OUT, { recursive: true })

const candidates = [process.env.CHROMIUM_PATH, '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'].filter(Boolean)
const executablePath = candidates.find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath, args: ['--no-sandbox'] })
const only = process.argv.slice(2)

async function shoot(theme, name, path, prepare, opts = {}) {
  if (only.length && !only.some((o) => name.includes(o))) return
  const ctx = await browser.newContext({ viewport: { width: opts.width ?? 1440, height: opts.height ?? 900 }, deviceScaleFactor: 1, colorScheme: theme })
  await ctx.addInitScript((t) => {
    try {
      localStorage.setItem('kestrel-theme', t)
      sessionStorage.setItem('kestrel-demo-banner', '0')
    } catch {}
  }, theme)
  const page = await ctx.newPage()
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
  await page.goto(`${BASE}${path}${path.includes('?') ? '&' : '?'}autologin=1`, { waitUntil: 'networkidle' })
  await page.waitForTimeout(700)
  if (prepare) await prepare(page)
  await page.waitForTimeout(500)
  if (opts.full) {
    // <main> is the scroll container, so grow the viewport to its content height.
    const h = await page.evaluate(() => {
      const m = document.querySelector('main')
      return m ? m.scrollHeight + (window.innerHeight - m.clientHeight) : document.body.scrollHeight
    })
    await page.setViewportSize({ width: opts.width ?? 1440, height: Math.min(Math.max(h, 900), 6000) })
    await page.waitForTimeout(400)
  }
  const file = `${OUT}${name}-${theme}.png`
  await page.screenshot({ path: file })
  console.log(file, errors.length ? `ERRORS: ${errors.join(' | ')}` : '')
  await ctx.close()
}

const firstIncident = async (page, host) => {
  await page.goto(`${BASE}/incidents?autologin=1&status=open,in_progress,resolved,dismissed&q=${host}`, { waitUntil: 'networkidle' })
  await page.waitForSelector('[data-row-id]')
  return page.$eval('[data-row-id]', (el) => el.getAttribute('data-row-id'))
}

for (const theme of ['dark', 'light']) {
  await shoot(theme, 'overview', '/', null, { full: true })
  await shoot(theme, 'incidents-drawer', '/incidents', async (page) => {
    await page.waitForSelector('[data-row-id]')
    await page.click('[data-row-id] >> nth=0 >> td >> nth=1')
    await page.waitForSelector('text=What happened')
  })
  await shoot(theme, 'incident', '/', async (page) => {
    const id = await firstIncident(page, 'SAL-LT-022')
    await page.goto(`${BASE}/incidents/${id}?autologin=1`, { waitUntil: 'networkidle' })
    await page.waitForSelector('text=What happened')
  }, { full: true })
  await shoot(theme, 'device', '/', async (page) => {
    await page.goto(`${BASE}/devices?autologin=1&q=SAL-LT-022`, { waitUntil: 'networkidle' })
    await page.click('[data-row-id] >> nth=0 >> td >> nth=0')
    await page.waitForSelector('text=Sensor health')
  }, { full: true })
  await shoot(theme, 'policy-editor', '/policies/pol-default', async (page) => {
    await page.waitForSelector('text=Detection rules')
  }, { full: true })
}

// Extra screens (dark only) for a broader visual pass.
await shoot('dark', 'hunt', '/hunt?q=dns_qname%20%3D%20api.telegram.org&range=7d', async (page) => page.waitForSelector('text=results', { timeout: 5000 }).catch(() => {}))
await shoot('dark', 'alerts', '/alerts')
await shoot('dark', 'devices', '/devices')
await shoot('dark', 'rules', '/rules?rule=ST-04')
await shoot('dark', 'exclusions-preview', '/incidents', async (page) => {
  const id = await firstIncident(page, 'IT-LT-002')
  await page.goto(`${BASE}/incidents/${id}?autologin=1`, { waitUntil: 'networkidle' })
  await page.click('text=Exclude… >> nth=0')
  await page.waitForSelector('text=Scope preview')
  await page.waitForTimeout(900)
})
await shoot('dark', 'enrollment', '/settings/enrollment')
await shoot('dark', 'audit', '/settings/audit')
await shoot('light', 'login', '/', async (page) => {
  await page.evaluate(() => fetch('/api/auth/logout', { method: 'POST' }))
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' })
  await page.waitForSelector('text=Sign in')
})
await shoot('dark', 'tablet-incidents', '/incidents', null, { width: 820, height: 1100 })

await browser.close()
