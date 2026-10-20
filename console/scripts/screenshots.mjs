// Screenshots of key screens against the mock dev server, in dark and light.
// Usage: npm run dev:mock (port 5173) in another shell, then `npm run screenshots`.
// Env: BASE_URL (default http://localhost:5173), CHROMIUM_PATH (optional system Chromium/Chrome/Edge),
// OUT_DIR (default console/screenshots). Pass name filters as arguments to shoot a subset.
import { chromium } from 'playwright'
import { mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../screenshots/', import.meta.url))
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
  const file = join(OUT, `${name}-${theme}.png`)
  await page.screenshot({ path: file })
  console.log(file, errors.length ? `ERRORS: ${errors.join(' | ')}` : '')
  await ctx.close()
}

const firstIncident = async (page, host) => {
  await page.goto(`${BASE}/incidents?autologin=1&status=open,in_progress,resolved,dismissed&q=${host}`, { waitUntil: 'networkidle' })
  await page.waitForSelector('[data-row-id]')
  return page.$eval('[data-row-id]', (el) => el.getAttribute('data-row-id'))
}

const openIncident = (host, rule) => async (page) => {
  await page.goto(`${BASE}/incidents?autologin=1&status=open,in_progress,resolved,dismissed&q=${host}`, { waitUntil: 'networkidle' })
  await page.waitForSelector('[data-row-id]')
  const id = await page.$$eval(
    '[data-row-id]',
    (els, r) => (els.find((el) => el.textContent?.includes(r)) ?? els[0]).getAttribute('data-row-id'),
    rule,
  )
  await page.goto(`${BASE}/incidents/${id}?autologin=1`, { waitUntil: 'networkidle' })
  await page.waitForSelector('text=What happened')
}

// v1.1 general-malware screens (ransomware, credential dumping, persistence), both themes.
for (const theme of ['dark', 'light']) {
  await shoot(theme, 'v11-incident-ransomware', '/', openIncident('OPS-DT-009', 'Ransomware'), { full: true })
  await shoot(theme, 'v11-incident-creddump', '/', openIncident('SRV-APP-02', 'Credential dumping'), { full: true })
  await shoot(theme, 'v11-incident-persistence', '/', openIncident('HR-LT-006', 'Persistence'), { full: true })
  await shoot(theme, 'v11-incident-persistence-actions', '/', async (page) => {
    await openIncident('HR-LT-006', 'Persistence')(page)
    await page.click('role=tab[name=/^Actions/]')
    await page.waitForTimeout(300)
  })
  await shoot(theme, 'v11-rules-catalog', '/rules?category=ransomware,credential_dumping,persistence')
  await shoot(theme, 'v11-rule-sigma', '/rules?rule=SIG-646ea171')
  await shoot(theme, 'v11-rule-builtin', '/rules?rule=RW-06')
  await shoot(theme, 'v11-policy-sensors-hardening', '/policies/pol-finance', async (page) => {
    await page.waitForSelector('#sensors')
    await page.$eval('#sensors', (el) => el.scrollIntoView({ block: 'start' }))
  }, { height: 1700 })
  for (const [name, host, kinds] of [
    ['v11-device-timeline-rw', 'OPS-DT-009', ['File activity', 'Process start']],
    ['v11-device-timeline-ps', 'HR-LT-006', ['Scheduled task', 'WMI subscription', 'Registry set']],
    ['v11-device-timeline-cd', 'SRV-APP-02', ['Process access', 'Registry set']],
  ]) {
    await shoot(theme, name, '/', async (page) => {
      await page.goto(`${BASE}/devices?autologin=1&q=${host}`, { waitUntil: 'networkidle' })
      await page.click('[data-row-id] >> nth=0 >> td >> nth=0')
      await page.waitForSelector('text=Sensor health')
      await page.click('role=tab[name=/Event timeline/]')
      for (const k of kinds) await page.click(`button[aria-pressed]:text-is("${k}")`)
      await page.waitForTimeout(600)
      await page.$eval('[role=tablist]', (el) => el.scrollIntoView({ block: 'start' }))
    }, { height: 1000 })
  }
  await shoot(theme, 'v11-device-hardening', '/', async (page) => {
    await page.goto(`${BASE}/devices?autologin=1&q=FIN-LT-021`, { waitUntil: 'networkidle' })
    await page.click('[data-row-id] >> nth=0 >> td >> nth=0')
    await page.waitForSelector('text=Sensor health')
    await page.click('role=tab[name=/Hardening/]')
    await page.waitForTimeout(400)
  }, { full: true })
}

if (process.env.V11_ONLY) {
  await browser.close()
  process.exit(0)
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
