// Screenshots of a live kestrel-server holding lab-VM data (docker compose deploy).
// Usage: KESTREL_URL=https://localhost KESTREL_EMAIL=… KESTREL_PASSWORD=… \
//        CHROMIUM_PATH="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" \
//        node console/scripts/screenshots-lab.mjs
// Writes docs/screenshots/lab-<page>-<theme>.png. Exits non-zero on page errors
// or failed API calls.
import { chromium } from 'playwright'
import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const url = process.env.KESTREL_URL ?? 'https://localhost'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../../docs/screenshots/', import.meta.url))
mkdirSync(OUT, { recursive: true })
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, args: ['--no-sandbox'] })
const problems = []

async function api(ctx, path) {
  const r = await ctx.request.get(`${url}${path}`)
  if (!r.ok()) throw new Error(`${path}: HTTP ${r.status()}`)
  return r.json()
}

for (const theme of ['dark', 'light']) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, colorScheme: theme })
  await ctx.addInitScript((t) => { try { localStorage.setItem('kestrel-theme', t) } catch {} }, theme)
  const page = await ctx.newPage()
  page.on('pageerror', (e) => problems.push(`${theme} pageerror: ${e.message}`))
  page.on('response', (r) => {
    if (r.url().includes('/api/') && r.status() >= 400 && !r.url().endsWith('/api/me')) problems.push(`${theme} HTTP ${r.status()} ${r.url()}`)
  })
  await page.goto(`${url}/`, { waitUntil: 'networkidle' })
  await page.fill('#email', process.env.KESTREL_EMAIL)
  await page.fill('#password', process.env.KESTREL_PASSWORD)
  await Promise.all([page.waitForLoadState('networkidle'), page.keyboard.press('Enter')])
  await page.waitForTimeout(1500)

  const incidents = await api(ctx, '/api/incidents?limit=100')
  const items = incidents.items ?? incidents
  // One incident per family, by title (the incident's headline family), highest priority first.
  const used = new Set()
  const pick = (prefix) => {
    const i = [...items].sort((a, b) => b.priority - a.priority).find((x) => x.title.startsWith(prefix) && !used.has(x.id))
    if (!i) return undefined
    used.add(i.id)
    return `/incidents/${i.id}`
  }
  const devices = await api(ctx, '/api/devices')
  const dev = (devices.items ?? devices).find((d) => d.status !== 'offline')

  const shots = [
    ['dashboard', '/'],
    ['incidents', '/incidents'],
    ['incident-ransomware', pick('Ransomware activity')],
    ['incident-stealer', pick('Credential theft')],
    ['incident-creddump', pick('Credential dumping')],
    ['incident-persistence', pick('Persistence planted')],
    ['device', dev && `/devices/${dev.id}`],
    ['rules', '/rules'],
    ['policy', '/policies/default'],
  ]
  for (const [name, path] of shots) {
    if (!path) { problems.push(`${theme}: no data for ${name}`); continue }
    await page.goto(`${url}${path}`, { waitUntil: 'networkidle' })
    await page.waitForTimeout(1200)
    await page.screenshot({ path: `${OUT}/lab-${name}-${theme}.png` })
  }
  await ctx.close()
}
await browser.close()
if (problems.length) {
  console.error(problems.join('\n'))
  process.exit(1)
}
console.log('screenshots written to', OUT)
