// Screenshots of the console served by a real kestrel-server (not the mock).
// Usage: E2E_KEEP=1 E2E_INFO_FILE=/tmp/e2e.json ./scripts/e2e.sh   (leaves the server up)
//        E2E_INFO_FILE=/tmp/e2e.json node console/scripts/screenshots-real.mjs
// Env: E2E_INFO_FILE (url/email/password/lumma ids written by e2e.sh), OUT_DIR
// (default docs/screenshots), CHROMIUM_PATH. Exits non-zero on page errors,
// browser console errors or failed API calls.
import { chromium } from 'playwright'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'

const info = JSON.parse(readFileSync(process.env.E2E_INFO_FILE ?? '/tmp/kestrel-e2e.json', 'utf8'))
const OUT = process.env.OUT_DIR ?? new URL('../../docs/screenshots/', import.meta.url).pathname
mkdirSync(OUT, { recursive: true })

const candidates = [process.env.CHROMIUM_PATH, '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'].filter(Boolean)
const executablePath = candidates.find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath, args: ['--no-sandbox'] })
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, colorScheme: 'dark' })
await ctx.addInitScript(() => {
  try { localStorage.setItem('kestrel-theme', 'dark') } catch {}
})
const page = await ctx.newPage()
const problems = []
page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`))
page.on('console', (m) => m.type() === 'error' && problems.push(`console: ${m.text()}`))
page.on('response', (r) => {
  if (r.url().includes('/api/') && r.status() >= 400) problems.push(`HTTP ${r.status()} ${r.request().method()} ${r.url()}`)
})

// Log in through the real form. (The unauthenticated GET /api/me → 401 that
// sends the SPA to the login screen is expected; drop problems seen before login.)
await page.goto(`${info.url}/`, { waitUntil: 'networkidle' })
await page.fill('#email', info.email)
await page.fill('#password', info.password)
await page.click('button[type=submit]')
await page.waitForFunction(() => !document.querySelector('#password'), null, { timeout: 15000 })
await page.waitForLoadState('networkidle')
const preLogin = problems.splice(0)
console.log(`login ok (${preLogin.length} expected pre-login responses: ${preLogin.join('; ')})`)

async function shoot(name, path, waitFor) {
  const before = problems.length
  await page.goto(`${info.url}${path}`, { waitUntil: 'networkidle' })
  if (waitFor) await page.waitForSelector(waitFor, { timeout: 15000 }).catch((e) => problems.push(`${name}: ${e.message.split('\n')[0]}`))
  await page.waitForTimeout(800)
  // <main> is the scroll container: grow the viewport to its content height.
  const h = await page.evaluate(() => {
    const m = document.querySelector('main')
    return m ? m.scrollHeight + (window.innerHeight - m.clientHeight) : document.body.scrollHeight
  })
  await page.setViewportSize({ width: 1440, height: Math.min(Math.max(h, 900), 6000) })
  await page.waitForTimeout(300)
  const file = `${OUT}real-${name}.png`
  await page.screenshot({ path: file })
  await page.setViewportSize({ width: 1440, height: 900 })
  const mine = problems.slice(before)
  console.log(file, mine.length ? `PROBLEMS:\n  ${mine.join('\n  ')}` : 'ok')
}

await shoot('overview', '/', 'text=Recent incidents')
await shoot('incidents', '/incidents?status=open,in_progress,resolved,dismissed', '[data-row-id]')
await shoot('incident-lumma', `/incidents/${info.lumma_incident}`, 'text=What happened')
await shoot('device-lumma', `/devices/${info.lumma_device}`, 'text=Sensor health')
await shoot('policy-editor', '/policies/default', 'text=Detection rules')

await browser.close()
if (problems.length) {
  console.error(`\n${problems.length} problem(s) found:\n  ${problems.join('\n  ')}`)
  process.exit(1)
}
