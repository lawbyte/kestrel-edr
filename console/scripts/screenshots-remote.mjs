// Screenshots of the remote-access screens (remote desktop, file manager,
// device remote-access summary, installer wizard) against the mock dev server,
// in light and dark. Usage: `VITE_MOCK=1 npx vite` (default port 5173) in another
// shell, then `node scripts/screenshots-remote.mjs`.
// Env: BASE_URL, CHROMIUM_PATH (system Chromium/Chrome/Edge), OUT_DIR (default docs/screenshots).
import { chromium } from 'playwright'
import { existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.BASE_URL ?? 'http://localhost:5173'
const OUT = process.env.OUT_DIR ?? fileURLToPath(new URL('../../docs/screenshots/', import.meta.url))
mkdirSync(OUT, { recursive: true })
const candidates = [process.env.CHROMIUM_PATH, '/opt/pw-browsers/chromium-1194/chrome-linux/chrome'].filter(Boolean)
const executablePath = candidates.find((p) => existsSync(p))
const browser = await chromium.launch({ executablePath, args: ['--no-sandbox'] })
const only = process.argv.slice(2)

async function newPage(theme, height = 900) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height }, deviceScaleFactor: 1, colorScheme: theme })
  await ctx.addInitScript((t) => {
    try {
      localStorage.setItem('kestrel-theme', t)
      sessionStorage.setItem('kestrel-demo-banner', '0')
    } catch {}
  }, theme)
  const page = await ctx.newPage()
  page.errors = []
  page.on('pageerror', (e) => page.errors.push(e.message))
  page.on('console', (m) => m.type() === 'error' && page.errors.push(m.text()))
  await page.goto(`${BASE}/devices?autologin=1`, { waitUntil: 'networkidle' })
  return { ctx, page }
}

/** Device ids from the mock API (same origin, patched fetch). */
async function pickDevice(page, pred) {
  return page.evaluate(async (predSrc) => {
    const fn = new Function('d', `return (${predSrc})(d)`)
    const list = await (await fetch('/api/devices?limit=500')).json()
    for (const d of list.items) {
      const det = await (await fetch(`/api/devices/${d.id}`)).json()
      if (fn(det)) return d.id
    }
    return null
  }, pred.toString())
}

async function save(page, name, theme) {
  const file = join(OUT, `${name}-${theme}.png`)
  await page.screenshot({ path: file })
  console.log(file, page.errors.length ? `ERRORS: ${page.errors.join(' | ')}` : '')
}

/** Scroll so the device tab list sits just below the sticky action bar. */
const toTabs = (page) =>
  page.evaluate(() => {
    document.querySelector('[role=tablist]')?.scrollIntoView({ block: 'start' })
    document.querySelector('main')?.scrollBy(0, -52)
  })

const want = (n) => !only.length || only.some((o) => n.includes(o))

for (const theme of ['light', 'dark']) {
  if (want('remote-desktop')) {
    const { ctx, page } = await newPage(theme, 1000)
    const id = await pickDevice(page, (d) => d.device.group_id === 'grp-eng' && d.remote_access?.desktop.available && d.device.status === 'online')
    await page.goto(`${BASE}/devices/${id}?autologin=1&tab=remote-desktop`, { waitUntil: 'networkidle' })
    await page.fill('#rd-reason', 'Checking the VPN client error from ticket IT-4821')
    await page.click('button:has-text("Connect")')
    await page.waitForSelector('text=Connected, view only', { timeout: 10000 })
    await page.click('#rd-viewonly')
    await page.waitForSelector('text=Connected, in control')
    await toTabs(page)
    await page.waitForTimeout(300)
    const canvas = await page.$('canvas')
    const box = await canvas.boundingBox()
    await page.mouse.click(box.x + box.width * 0.3, box.y + box.height * 0.5)
    await page.mouse.click(box.x + box.width * 0.62, box.y + box.height * 0.42)
    await page.keyboard.press('KeyK')
    await page.mouse.move(box.x + box.width * 0.64, box.y + box.height * 0.45, { steps: 5 })
    await page.waitForTimeout(1800)
    await save(page, 'remote-desktop', theme)
    await ctx.close()
  }
  if (want('remote-files')) {
    const { ctx, page } = await newPage(theme, 1000)
    const id = await pickDevice(page, (d) => d.device.group_id === 'grp-eng' && d.remote_access?.files.available && d.device.status === 'online')
    await page.goto(`${BASE}/devices/${id}?autologin=1&tab=files`, { waitUntil: 'networkidle' })
    await page.click('table >> text=C:\\')
    await page.click('table >> text=Users')
    await page.waitForSelector('table >> text=Public')
    const user = await page.$$eval('table tbody tr', (rows) => rows.map((r) => r.querySelector('td')?.textContent ?? '').find((t) => t && !/Public|Default/.test(t)))
    await page.click(`table >> text=${user.replace(/hidden|link/g, '').trim()}`)
    await page.click('table >> text=Documents')
    await page.waitForSelector('text=Expense claim October.xlsx')
    await toTabs(page)
    await page.waitForTimeout(500)
    await save(page, 'remote-files', theme)
    await ctx.close()
  }
  if (want('remote-summary')) {
    const { ctx, page } = await newPage(theme, 1000)
    const id = await pickDevice(page, (d) => d.device.group_id === 'grp-sales' && d.remote_access?.files.available && d.device.status === 'online')
    await page.goto(`${BASE}/devices/${id}?autologin=1&tab=files`, { waitUntil: 'networkidle' })
    await page.waitForSelector('text=Install ceiling')
    await page.$eval('section[aria-label="Remote access"]', (el) => el.scrollIntoView({ block: 'start' }))
    await page.waitForTimeout(500)
    await save(page, 'remote-summary', theme)
    await ctx.close()
  }
  if (want('installer')) {
    const { ctx, page } = await newPage(theme, 1000)
    await page.click('button:has-text("Install agent")')
    await page.waitForSelector('text=Remote control + file manager with guardrails')
    await page.waitForTimeout(400)
    await save(page, 'installer-step1', theme)
    await page.click('[role=dialog] button:has-text("Next")')
    await page.waitForSelector('text=Prefilled with the recommended guardrails')
    await page.waitForTimeout(400)
    await save(page, 'installer-step2', theme)
    await page.click('[role=dialog] button:has-text("Next")')
    await page.waitForSelector('#wiz-group')
    await page.selectOption('#wiz-group', { label: 'IT' })
    await page.click('button:has-text("Create installer")')
    await page.waitForSelector('text=Shown once.')
    await page.waitForTimeout(400)
    await save(page, 'installer-step3', theme)
    await ctx.close()
  }
}
await browser.close()
