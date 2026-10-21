// Screenshots of the Remote desktop tab connected to a real agent (lab VM).
// Usage: KESTREL_URL=https://localhost KESTREL_EMAIL=… KESTREL_PASSWORD=… DEVICE_ID=… \
//        CHROMIUM_PATH=… OUT_DIR=website/public/img/console node console/scripts/remote-desktop-shots.mjs
// Writes device-remote-desktop-<theme>.png. View-only session; the employee sees the banner.
import { chromium } from 'playwright'

const url = process.env.KESTREL_URL ?? 'https://localhost'
const out = process.env.OUT_DIR ?? 'website/public/img/console'
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH })
for (const theme of ['dark', 'light']) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, ignoreHTTPSErrors: true, colorScheme: theme })
  await ctx.addInitScript((t) => { try { localStorage.setItem('kestrel-theme', t) } catch {} }, theme)
  const page = await ctx.newPage()
  await page.goto(`${url}/`, { waitUntil: 'networkidle' })
  await page.fill('#email', process.env.KESTREL_EMAIL)
  await page.fill('#password', process.env.KESTREL_PASSWORD)
  await page.getByRole('button', { name: /sign in/i }).click()
  await page.getByText('Overview', { exact: true }).first().waitFor({ timeout: 30000 })
  await page.goto(`${url}/devices/${process.env.DEVICE_ID}`, { waitUntil: 'networkidle' })
  await page.getByText('Remote desktop', { exact: true }).first().click({ timeout: 15000 })
  await page.waitForTimeout(1200)
  const reason = page.getByLabel(/reason/i)
  if (await reason.count()) await reason.first().fill('Helping with a VPN problem (ticket 4821)')
  await page.getByRole('button', { name: /^connect/i }).first().click()
  await page.waitForTimeout(9000)
  // Scroll the tab bar to the top of the viewport so the desktop fills the shot.
  await page.getByText('Remote desktop', { exact: true }).first().evaluate((el) => el.scrollIntoView({ block: 'start' }))
  await page.waitForTimeout(2500)
  await page.screenshot({ path: `${out}/device-remote-desktop-${theme}.png` })
  await page.getByRole('button', { name: /disconnect/i }).first().click().catch(() => {})
  await page.waitForTimeout(2000)
  await ctx.close()
  console.log(theme, 'ok')
}
await browser.close()
