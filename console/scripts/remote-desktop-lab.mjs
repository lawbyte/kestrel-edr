// Lab check of the Remote desktop tab against a live server and a real agent.
// Usage: KESTREL_URL=https://localhost KESTREL_EMAIL=… KESTREL_PASSWORD=… DEVICE_ID=… \
//        CHROMIUM_PATH=… OUT=<png prefix> node console/scripts/remote-desktop-lab.mjs
import { chromium } from 'playwright'

const url = process.env.KESTREL_URL ?? 'https://localhost'
const out = process.env.OUT ?? 'remote-lab'
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH, args: ['--no-sandbox'] })
const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, ignoreHTTPSErrors: true, colorScheme: 'dark' })
const page = await ctx.newPage()
const problems = []
page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`))
page.on('websocket', (ws) => {
  let frames = 0
  ws.on('framereceived', () => { frames += 1 })
  ws.on('close', () => console.log(`websocket closed after ${frames} frames`))
  setTimeout(() => console.log(`websocket frames after 12 s: ${frames}`), 12000)
})

await page.goto(`${url}/`, { waitUntil: 'networkidle' })
await page.fill('#email', process.env.KESTREL_EMAIL)
await page.fill('#password', process.env.KESTREL_PASSWORD)
await page.getByRole('button', { name: /sign in/i }).click()
await page.getByText('Overview', { exact: true }).first().waitFor({ timeout: 30000 })
await page.goto(`${url}/devices/${process.env.DEVICE_ID}`, { waitUntil: 'networkidle' })
await page.waitForTimeout(2000)
await page.screenshot({ path: `${out}-device.png`, fullPage: true })
await page.getByText('Remote desktop', { exact: true }).first().click({ timeout: 15000 })
await page.waitForTimeout(1500)
await page.screenshot({ path: `${out}-tab.png` })
const reason = page.getByLabel(/reason/i)
if (await reason.count()) await reason.first().fill('Lab test of remote desktop')
await page.getByRole('button', { name: /^connect/i }).first().click()
console.log('connect clicked', new Date().toISOString())
await page.waitForTimeout(10000)
const cv = page.locator('canvas').first()
await cv.scrollIntoViewIfNeeded().catch(() => {})
await page.screenshot({ path: `${out}-connected.png` })
await cv.screenshot({ path: `${out}-canvas.png` }).catch((e) => problems.push(`canvas: ${e.message}`))
await page.waitForTimeout(8000)
// Control mode: turn View only off, then click the Start button (x 213/1024, y 744/768 of the desktop).
if (process.env.CONTROL) {
  await page.getByText('View only', { exact: true }).first().click()
  await page.waitForTimeout(2500)
  const b = await cv.boundingBox()
  if (b) {
    await page.mouse.click(b.x + b.width * (315 / 1158), b.y + b.height * (658 / 680))
    await page.waitForTimeout(1500)
    await page.mouse.click(b.x + b.width * (315 / 1158), b.y + b.height * (658 / 680))
    console.log('clicked Start', new Date().toISOString())
  }
  await page.waitForTimeout(6000)
  await cv.screenshot({ path: `${out}-control.png` }).catch(() => {})
}
// Move the mouse over the canvas and type into the desktop (control mode).
const canvas = page.locator('canvas').first()
if (await canvas.count()) {
  const box = await canvas.boundingBox()
  if (box) {
    await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.5)
    await page.mouse.click(box.x + box.width * 0.5, box.y + box.height * 0.5)
  }
}
await page.waitForTimeout(3000)
await page.screenshot({ path: `${out}-after-input.png` })
await page.getByRole('button', { name: /disconnect/i }).first().click().catch(() => problems.push('no Disconnect button'))
await page.waitForTimeout(2000)
await browser.close()
if (problems.length) console.error(problems.join('\n'))
