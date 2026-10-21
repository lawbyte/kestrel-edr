// Screenshots of the mock UI at 420x600 in light and dark.
// Usage: npm run build:mock && npm run screenshots
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "screenshots");
const port = 4174;
// Fixed command string (no user input); a shell is needed for npx.cmd on Windows.
const server = spawn(`npx vite preview --outDir dist-mock --port ${port} --strictPort`, { cwd: root, stdio: "ignore", shell: true });
const base = `http://localhost:${port}/`;

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(base)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("preview server did not start");
}

const shots = [
  // [name, query, after(page)]
  ["status-attention", "tab=status&state=attention"],
  ["status-protected", "tab=status&state=protected"],
  ["status-isolated", "tab=status&state=isolated"],
  ["status-degraded", "tab=status&state=degraded"],
  ["status-offline", "tab=status&state=offline"],
  ["status-unavailable", "tab=status&state=unavailable"],
  ["status-quickcheck-running", "tab=status&state=protected", async (p) => { await p.getByRole("button", { name: "Run check" }).click(); await p.waitForTimeout(700); }],
  ["status-quickcheck-done", "tab=status&state=protected", async (p) => { await p.getByRole("button", { name: "Run check" }).click(); await p.getByRole("status").waitFor(); await p.waitForTimeout(200); }],
  ["activity", "tab=activity"],
  ["activity-expanded", "tab=activity", async (p) => { await p.locator(".card__head").first().click(); await p.waitForTimeout(100); }],
  ["activity-review-dialog", "tab=activity", async (p) => { await p.getByRole("button", { name: "Request review" }).first().click(); await p.locator("textarea").fill("This is the installer for SAP GUI from our vendor's portal. Finance needs it for month-end close."); await p.waitForTimeout(150); }],
  ["activity-empty", "tab=activity&empty=1"],
  ["activity-push-banner", "tab=activity&state=protected&push=0.4", async (p) => { await p.waitForTimeout(900); }],
  ["status-remote-control", "tab=status&state=protected&remote=control"],
  ["status-remote-view", "tab=status&state=attention&remote=view"],
  ["status-remote-files", "tab=status&state=protected&remote=files"],
  ["activity-remote-control", "tab=activity&state=protected&remote=control"],
  // IT consent prompt. The hooks also check behaviour: an early Enter must not allow,
  // Escape denies, Enter after the arm delay allows.
  ["consent-desktop", "tab=status&state=protected&consent=desktop&consent_in=0.1", async (p) => { await p.locator(".consent").waitFor(); await p.waitForTimeout(1200); }],
  ["consent-files-queue", "tab=status&state=protected&consent=queue&consent_in=0.1", async (p) => { await p.locator(".consent").waitFor(); await p.waitForTimeout(1200); }],
  ["consent-early-enter-ignored", "tab=status&state=protected&consent=view&consent_in=0.1", async (p) => {
    await p.locator(".consent").waitFor();
    await p.keyboard.press("Enter");
    await p.waitForTimeout(700);
    if (!(await p.locator(".consent").isVisible())) throw new Error("early Enter must not answer the prompt");
  }],
  ["consent-denied-escape", "tab=status&state=protected&consent=desktop&consent_in=0.1", async (p) => {
    await p.locator(".consent").waitFor();
    await p.keyboard.press("Escape");
    await p.locator(".consent-result").waitFor();
    if (await p.locator(".remote").count()) throw new Error("Escape must deny");
  }],
  ["consent-allowed-enter", "tab=status&state=protected&consent=files&consent_in=0.1", async (p) => {
    await p.locator(".consent").waitFor();
    await p.waitForTimeout(1300);
    await p.keyboard.press("Enter");
    await p.locator(".remote").waitFor();
    await p.waitForTimeout(150);
  }],
  ["consent-expired", "tab=status&state=protected&consent=desktop&consent_in=0.1&consent_timeout=2", async (p) => {
    await p.locator(".consent").waitFor();
    await p.locator(".consent-result").waitFor({ timeout: 5000 });
    if (await p.locator(".consent").count()) throw new Error("expired prompt must close");
  }],
  ["help", "tab=help"],
  ["help-notice", "tab=help", async (p) => { await p.locator("#h-notice").scrollIntoViewIfNeeded(); await p.waitForTimeout(100); }],
];

try {
  await waitForServer();
  // CHROMIUM_PATH lets you reuse an existing Chromium when `npx playwright install` is blocked.
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const only = process.argv[2];
  for (const theme of ["light", "dark"]) {
    const ctx = await browser.newContext({ viewport: { width: 420, height: 600 }, deviceScaleFactor: 2, colorScheme: theme, reducedMotion: "reduce" });
    const page = await ctx.newPage();
    for (const [name, q, after] of shots) {
      if (only && !name.includes(only)) continue;
      await page.goto(`${base}?${q}&theme=${theme}`);
      await page.waitForSelector(".app");
      await page.waitForTimeout(450);
      await page.mouse.move(0, 599);
      if (after) await after(page);
      await page.mouse.move(0, 599);
      const file = join(out, `${name}-${theme}.png`);
      await page.screenshot({ path: file });
      console.log("wrote", file);
    }
    await ctx.close();
  }
  await browser.close();
} finally {
  // With `shell: true` (Windows) kill() only stops the shell; take the whole tree down.
  if (process.platform === "win32" && server.pid) spawn("taskkill", ["/pid", String(server.pid), "/T", "/F"], { stdio: "ignore" });
  else server.kill();
}
