# Kestrel tray app (employee-facing)

The small Windows app that employees see. It shows whether Kestrel is protecting the PC, explains what was blocked in plain language, lets the employee ask IT to review a block, and shows the company's IT contact and monitoring notice (the visible notice required under PDPA and UU PDP).

It runs **per user, unprivileged** and only talks to the agent service over the tray protocol. It cannot change protection, allow or restore anything. Those actions stay with IT in the console.

- **Tauri 2** (Rust) shell in `src-tauri/`. This is its **own Cargo workspace** (`[workspace]` in its `Cargo.toml`) and is not part of the root workspace.
- **Vite + React + TypeScript** UI in `src/`. There is no UI library: plain CSS tuned to Windows 11 (Segoe UI Variable, 4/8 px radii, Mica backdrop, light and dark follow the system).

## Layout

```
src/
  protocol.ts          TS mirror + validating parser of kestrel_common::tray (the contract)
  markdown.ts          tiny safe Markdown → AST parser for the org privacy notice (no HTML)
  api/tauri.ts         backend commands/events      api/mock.ts   browser mock (dev:mock)
  App.tsx, components/ Status, Activity (+ Request review dialog), Help & privacy
src-tauri/src/
  protocol.rs          Rust mirror of kestrel_common::tray (tests/contract.rs checks it against the real crate)
  client.rs            pipe / unix-socket client, JSON lines, timeouts, backoff
  mock.rs              in-process mock agent (KESTREL_TRAY_MOCK=1)
  lib.rs               tray icon + menu, flyout window, commands, push subscription, toasts
scripts/gen-icons.mjs  brand mark + per-state tray icons (SVG → PNG/ICO)
scripts/screenshots.mjs Playwright screenshots of the mock UI → screenshots/
```

## Protocol

The tray uses `\\.\pipe\kestrel-tray` with one JSON object per line, as defined in `crates/kestrel-common/src/tray.rs`.

| UI need | Request | Notes |
|---|---|---|
| Status tab, tray icon | `{"op":"status"}` | also polled every 30 s and after every push |
| Activity tab | `{"op":"activity","limit":50}` | |
| Quick check | `{"op":"quick_check"}` | 180 s timeout; the result is the `Ack.message` |
| Request review | `{"op":"request_review","alert_id":…,"justification":…}` | justification is trimmed and capped at 2000 chars |
| Answer an IT consent request | `{"op":"consent_response","request_id":…,"allow":true\|false}` | sent on its own connection; the agent's `Ack`/`Error` is shown |
| Pushes | `{"op":"subscribe_with","features":["remote_session","remote_consent"]}` on a long-lived connection | expects `Ack`, then `Notification`, `RemoteSession` and `ConsentRequest` pushes. If the agent answers `Error` (an agent older than `subscribe_with`), the tray reconnects with plain `{"op":"subscribe"}` and only sees the remote session via `status.remote_session` (no consent prompts). Reconnects with backoff from 1 s to 30 s with jitter |

Each request uses its own short connection. The subscription keeps one connection open. A push line the tray can't parse (for example a response type from a newer agent) is logged and skipped. It doesn't drop the subscription.

### IT remote sessions

Admins can open a remote-desktop session on the PC without a consent prompt (owner decision), so the tray must always tell the employee. While `status.remote_session` is active, or after a `remote_session` push with `active: true`:

- A **non-dismissable banner** sits at the top of the window above the tabs, on every tab: "{admin} from IT is viewing your screen" (view only), "…can see and control your screen", or, for a file-manager session (`kind: "files"`), "…can open and copy files on this PC". It also shows the mode in words, "Since HH:MM", the reason if one was given, and "Didn't expect this? Contact {IT contact} ({phone or email}) now." with a **Contact IT** link to the Help tab. It uses `role="status"` with `aria-live`, and a different icon for view-only, control and file access, so colour is never the only signal.
- The Status tab shows an **IT remote access** row.
- The banner covers file sessions too: "{admin} from IT is accessing files on this PC".
- The tray tooltip starts with **"Kestrel: IT is connected"** followed by "{admin} is viewing/controlling your screen".

### IT consent requests

When the admin's guardrails require consent, the agent pushes a `consent_request`. The tray:

- queues it (arrival order, de-duplicated by id, at most 16), brings the flyout to the front and focuses it, and raises a toast ("IT wants to connect … Open Kestrel to allow or deny");
- shows a modal Allow / Deny prompt (`role="alertdialog"`): "{admin} from IT wants to see and control your screen", "…wants to see your screen (view only)" or "…wants to access files on this PC", the reason, what allowing means, a countdown to `expires_at`, and how many more requests are waiting;
- **Deny is the safe default.** Escape or the Deny button answers Deny at once. When the countdown ends, the prompt closes **without sending anything** (the agent treats no answer as deny) and says so;
- Enter = Allow, but only once the prompt has been visible for 1 s. The window takes focus when a request arrives, so a stray Enter typed into another app must not grant access. The Allow button is disabled for that second too. Enter while the Deny button has focus means Deny;
- sends the answer as `consent_response` on a fresh connection and shows the agent's `Ack` message. If the agent returns `Error` (expired/unknown request), the prompt closes and says IT can't connect. If the service is unreachable, the prompt stays so the answer can be retried before it expires;
- doesn't hide the flyout on blur, and Escape doesn't close the window, while a request is pending.

`remote_session` pushes only change UI state. The agent also sends a high-severity `Notification` ("Remote session started" / "Remote session ended"), and that notification raises the toast through the normal toast rules.

**Pipe trust (Windows):** the client opens the pipe with `SECURITY_IDENTIFICATION` QoS, so the server cannot impersonate the user. It then calls `GetNamedPipeServerSessionId` and only trusts a server in **session 0** (a service). If an unprivileged process squats the pipe name, the tray treats it as "service not running" and never shows its status or toasts. For local debugging against a user-mode simulator, a debug build accepts `KESTREL_TRAY_ALLOW_USER_SERVER=1`.

**Transports:**

| Where | Transport |
|---|---|
| Windows | named pipe (above) |
| Linux/macOS dev | Unix socket at `$KESTREL_TRAY_SOCK` (the agent simulator serves the same protocol) |
| Anywhere | `KESTREL_TRAY_MOCK=1` uses the built-in mock agent (`KESTREL_TRAY_MOCK_STATE=protected\|attention\|isolated\|degraded\|offline`). After subscribing, it pushes one demo critical notification about 15 s later. `KESTREL_TRAY_MOCK_CONSENT=desktop\|view\|files` sends an IT consent request about 5 s after subscribing (allowing it starts a matching session). `KESTREL_TRAY_MOCK_REMOTE=view\|control\|files` starts with an active IT remote session. `cycle` starts one about 5 s after subscribing, ends it after 40 s, and repeats. |

If nothing answers, the UI shows **"Kestrel isn't running"** with steps and the IT contact, and the tray shows the red hollow shield.

## Tray icon states

Each state uses a different shape and fill style as well as a different colour. The tooltip always spells the state out.

| State | Icon | Tooltip |
|---|---|---|
| `protected` | solid green shield, check | Kestrel: Protected |
| `attention` | solid amber shield, `!` | Kestrel: Protected. Something was blocked |
| `isolated` | solid indigo shield, padlock | Kestrel: Network limited by IT |
| `degraded` | half-filled orange shield, wave | Kestrel: Protection partly working |
| `offline` | solid grey shield, crossed-out cloud | Kestrel: Protected, not connected to IT |
| pipe unavailable | hollow red shield, ✕ | Kestrel: service isn't running. Contact IT. |
| any state + IT remote session | unchanged icon | Kestrel: IT is connected / {admin} is viewing (or controlling) your screen |

`screenshots/tray-icons.png` shows all states at 16, 24 and 32 px on light and dark taskbars.

Left-clicking the icon toggles the flyout. The right-click menu has **Open Kestrel**, **Quick check**, **Contact IT** and **Quit**. Quit only closes this app; the agent service keeps protecting the PC. The app comes back at next logon.

## Window

- **Flyout mode (default):** 420×600, borderless, placed next to the tray icon inside the monitor's work area. It hides when it loses focus or when you press Esc, like Windows flyouts. Closing never quits the app.
- **Window mode:** the pop-out button in the title bar turns it into a normal framed, resizable window that stays open.
- **Mica:** applied from code on Windows 11 (build 22000 and later). The UI switches to translucent layers only when Mica is actually active (`data-mica="on"`). Otherwise it uses solid surfaces.

## Toasts

Pushed `Notification`s raise a Windows toast titled "Kestrel for {org}". Rules:

- **Critical items are always shown**, even if the window is open (the Microsoft Defender rule).
- Other items are toasted only when the window isn't focused.
- `info` items, such as "settings updated", only appear in Activity.
- Review decisions (approved/denied) arrive as updated items and get their own wording.

## Development

```bash
npm install
npm run dev:mock          # browser-only UI with sample data at http://localhost:1430
                          #   ?state=protected|attention|isolated|degraded|offline|unavailable
                          #   &tab=status|activity|help &theme=light|dark &empty=1 &push=3 &notice=0
                          #   &remote=view|control|files|cycle   (IT remote session banner)
                          #   &consent=desktop|view|files|queue &consent_in=1 &consent_timeout=60
npm test                  # Vitest: protocol parsing, markdown sanitising, remote-session banner, consent queue + prompt
npm run build             # tsc (strict) + vite build → dist/
npm run icons             # regenerate src-tauri/icons/** from scripts/gen-icons.mjs

# Native shell (needs Rust; on Linux: libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev)
KESTREL_TRAY_MOCK=1 npm run tauri dev
KESTREL_TRAY_SOCK=/path/to/agent-sim/tray.sock npm run tauri dev

cd src-tauri && cargo test   # client/mock tests + contract test against crates/kestrel-common

# Windows cross-check from Linux (mingw linker set in src-tauri/.cargo/config.toml)
cd src-tauri && RUSTC_BOOTSTRAP=1 cargo check -Zbuild-std=std,panic_abort --target x86_64-pc-windows-gnu

# Screenshots (420x600, light + dark) → screenshots/
npm run build:mock && npm run screenshots
#   if `npx playwright install chromium` is blocked: CHROMIUM_PATH=/path/to/chrome npm run screenshots
```

The production bundle never contains sample data. The mock is only compiled in with `--mode mock`.

## Building on Windows

Prerequisites: Rust (MSVC toolchain), Node 20+, the WebView2 runtime (present on Windows 11), and the WiX Toolset v3 / NSIS that the Tauri CLI downloads automatically.

```powershell
npm ci
npm run tauri build
# → src-tauri\target\release\kestrel-tray.exe
# → src-tauri\target\release\bundle\msi\Kestrel_0.1.0_x64_en-US.msi
# → src-tauri\target\release\bundle\nsis\Kestrel_0.1.0_x64-setup.exe
```

Sign `kestrel-tray.exe` and the installer with the same Authenticode certificate as the agent. The agent's tamper rules can then recognise the tray by its signer.

## How the agent MSI installs it

The standalone Tauri MSI above is for testing. In production the **agent MSI** ships the tray. Its expectations:

1. **Files:** `kestrel-tray.exe` goes into `%ProgramFiles%\Kestrel\` next to the agent, read-only for users.
2. **WebView2:** present on Windows 11 and on updated Windows 10. Otherwise, chain the Evergreen bootstrapper (`MicrosoftEdgeWebview2Setup.exe /silent /install`).
3. **Start at logon for every user (per-machine Run key):**
   ```
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
     KestrelTray (REG_SZ) = "C:\Program Files\Kestrel\kestrel-tray.exe" --background
   ```
   `--background` starts the app in the tray without opening the window. A per-machine Run key was chosen over a scheduled task because Explorer starts it in each interactive session as the logged-on user, unprivileged, which is exactly what the app needs. The per-user policy "Run only specified Windows applications" does not block it.
   - Alternative if Run keys are restricted by GPO: a scheduled task with an `At log on` trigger for `BUILTIN\Users`, *Run only when user is logged on*, *Run with lowest privileges*, and the same command line.
4. **Start menu shortcut:** `Kestrel.lnk` with the AppUserModelID `id.lbyte.kestrel.tray`. Windows only shows toasts with the right name and icon for an app that has a registered AUMID shortcut.
5. **After install / upgrade:** the MSI must not start the tray as SYSTEM. It appears at next logon, or IT can push a one-off logon script. Single instance is enforced per session (`tauri-plugin-single-instance`). A second launch just opens the window.
6. **Uninstall:** remove the Run value and shortcut, then stop running `kestrel-tray.exe` instances (`taskkill /im kestrel-tray.exe /f` in a deferred custom action) before removing files.

The pipe server side (agent) must create `\\.\pipe\kestrel-tray` with a DACL that grants Authenticated Users read/write, and must create it first at service start. The tray refuses a pipe served outside session 0.

## Needs testing on real Windows

The following could not be checked from Linux:

- Mica rendering, flyout positioning on multi-monitor setups and on top or left taskbars, and per-monitor DPI
- the blur-to-hide and tray-click toggle timing
- toast branding with the installed AUMID shortcut
- `GetNamedPipeServerSessionId` against the real agent service
- the MSI / NSIS bundles produced by `npm run tauri build`
