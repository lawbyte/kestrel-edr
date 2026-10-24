# Detection quality: evaluation harness, corpus and the owner-PC baseline

Status 2026-10-25. Engine at workspace version 1.1.6 + uncommitted changes of the day.
Everything below is counts only; the only personal identifier kept is the replaced user name `j.doe`.

> **Fix round 2026-10-25 (section 8):** sections 4 to 6 describe the baseline *before* the fix round. After it: corpus malicious 125/125 (117 + 8 red-team scenarios), benign 47/47, benign-lookalike 15/15, ratchet empty; owner export Default policy 463 alerts and 13 containment actions (was 668 / 549), all of them on two processes whose signature the export does not carry; with those two signatures assumed, 347 alerts and 0 containment actions.

## 1. What exists

| Piece | Where | What it does |
|---|---|---|
| Harness | `crates/kestrel-detect/src/eval.rs` (`kestrel_detect::eval`) | Replays an event stream through a **fresh `Engine`** per policy with **deterministic time** (engine `tick` on a 250 ms grid of *event* time, a 10-minute drain at the end), catches engine panics, and reports per rule: alerts, distinct processes, images, severities and the response actions asked for (Protect = would-be actions). It also judges corpus scenarios against expect files and seeds processes that started before the agent (see 3.3). |
| Gate | `crates/kestrel-detect/tests/corpus_eval.rs` | A normal `cargo test`. Every scenario under `tests/corpus/{malicious,benign,benign-lookalike}` runs twice (all rules Audit, all rules Protect). It fails on any failure that is not listed in the known-failures ratchet, on a listed scenario that passes now (remove the entry), on a listed scenario that no longer exists, and on an `.expect.json` without its `.jsonl`. |
| Ratchet | `crates/kestrel-detect/tests/corpus/harness-known-failures.json` | `{"<class>/<scenario>": "reason"}`. Holds the detection gaps and false positives that are tracked but not fixed yet (29 today, section 6). `KESTREL_CORPUS_NO_BASELINE=1` ignores it. |
| CLI | `crates/kestrel-detect/examples/eval.rs` | `run` (full stream replay, human summary + JSON), `corpus` (the gate, with `--json`, `--no-baseline`, `--write-baseline`), `slice` (cuts anonymised scenario slices around alerts and activity samples and drafts their expect files), `scan` (flags anything that looks like personal data or a secret). |
| Benign corpus | `crates/kestrel-detect/tests/corpus/benign/` | 47 anonymised slices of the owner's real telemetry (4,371 events, 1.8 MB): 27 cut around the alerts the engine raises, 20 samples of normal activity. |
| CI | `.github/workflows/ci.yml`, Linux job | "Detection-quality gate" step: `cargo test -p kestrel-detect --test corpus_eval -- --nocapture` and `cargo run -p kestrel-detect --example eval -- corpus`. |

The malicious and benign-lookalike scenarios (`tests/corpus/malicious/`, `tests/corpus/benign-lookalike/`) are owned by the corpus author. The harness only reads them.

## 2. How to run

```powershell
# Gate (what CI runs). Prints every scenario with its alerts.
cargo test -p kestrel-detect --test corpus_eval -- --nocapture
cargo run  -p kestrel-detect --example eval -- corpus                  # same, as a CLI
cargo run  -p kestrel-detect --example eval -- corpus --no-baseline    # full state, ignores the ratchet

# Full replay of a telemetry export (JSON lines of Event, optionally .zst).
cargo run -p kestrel-detect --release --example eval -- run D:\kestrel-build2\corpus\owner-pc-2026-10.jsonl.zst `
    --signatures D:\kestrel-build2\corpus\owner-signatures.jsonl `
    --policies audit,protect,default --top 8 `
    --json D:\kestrel-build2\corpus\owner-run.json --alerts D:\kestrel-build2\corpus\owner-alerts.jsonl

# New benign slices from a run (anonymised; review them with `scan` before committing).
#    Personal identifiers are command-line input only, never in the source:
cargo run -p kestrel-detect --release --example eval -- slice <export> --alerts <alerts.jsonl> `
    --signatures <signatures.jsonl> --out <dir>\benign --max-alert-slices 34 --max-events 200 `
    --sample onedrive-storm=<guid>@<ts> `
    --replace <mail handle>=j.doe --replace <host>=WS-01 --replace <game handle>=player1 `
    --replace <private folder>=<neutral folder> --replace <user>=j.doe
cargo run -p kestrel-detect --example eval -- scan <dir> --needle <user> --needle <host> --needle <handle>
```

`slice` drafts `<name>.expect.json` from the slice's own replay (alerts above Low or with Protect actions go to `known_false_positives`, the rest to `allow`, notes `TODO`); fill in the FP ids by hand. The 47 slices in the repo were cut with `--max-alert-slices 34`, then 4 dropped (a duplicate of one WINWORD process, and alerts resting on a signature that telemetry does not have) and 4 renamed from `alert-*` to `sample-*` because they are quiet once the snapshot signature is known.

The full replay of 5.0 M events through three engines takes 28 s (release, one thread) and keeps memory bounded. `run` output (`owner-run.json`, `owner-alerts.jsonl`) contains raw personal paths and command lines; it stays in `D:\kestrel-build2\corpus\` and is never committed.

### Expect file format (`<scenario>.expect.json`)

Unknown keys are ignored (the corpus author's `family`, `category`, `sources`, `notes` are fine).

| Key | Meaning |
|---|---|
| `must_alert` | List of groups, **all** required (Audit run). A string is one rule; an array is any-of (`["ST-05", "ST-06"]`); an object `{"any_of": [...], "min_severity": "high"}` sets its own floor. `PREFIX*` matches by prefix (`"CD-*"`). |
| `min_severity` | Floor for every `must_alert` group without its own. |
| `should_alert` | Same syntax; a miss is a note, never a failure. |
| `must_not_alert` | No alert of these rules may fire, at any severity (every class). |
| `must_act` | The Protect run must ask for one of these actions (`kill_process`, `quarantine_file`, …). |
| `max_severity` | Benign classes: ceiling for unlisted alerts (default `low`). |
| `allow` | Benign classes: permitted alerts, `"ST-12"` or `{"rule", "max_severity", "actions": bool, "note"}`. |
| `known_false_positives` | Benign classes: alerts that are false positives today. They pass (Protect actions included) and are printed as `known FP`; an entry that no longer fires is printed as stale. Every entry carries the FP id of section 5. |
| `strict` | Benign classes: every alert must be listed in `allow` / `known_false_positives`. Default: true when the file has one of those lists (all slices in `benign/` set it explicitly), else false. |

Verdicts: `malicious/` needs an expect file with `must_alert` or `must_act`. `benign/` and `benign-lookalike/` fail on any alert above `max_severity` that is not listed, any unlisted alert when strict, and any Protect-mode containment action (`resume_process` excepted) that is not covered by a `known_false_positives` entry or an `allow` entry with `"actions": true`.

## 3. The owner-PC telemetry export

### 3.1 Source and statistics

* Server: local Docker deployment, ClickHouse `events` table (credentials from the deploy `.env`, used inside the container only, never printed). Read-only `SELECT`. Postgres `alerts` was read for comparison and for signer facts.
* Device: one PC (`WS-01` after anonymisation), three enrolments (agent reinstalls): 2026-10-21 15:32 to 17:16 UTC, 2026-10-21 17:22 to 2026-10-22 10:42, and 2026-10-23 13:20 to 2026-10-24 19:20 (cut-off). **No telemetry from 2026-10-22 10:42 to 2026-10-23 13:20** (26.6 h, agent not installed).
* 5,011,100 events, 189,256 process GUIDs, 187,931 process starts (signature: valid 150,131, unsigned 31,959, invalid 5,827, unknown 14).
* By kind: process_access 2,839,895 · file_access 1,079,922 · net_connect 255,119 · dpapi_unprotect 239,811 · process_start 187,931 · process_stop 187,921 · image_load 125,617 · dns_query 61,724 · file_activity 17,650 · script_block 7,897 · tamper 3,900 · registry_set 3,268 · task_registered 437 · service_installed 7 · wmi_subscription 1.
* 1,475,860 rows are byte-identical to another row (same millisecond, same content: OneDrive's handle-open storm, DPAPI and DNS bursts). They are real repeated events, not upload retries (no process_start is duplicated), and are kept.
* Export: `D:\kestrel-build2\corpus\owner-pc-2026-10.jsonl.zst` (37 MB, zstd level 9), one `Event` JSON per line, 0 unparsable lines. Signer facts: `D:\kestrel-build2\corpus\owner-signatures.jsonl` (109 images, from the live agent's alerts).

### 3.2 How rows map back to engine events

* The ClickHouse `raw` column is the agent's `Event` JSON after the server-side scrub, so the conversion is lossless for what was uploaded; the projected columns are not needed.
* Order: `ORDER BY greatest(ts, start_ts_of_process), event_type != 'process_start', ts`. A process's start always precedes its other events, even when the sensor stamped an event a few ms before the start record.
* `repeat_count` / `repeat_first_ts` (agents 1.1.7+, one summary row for N identical events) are expanded back into N events at the row's time (capped at 100,000). No row before the cut-off carries them (the 1.1.7 uploader arrived after it), so this export is unaffected.

### 3.3 What telemetry loses against the live sensor (limits of this baseline)

1. **Processes that started before the agent** have no `process_start` in telemetry: 1,325 GUIDs, 1,750,047 events (35 % of the stream; 1.36 M of them are OneDrive's handle opens). The live agent seeds them from a snapshot with image and Authenticode facts. The harness approximates that (`SeedBuilder`): image from other processes' `target_guid` / `target_image` (520 resolved), signature from a `process_start` of the same image elsewhere in the stream (460) or from the live agent's alerts (`--signatures`, 3 more), and `%SystemRoot%` images assumed Microsoft-signed (19, e.g. lsass.exe; without this, lsass "read" the Credential Manager 292 times). 805 orphans stay unknown (empty image). 122 of the 668 Audit alerts are on processes whose signature stayed unknown; 114 of them belong to one Discord process (section 5, FP-06).
2. **Late enrichment** (`Engine::enrich_process`: hash or signature resolved after the start budget, revocations) is not uploaded. 14 process starts carry `unknown` (e.g. `docker-scout.exe`, 4 ST-01 alerts); the live engine probably knew the signer.
3. **Old agent formats.** `file_activity` before 1.1.6 has no `self_created` (all of 2026-10-21); RW-06 cannot tell compiler output from existing files there (40 of the 43 RW-06 alerts).
4. **Not telemetry at all:** sensor write hints for evidence capture, the decoys the agent armed (ST-16 cannot fire in a replay unless the decoys are armed), the persisted ST-12 first-seen memory, the policy in force at the time (exclusions, custom Sigma: the live `SIG-a642964e` is not replayed), pause state, agent PID and server IPs.
5. **Events never uploaded:** whatever the sensors filter before the engine (file access is limited to credential-store, persistence and canary paths, image loads to a short list); ETW losses and outbox drops (the live server raised `TP-SRV-EVENTS-LOST` 4 times). Default privacy settings were in force (full command lines, user names not hashed, DNS captured), so nothing was truncated by the privacy filter.
6. **Ordering inside a millisecond** across processes is by ClickHouse sort, not arrival order; correlation windows can differ by a few ms from the live engine.
7. **ST-12 in Protect** deliberately suspends every run (no first-seen folding, review M1), so the Protect run counts every compiler process (section 4).

## 4. Full-run results (current engine)

Run with `--signatures`; 0 engine panics in all three runs.

* **Audit (every rule Audit): 668 alerts.**
* **Protect (every rule Protect): 26,032 alerts.** Standalone actions: resume 1,451, block_destination 85, kill_process 20.
* **Default policy (shipped modes): 668 alerts, 549 containment actions.** Standalone actions: block_destination 85, kill_process 8.

| Rule | Alerts (Audit) | Processes | Images | Severities | Protect run: alerts / would-be actions | Default policy: actions |
|---|---:|---:|---:|---|---|---|
| ST-01 Credential-store read by untrusted process | 225 | 147 | 52 | low 104, high 97, medium 24 | 225 / suspend 30 | - |
| ST-04 Steal-then-send | 175 | 48 | 23 | low 160, critical 14, high 1 | 175 / block_destination 24, kill 24, quarantine 4 | kill 18, block_destination 14, quarantine 4 |
| ST-14 Dead-drop / exfil service from non-browser | 103 | 4 | 3 | high 99, low 4 | 103 / block_image_network 99 | - |
| ST-07 Browser process tampering | 46 | 2 | 2 | critical 46 | 46 / kill 46 | kill 46 |
| RW-06 Mass file encryption behaviour | 43 | 43 | 1 | critical 43 | 43 / kill 240, quarantine 129 | kill 240, quarantine 129 |
| ST-12 Untrusted execution from user paths | 20 | 20 | 17 | low 16, medium 4 | **25,383 / suspend 25,383** | - |
| ST-05 Browser debugging abuse | 15 | 15 | 2 | high 15 | 15 / kill 30 | - |
| TP-02 WFP filter tampering | 13 | 3 | 1 | critical 13 | 13 / - | - |
| ST-03 Foreign DPAPI unprotect of browser secrets | 11 | 11 | 9 | high 6, low 5 | 11 / suspend 4 | - |
| CD-06 Blocked LSASS access attempt | 9 | 9 | 5 | low 7, high 2 | 9 / suspend 2 | - |
| ST-02 Smash-and-grab credential collection | 4 | 3 | 2 | critical 4 | 5 / kill 6 | kill 4 |
| CD-13 LSA protection / Credential Guard tamper | 2 | 2 | 1 | medium 2 | 2 / - | - |
| CD-02 Known LSASS dumping tool | 1 | 1 | 1 | critical 1 | 1 / kill 1 | kill 1 |
| ST-08 Chrome elevation-service abuse | 1 | 1 | 1 | medium 1 | 1 / - | - |

Top images (Audit): ST-01 rustc.exe 52, OneDrive.Sync.Service.exe 34, WINWORD.EXE 32, Discord.exe 12 · ST-04 WINWORD.EXE 53, OneDrive.Sync.Service.exe 43, MicrosoftStartFeedProvider.exe 28, com.docker.build.exe 15 · ST-14 Discord.exe 98, wslservice.exe 4, Xeno 1 · ST-07 WhatsApp.Root.exe 42, Discord.exe 4 · RW-06 rustc.exe 43 · ST-12 light.exe, Xeno 1.3.60, Xeno 1.3.65 (2 each), cargo, protoc, wix, makensis, cargo-fmt, clippy-driver, … · ST-05 chrome.exe 12, msedge.exe 3 · TP-02 kestrel-agent.exe 13 · ST-02 dllhost.exe 3, copilotapp.exe 1 · CD-02 grep.exe 1.

**What the Default policy would have done to this PC in four days:** kill and quarantine `rustc.exe` 43 times during builds (RW-06), kill WhatsApp's background process 42 times (ST-07), kill `dllhost.exe` 3 times, Discord 7 times, Docker buildx, VS Code, the Copilot app, Internet Download Manager and NordVPN's service (ST-04 / ST-02), kill a `grep` (CD-02), and both Xeno runs. Nothing on this PC was a stealer (section 5), so every one of those would have been a false positive.

**Against the live agent** (older engines, same window, Postgres `alerts`): 16,555 alerts, of which ST-12 14,986 (before the 7-day first-seen memory), ST-01 876, RW-06 261, ST-04 177, ST-07 49, RW-08 49, ST-02 43, ST-14 39. The current engine is down to 668 (ST-12 20, RW-08 0, ST-02 4).

**Sensitivity:** if Discord 1.0.9262 is assumed signed like 1.0.9263 / 1.0.9265 (Discord Inc.), the Audit run drops to 554 alerts: ST-14 98 → 0, ST-01 12 → 0, ST-07 4 → 0. The benign slices are cut with that assumption so they do not encode a harness artefact as a known FP.

## 5. Every remaining alert, classified

None of the 668 alerts is a true positive for a stealer, ransomware or credential dumper. Classification per group (rule, image, Audit count):

| # | Rule / image (count) | Verdict | Why |
|---|---|---|---|
| FP-01 | ST-01 high/medium: rustc 52, build-script-build 9, conhost 7, bash 6, grep 3, powershell 4, wsl 2, cargo 2, clippy-driver 2, sed 2, head, timeout, rustdoc, a test binary (1 each); low: cl, link, lib (1 each) | **False positive** | Each "reads" `C:\Users\j.doe\.docker\config.json` (sometimes `.docker\contexts\…`) once, 9-67 s into its life, with no code path that would do so (`head -20`, `sed -n`, `conhost 0x4`, `cl.exe` compiling zstd). `docker.exe` opens that file 58,774 times (polled by Docker Desktop / the VS Code extension); about 150 opens land on unrelated short-lived processes. PID reuse was checked and is not it (the previous holders of those PIDs were not Docker). Root cause: probably **sensor attribution** (Kernel-File create attributed to the wrong process; DECISIONS.md already suspects the same for dllhost's Vault read). Needs a live repro (Procmon + `sensors-test`). One bash alert is different: a bash command line logged as a file path containing a wallet name (sensor path-naming defect). |
| FP-02 | ST-04 critical docker-buildx 3, ST-01 medium docker-buildx 3, ST-01 high docker-scout 4, ST-04 high docker.exe 1; low by design: com.docker.build 15 + 3, docker-* CLI plugins 12, Docker Desktop 5 + 2 | **False positive** | Docker's own signed (Docker Inc, Program Files) tools reading `~\.kube\config` and `~\.docker\config.json`. The dev-tool exemption downgrades single-store reads to Low, but not when buildx (child of docker-compose) reads both stores and then talks to `auth.docker.io`, nor when the signature is unknown (docker-scout, late enrichment not in telemetry), nor when the "send" is the parent Code.exe. Root cause: ST-01 / ST-04 developer-credential exemption is too narrow (parent chain, two stores, vendor endpoints). |
| FP-03 | WAM token-broker cache: ST-04 low WINWORD 53, OneDrive 43, StartFeedProvider 28, opushutil 2, Calendar, GamingServices; ST-01 low WINWORD 32, OneDrive 34, StartFeedProvider 5, opushutil 4, Code 3; **ST-04 critical Code.exe 2**, low 2 | Low ones: **expected noise by design**. Code.exe critical: **false positive** | Microsoft-signed apps reading `TokenBroker\Cache\*.tbres` (they are WAM clients). With the real signature they are Low (the live agent, older engine, raised 30 critical on WINWORD). VS Code (per-user install in AppData) read the WAM cache and then connected to `api.github.com` (GitHub sign-in, a non-Microsoft endpoint): the "Microsoft endpoint only" condition fails, critical + kill in Default. Root cause: the WAM exemption keys on destination, and GitHub sign-in through VS Code is normal. |
| FP-04 | ST-03 high Discord 3, ST-04 critical Discord 3, ST-03 high Code.exe 1; Copilot app: ST-01 medium 2, ST-04 critical 2, ST-02 critical 1; low by design: Claude, OpenVPN Connect, Docker Desktop | **False positive** | Electron / WebView2 apps decrypting **their own** safeStorage key (DPAPI description "Chromium") or reading **their own** embedded profile (`AppData\Local\Microsoft\Copilot\User Data\Default\Network\Cookies`, `Local State`). The exemption needs a signed Program Files install; Discord and VS Code are per-user installs in AppData, and the Copilot app's profile is treated as a third-party browser. Root cause: "own profile" is not recognised for per-user Electron apps and WebView2 hosts (the store's owning app is the reader). |
| FP-05 | ST-07 critical WhatsApp.Root.exe 42, Discord.exe 4 | **False positive** | WhatsApp (MSIX package from WindowsApps: individual binaries carry no Authenticode, so "unsigned") opens its own `msedgewebview2.exe` with 0x1F0FFF; Discord opens `brave.exe` with 0x410 (game / activity presence detection). Default policy kills WhatsApp's background task 42 times. Root cause: ST-07 does not recognise a WebView2 host opening its own WebView2 child, nor MSIX package identity as trust; 0x410 (query + read) on a browser from a signed messenger is presence detection. The Discord part disappears when its signature is known. |
| FP-06 | ST-14 high Discord.exe 98; low by design wslservice 4 | **Harness artefact** for Discord; wslservice expected | Discord resolving `discord.com` / `cdn.discordapp.com`. `domain_owner_ok` accepts Discord.exe for its own domain only with a trusted signature; this Discord process started before the agent and no source in telemetry names its signer (sensitivity run: 0 alerts when signed). wslservice is Low by design (DNS proxy for WSL guests); with an unknown signature it was High (93) before `--signatures`. |
| FP-07 | RW-06 critical rustc.exe 43 (kill 240 + quarantine 129 in Default) | **False positive** | `cargo` builds write `.tmp` and rename them to `.rlib`. 40 alerts are 2026-10-21 telemetry from agents before 1.1.6 (no `self_created`). **3 are current-format** (2026-10-24, `kestrel-tray` builds): 100 files touched, 50 renames, 50 new, 50 self-created: the 50 rename destinations count as "existing files rewritten". Root cause: rename destinations of self-created files are not credited as self-created (or `files_touched - max(new, self_created)` over-counts when a rename touches two names). Highest-impact FP: RW-06 is Protect from day one. |
| FP-08 | ST-05 high chrome.exe 12, msedge.exe 3 | **False positive** (technique-identical) | Playwright (`node.exe`) launching Chrome / Edge with `--remote-debugging-pipe`, `--headless` and a fresh temporary `--user-data-dir` (console screenshots, tests). Same technique as CDP cookie theft, but against an empty throw-away profile. Distinguishing evidence: the profile directory is a new temp folder (not the real `User Data`), no read of the real cookie store, the parent is a test runner under a project folder. The corpus author's `benign_playwright_tests_cdp` lookalike fails for the same reason (baselined). |
| FP-09 | CD-02 critical grep.exe 1 | **False positive** | `grep -n lsass\|0x1410\|VM_READ -r src/…`: the word lsass in a search pattern matched "procdump-style arguments (renamed tool)". Default policy kills. Root cause: CD-02's renamed-tool heuristic matches argument text without requiring a dump flag together with an LSASS PID / name as the target argument, and does not exclude text tools. |
| FP-10 | TP-02 critical kestrel-agent 13 | **False positive** | Windows Firewall / BFE replacing its own filters (`windefend_auth_recv_accept_v4`, `InternetClient Default Rule`, … with BFE's own provider, change "add") during profile changes and Hyper-V / WSL network setup. Root cause: TP-02 treats every WFP change at ALE layers that can affect the agent as tampering; Windows Firewall's own filter refreshes need to be recognised (provider BFE / Windows Defender Firewall, filters not referencing Kestrel's sublayer). The live agent raised the same 13. |
| FP-11 | CD-06 high RobloxPlayerBeta 2; low by design BraveUpdate 3, nvcontainer 2, IDM 1, EA Desktop 1 | High: **false positive**; lows expected | Roblox's anti-cheat (Hyperion) asks for 0x40A on LSASS and is refused. Signed (Roblox Corporation), user-profile install, so the "signed Program Files service" downgrade does not apply. Root cause: CD-06's downgrade keys on install location; a refused open by a validly signed game client is not an attack in progress. |
| FP-12 | CD-13 medium 2 | **False positive** (benign, rule literal) | NordVPN (re)installing its own kernel drivers from `C:\Program Files\NordVPN\…\travis.sys` / `NDivert.sys`; the change was not attributed to a process. Medium for a signed vendor driver in Program Files is noisy; checking the driver's signer before alerting would settle it. |
| FP-13 | ST-02 critical dllhost.exe 3, ST-01 medium dllhost 3 | **False positive / unclear** | `DllHost.exe /Processid:{DFB65C4C-B34F-435D-AFE9-A86218684AA8}` opening **directories**: `ProgramData\Microsoft\Vault`, `.aws\cli\cache`, and the MetaMask folders of the `Kometa` and `7Star` browsers, which are **Kestrel's own decoys**. Directory opens are enumeration (a shell / indexer COM server), not reads. Root cause: ST-02 counts directory opens of store folders as collection; plus the attribution question of FP-01. Default policy kills dllhost 3 times. |
| FP-14 | ST-12 Audit low 16 / medium 4 (cargo, rustc, rustfmt, clippy, protoc, WiX, NSIS, Xeno); **Protect: 25,383 alerts and 25,383 suspends** | Audit: expected (rule intent met: unsigned binaries in the user profile); Protect: **operational false positive** | In Protect every run of an unsigned user-profile binary is suspended and judged (review M1), so every `rustc` invocation of a build is suspended. ST-12 must stay Audit on developer PCs, or Protect needs a first-seen / allow-by-hash path for toolchains. |
| FP-15 | ST-04 critical IDMan.exe 1, ST-01 medium 1 | **Unclear (by design)** | Internet Download Manager (signed Tonec, Program Files) reads Brave's `Cookies` and `Local State` to download with the user's session, then talks to its CDN. Behaviourally identical to cookie theft; vendor-intended. Candidate for a documented allow-list entry rather than an engine change. |
| FP-16 | ST-01 medium claude.exe 2 | **False positive** | The Claude desktop app (signed Anthropic, MSIX) reads Chrome's `Local State` (browser-extension integration). Reads only the key container, no cookie / password store, no send. |
| FP-17 | ST-01 high + ST-04 critical nordvpn-service.exe | **Harness artefact (likely)** | NordVPN's service reading its own settings under the SYSTEM profile; the process started before the agent and its signature is unknown in telemetry. |
| FP-18 | ST-08 medium Brave elevation_service 1 | **False positive** | Brave's updater closed Brave twice and the elevation service started 254 ms later without a relaunch (update flow); caller unknown. |
| X-01 | Xeno 1.3.60 / 1.3.65: ST-12 medium 4, ST-03 high 2, ST-04 critical 2, ST-14 high 1 | **Unclear: not a stealer, a game-cheat injector (PUA)** | See below. |

### The Xeno run (Roblox executor), what the engine sees and what would separate it from a stealer

**What happened** (1.3.65, 2026-10-24 16:06 UTC; 1.3.60 identical six minutes earlier):

1. `D:\games\tools\Xeno-v1.3.65.exe` (88 MB, Authenticode present but **invalid**, self-signed "Rizve A", no Mark of the Web) unpacks itself to `%TEMP%\<random 27 chars>\Xeno-v1.3.65.exe` (163 MB, **unsigned**) and starts it; the launcher exits.
2. The Temp copy is an **Electron app**: GPU, network-service, renderer and audio children with `--user-data-dir=%APPDATA%\Xeno` and `--app-path=%TEMP%\…\resources\app.asar`.
3. Within a second of its start the main process calls `CryptUnprotectData` with description **"Chromium"** once: Electron's `safeStorage` / os_crypt key of **its own** profile (`%APPDATA%\Xeno\Local State`). No file of any browser, wallet, Discord or Telegram store is opened (only files under `%LOCALAPPDATA%\Xeno\workspace\…`: dumped Roblox Lua scripts, 15 distinct files).
4. The network-service child sends **1,250 bytes over UDP to 172.66.44.125:443** (Cloudflare): a QUIC Initial packet, which Chromium pads to 1,250 bytes. This is a handshake, not an upload.
5. The main process resolves **pastebin.com** twice and opens TLS to it (bytes sent not recorded: a fetch of its version / key / script list); later it uploads up to 75 KB to `api.lua.expert` (a Luau decompiler API: the dumped scripts), and its children talk to Roblox (128.116.x.x).
6. It opens `RobloxPlayerBeta.exe` with **PROCESS_ALL_ACCESS (0x1FFFFF)**: the injection an executor exists for. No Kestrel rule fires on that (ST-07 covers browsers, CD-xx covers LSASS).

**What the engine concludes:** ST-12 medium (unsigned, 155 MB "padded", Temp, from a parent of the same name); ST-03 high (foreign "Chromium" DPAPI unprotect by an unsigned Temp binary); ST-04 critical (that unprotect counted as "read Chromium DPAPI-protected secrets", followed 0.6 s later by a child's 1,250 B connection); ST-14 high (pastebin lookup by a non-browser). In the Default policy ST-04 kills the tree, blocks the destination and quarantines the Temp copy.

**Verdict:** not a stealer on this evidence; a potentially unwanted game-cheat injector from an untrusted publisher, run deliberately by the owner. ST-12 is right on its own terms. ST-03 / ST-04 / ST-14 are wrong for the reasons they give.

**Evidence that would distinguish it from a stealer** (all of it is available to the engine or the sensors):

* **Which blob was unprotected.** A stealer reads another app's `Local State` (Chrome / Edge / Brave) *before* unprotecting; Xeno read no foreign `Local State`, and its profile is its own `--user-data-dir`. Linking a "Chromium" unprotect to a preceding foreign `Local State` read (or to its absence) separates the two; today ST-03 / ST-04 take the description alone.
* **Volume and shape of the "send".** 1,250 B UDP to 443 is a QUIC Initial; exfiltration is an upload of tens of KB to MB (ZIP of browser profiles) to Telegram / Discord webhooks / a raw IP / a fresh domain. ST-04 should require bytes sent above a floor, or TCP / QUIC with a body, before "steal-then-send" turns critical.
* **No store access at all.** Stealers open dozens of store paths across browsers and wallets within seconds (ST-02's domain); Xeno opened none.
* **pastebin direction.** A GET of a few hundred bytes is a dead-drop *read* (also what loaders do, so ST-14 is a fair hunting signal at Low); a stealer uses it for config too, so the lookup alone should not be High.
* **Parent and origin.** Launched by the user from Explorer, not from a browser download, script host or Run dialog; no MOTW. (A ClickFix stealer arrives via `mshta` / PowerShell / Run-dialog, which ST-10 / ST-11 cover.)
* **What it does instead:** full-access open of a game process. A PUA / injection rule (`EX-xx` family: unsigned Temp binary opening another user process with VM_WRITE + CREATE_THREAD) would describe Xeno correctly.

## 6. Corpus state today

* `benign/`: 47 / 47 pass. 27 slices are cut around alerts and pin the false positives above as `known_false_positives` with their FP id (they print as `known FP`; a fix that silences one prints "no longer fires: remove it"). 20 are activity samples (cargo build / test, Docker CLI and plugins, WSL, VS Code, Brave, Edge, Chrome, the OneDrive handle storm, NVIDIA, Steam, WhatsApp, Discord (4), Roblox, Xeno). Office has no sample: WINWORD started before the agent in every enrolment, and its alert slices rest on that unknown start.
* `benign-lookalike/`: 14 / 15 pass; `benign_playwright_tests_cdp` fails with FP-08 (baselined).
* `malicious/`: 89 / 117 pass. 28 fail: these are detection gaps found by the corpus author's scenarios (ST-04 not raised when the send is delegated to a child / BITS / curl / a slow 10-minute exfil, ST-02 not raised for several evasions, RW-06 not raised for rename-over-original and 30-second pacing, CD-10 / CD-11 for wbadmin NTDS backups, ST-07 in the DeerStealer chain, …). All 28 are listed with their first failure in `harness-known-failures.json`.

### Anonymisation of the benign slices

`slice` replaces the owner's user name and host name (→ `j.doe`, `WS-01`; a game-account variant of the handle → `player1`), e-mail addresses, the machine SID part of `S-1-5-21-…`, and a personal project folder name; drops command-line arguments with tokens, passwords, keys, signatures, session / cookie values, URLs with a query string or user-info, and opaque blobs of 40+ characters; replaces every host name outside a fixed list of infrastructure domains (Microsoft, Google, Brave, Docker, GitHub, Steam, Discord, Roblox, NVIDIA, WhatsApp, pastebin and the policy's exfil-domain list) by `h<hash>.example.net` consistently; drops file paths that name visited sites (IndexedDB origins, service-worker scopes, history / session databases); truncates script blocks to 2,000 characters. `scan` then flagged 221 lines; every one was reviewed: TokenBroker cache file names (hashes), Docker context directories (sha256 of the context name), Chromium's "Trust Tokens" file, a `windows-sys` feature name, Brave component-cache hashes, Docker's `.token_seed` file name and a website image file name. No secret, token, e-mail address, browsing destination or private path other than `j.doe` remains.

## 7. Notes for whoever fixes the FPs

* Fix order by impact under the Default policy: FP-07 (RW-06 kills rustc), FP-05 (ST-07 kills WhatsApp), FP-01 (attribution; touches ST-01 / ST-02 / ST-04 everywhere), FP-04 / FP-03 (Electron and WebView2 own stores; VS Code GitHub sign-in), FP-13, FP-09, FP-10, FP-14 (ST-12 Protect on developer PCs).
* After a fix: rerun `run` on the export to update section 4, then `corpus`: the slice's `known_false_positives` entry prints as stale; remove it (the gate keeps passing). For a malicious gap, remove its entry from `harness-known-failures.json` (the gate fails while a listed scenario passes).
* New real-world false positives: cut a slice with `slice` (with `--signatures`), run `scan`, review, copy into `tests/corpus/benign/`, set the FP id in its notes.

## 8. Fix round 2026-10-25: before and after

What changed is recorded in `docs/DECISIONS.md` (entry "Detection fix round", 2026-10-25). Same export, same harness, with `--signatures`. The harness now also applies `--signatures` facts as late enrichment to a `process_start` whose signature is `unknown` (what the live agent's `Engine::enrich_process` does); before, only processes that started before the agent used them. 0 engine panics in every run.

### 8.1 Numbers

| Measure | Before | After | After, two signatures assumed* |
|---|---:|---:|---:|
| Corpus malicious | 89 / 117 | 125 / 125 (117 + 8 red-team scenarios) | |
| Corpus benign / benign-lookalike | 47 / 47, 14 / 15 | 47 / 47, 15 / 15 | |
| Ratchet entries (`harness-known-failures.json`) | 29 | 0 | |
| Audit run: alerts | 668 | 463 | 347 |
| Protect run: alerts / containment actions | 26,032 / 25,383 suspends + 129 others | 497 / 201 (54 ST-12 suspends, 99 ST-14 image blocks, 18 ST-01 suspends, ...) | 381 / 65 |
| **Default policy: alerts / containment actions** | 668 / 549 | **463 / 13** | **347 / 0** |

\* Discord 1.0.9262 (`Discord Inc.`, like the 1.0.9263 / 1.0.9265 builds the export does carry) and `nordvpn-service.exe` (`nordvpn s.a.`, the subject seen on this PC by the signer research) both started before the agent and no source in the export names their signer, so the harness treats them as unsigned. File: `D:\kestrel-build2\corpus\owner-signatures-assumed.jsonl` (not in the repository).

Per rule, Audit run (after): ST-04 170 (low 164, high 5, critical 1), ST-01 116 (low 98, medium 4, high 14), ST-14 103 (high 99, low 4), ST-12 20, ST-05 15 (all low), TP-02 13 (all low), ST-03 11 (high 2, low 5, info 4), CD-06 9 (low 8, high 1), ST-07 4, CD-13 2 (low). RW-06, ST-02, ST-08 and CD-02 no longer fire.

### 8.2 The 13 remaining Default-policy containment actions

| Rule / image | Actions | Why it remains |
|---|---|---|
| ST-07 critical, Discord 1.0.9262 opening `brave.exe` with 0x410 (×4) | kill, quarantine | Harness artefact: the process predates the agent and its signature is unknown, so it is an "untrusted actor". With the signature known (the 1.0.9263 / 1.0.9265 builds are `Discord Inc.`) it is a genuine per-user Discord and ST-07 does not apply (0 actions in the assumed run). |
| ST-04 critical, `nordvpn-service.exe` reading its own `user.config` under the SYSTEM profile, then 1.1.1.1:443; plus 7 standalone blocks of later connections | kill, block | FP-17, harness artefact of the same kind (unknown signature of a process that predates the agent). With the signature known it owns its store. |

### 8.3 Every remaining Audit alert above Low, explained

| Count | Rule / image | Verdict |
|---:|---|---|
| 98 + 12 + 4 | ST-14 high, ST-01 high, ST-07 critical: Discord 1.0.9262 | Harness artefact (unknown signature, see 8.2); 0 with the signature known. |
| 2 | ST-01 high + ST-04 critical: `nordvpn-service.exe` | Harness artefact (FP-17). |
| 3 | ST-01 medium: `dllhost.exe` opening `Telegram Desktop\tdata\dumps` | Expected by design: trusted Windows binaries are no longer exempt for messenger / wallet / browser stores (corpus finding 1: hollowed `dllhost` / `credwiz` / `OpenWith`). A shell COM surrogate enumerating the Telegram folder. Medium, Audit, no action. |
| 1 | ST-01 medium: `backgroundTaskHost.exe` opening `.docker\config.json` | Unexplained, most likely the FP-01 attribution artefact of the pre-1.1.6 agents (a background task has no reason to read it); Audit, no action. |
| 1 | ST-01 high: `bash.exe` | FP-01, a command line logged as a file path (sensor naming defect in the old agents). |
| 2 + 2 + 1 + 4 | Xeno 1.3.60 / 1.3.65: ST-03 high, ST-04 high, ST-14 high, ST-12 medium | X-01, by design without the new sensor evidence: the "Chromium" key decrypt by an unsigned Temp binary stays ST-03 High, and ST-04 is High Audit without containment (only a "Chromium" key, no credential store opened by it or its tree). The pastebin lookup is ST-14 High. With the 2026-10-25 sensor's own-profile `Local State` event the decrypt becomes ST-03 Info and no ST-04 (tested with synthetic fixtures, `tests/fix_round.rs`). |
| 1 | ST-04 high: VS Code (per-user) after a WAM read, `api.github.com` | FP-03 decision: GitHub sign-in calls the API, but the API can create gists; High Audit, no kill. `github.com`, `*.githubcopilot.com` and `copilot-telemetry.githubusercontent.com` are Low; Application Insights ingestion is High Audit. |
| 1 | ST-04 high: `com.docker.build.exe` after reading kubeconfig, `sessions.bugsnag.com` | By design: a developer tool sending to a host that is not its publisher's or provider's endpoint (a third-party crash reporter where anyone can have an account) is High Audit, no kill. |
| 1 | ST-04 high: Copilot app after a WAM read, connection to an IP with no DNS name | By design: a WAM read followed by a send to an address without a name is High Audit. |
| 1 | CD-06 high: `RobloxPlayerBeta.exe` (genuine) refused at LSASS | Correct: this Roblox instance had been opened with full access by the Xeno executor (taint), so the genuine-client downgrade no longer applies. The other probe is Low (FP-11). |

Low / Info alerts (alert only, folded): WAM reads by Word, OneDrive, the Start feed provider, opushutil, VS Code and their sends to Microsoft services (FP-03 "expected noise by design"); Docker tools reading Docker / kube stores and talking to Docker (FP-02); NVIDIA's Steam `config.vdf` scan; ST-05 Low for Playwright (FP-08); TP-02 Low for Windows Firewall (FP-10); ST-12 Low for first-seen toolchain binaries; ST-03 Low / Info for Electron apps' own keys (FP-04); CD-06 Low for BraveUpdate / nvcontainer / Roblox; CD-13 Low for NordVPN's drivers (FP-12); ST-14 Low for WSL.

### 8.4 Status of FP-01..FP-18

| FP | Status |
|---|---|
| FP-01 | Sensor artefact of pre-1.1.6 agents (PID reuse; confirmed and fixed in the 1.1.6 sensor). Engine: reads stamped > 5 s after the process's stop are dropped; no engine allowance. One `bash` command-line-as-path alert and possibly the `backgroundTaskHost` one remain. |
| FP-02 | Fixed: Docker Inc tools are developer tools for Docker / kube stores (exact signer); `--file -` is not an eval switch; ST-04 Low to Docker endpoints. `docker-scout`'s slice keeps its known FP (signature unknown in that slice). |
| FP-03 | Fixed (decision above). |
| FP-04 | Fixed: identity-based own key (per-user Discord, VS Code), Copilot's own embedded profile, Info with own-profile evidence. Xeno: see 8.3. |
| FP-05 | Fixed: MSIX package hosting (WhatsApp); Discord's 0x410 part is the signature artefact. |
| FP-06 | Harness artefact (Discord 1.0.9262 signature). |
| FP-07 | Fixed (RW-06 compiler / build-tree discounts, current and old agents). |
| FP-08 | Fixed (ST-05 Low for Playwright temporary profiles). |
| FP-09 | Fixed (CD-02 target argument). |
| FP-10 | Fixed (TP-02 Low). |
| FP-11 | Fixed (CD-06 Low for the genuine client, unless tampered). |
| FP-12 | Fixed (CD-13 Low for NordVPN's two drivers at their exact paths). |
| FP-13 | Fixed (store-folder opens are not reads). |
| FP-14 | Fixed: ST-12 Protect folds a binary after 3 resumes (Protect run: 25,383 → 54 suspends). |
| FP-15 | Fixed (IDM benign browser-integration reader, exact signer). |
| FP-16 | Fixed (Claude desktop app, `Local State` only). |
| FP-17 | Harness artefact (signature unknown). |
| FP-18 | Fixed (browser update window). |

### 8.5 Red team

Two rounds of a fresh, read-only reviewer acting as a malware author. Round 1: an unpinned minor-browser name (Thorium, Kometa, LibreWolf, ...) or wallet name with any valid certificate in the profile, and the same name written to Program Files, were "genuine" owners (fixed: only names pinned by the publisher table are browsers; unpinned owner names in their own folder are alert-only "own-folder readers" whose sends are judged by destination). Round 2: an `unknown`-signature side-loaded DLL in a pinned per-user Chrome folder, early-bird injection into a browser the stealer launched itself, and Office macros sending WAM tokens or developer credentials to customer-owned Azure names (`*.blob.core.windows.net`, `*.cloudapp.azure.com`) (fixed: unknown DLLs with side-load names taint; a browser launched by an untrusted process owns only its own vendor's stores and key; customer namespaces are never first-party or developer-tool endpoints; Office hosts are never developer tools). All 8 scenarios are in `tests/corpus/malicious/`.

### 8.6 Known gaps

* **Unknown-signature DLLs with ordinary names** loaded into a pinned per-user application (the sensor enriches DLLs without blocking) do not taint; only side-load names and Chromium core DLLs outside a version folder do. Fix belongs in the sensor (re-feed late DLL facts, or block briefly for DLLs loaded from user-writable folders into signed processes).
* **Unpinned owners**: a stealer with a purchased certificate placed in an unpinned app's own folder (`%LOCALAPPDATA%\Coinomi\coinomi.exe`) reading that app's store gets ST-01 Low and a High Audit ST-04 towards a named host (full response for a raw IP or an exfiltration service). Extending the publisher table closes this per app.
* **Minor browsers** installed per user (LibreWolf, Waterfox, Floorp, Zen, Thorium, Epic) are no longer browsers for the engine's shortcuts: their own-profile reads are Low alerts, a cross-browser import or their own DPAPI key raise ST-01 / ST-03. Add publisher entries when their signers are verified.
* **Office macros** (no DLL load) reading the WAM cache and uploading to SharePoint / Graph stay Low (Office talks to those services); an XLL or other side-load taints Excel.
* **Small QUIC uploads**: a UDP/443 upload is only seen as a send once the flow reports 64 KB.
* **8.3 paths** are only expanded for a fixed vocabulary of store components. The sensor's prefilter forwards them (`paths::may_be_sensitive_short`, since the 1.1.7 integration).
* **ProcessFacts for DLLs, ServiceInstall signer**: no contract field exists; CD-13's NordVPN allowance is path-only.
