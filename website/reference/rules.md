# Detection rules

Kestrel ships 55 built-in behavioural rules and a 70-rule SigmaHQ pack. This table is taken from the engine's catalog (`Engine::catalog()`, `crates/kestrel-detect/src/catalog.rs` and `families/`). **Protect** in the Default column marks the *safe on day one* set; everything else starts in Audit. The console's **Rules** page shows each rule's full logic, ATT&CK techniques, Protect action, references and known false positives.

<Shot src="img/diagrams/detection-flow.svg" alt="Detection and response flow" />

## How detection works

* **Behaviour, not allow-lists.** Rules look at what a process does: which credential store it opened, whether it then connected out, whether it touched LSASS or wrote an autorun. There is no general "never kill this app" list; false positives are fixed per rule, with exclusions or by the rule's own checks of the owning application and signature.
* **Per-process correlation.** The engine keeps short-lived state per process (secret categories touched, evidence events, DNS answers), which lets rules like ST-02 and ST-04 combine several events and lets the server explain what was at risk.
* **One path for every hit.** The mode comes from the policy (Off drops the hit). The agent itself and PIDs 0 and 4 are never subjects. An Allow IOC on the file's SHA-256 or signer suppresses all rules. Exclusions are applied. Duplicates are dropped (one alert per rule per process per 10 minutes, except escalations). In Audit the alert carries no actions; in Protect it carries actions, filtered by the response safety rules.
* **Unknown signatures are never trusted.** The first start of a new program is held up to 750 ms while it is hashed and its signature checked. Facts that arrive later re-run hash IOCs and the rules that depend on them.

## Stealer rules (ST)

| Id | Rule | Severity | Default |
|---|---|---|---|
| ST-01 | Credential-store read by untrusted process | Medium | Audit |
| ST-02 | Smash-and-grab credential collection (3 or more secret categories in 60 s) | Critical | **Protect** |
| ST-03 | Foreign DPAPI unprotect of browser secrets | High | Audit |
| ST-04 | Steal-then-send (credential read, then external connection within 300 s) | Critical | **Protect** |
| ST-05 | Browser debugging abuse (`--remote-debugging-*` with headless or alternate profile) | High | Audit |
| ST-06 | Local CDP client (non-browser connects to the DevTools port) | High | Audit |
| ST-07 | Browser process tampering (memory access, injection, debugger attach) | Critical | **Protect** |
| ST-08 | Chrome elevation-service abuse | High | Audit |
| ST-09 | Foreign crypto library load (`nss3.dll`) | Medium | Audit |
| ST-10 | ClickFix Run/Address-bar artefact (RunMRU, TypedPaths) | High | Audit |
| ST-11 | Paste-and-run process chain | High | Audit |
| ST-12 | Untrusted execution from user paths | Low | Audit |
| ST-13 | .NET LOLBin hollowing | High | Audit |
| ST-14 | Dead-drop / exfil service from non-browser (Telegram, Steam, Discord webhooks and others) | High | Audit |
| ST-15 | Trusted-binary sideload from user path | High | Audit |
| ST-16 | Canary tripwire | Critical | **Protect** |

ST-01, ST-03 and ST-12 use **suspend on suspicion** in Protect mode: the process is frozen for the policy's suspend window and killed only if a strong rule (ST-02, ST-04, ST-07, ST-16) confirms the theft, or if it is unsigned and runs from a user-writable folder. ST-16 kills the reader, blocks its network for 24 hours and quarantines it; it isolates the host only when the reader is unsigned and runs from a user-writable folder. A genuine browser or password manager installed under Program Files reading a decoy gets an Audit alert only.

Developer-tool credential stores (kubeconfig, Docker `config.json`, AWS credentials and SSO cache, Azure CLI token cache, Google Cloud SDK credentials) are read by many developer tools as part of normal work. When the reader is validly signed, installed under Program Files or WindowsApps on the system volume, is not an interpreter, script host or LOLBin, has no script, eval, inspector or remote-debugging argument and was never injected into, ST-01 raises a Low Audit alert and a following ST-04 is Audit only: no kill, no block. Browser, wallet, messenger and Windows credential stores are not covered by this. Interpreters such as `python.exe` or `node.exe` are not owners of the AWS, Azure CLI or Google Cloud stores, so their reads raise ST-01. Only the official CLI layouts are owners: the Azure CLI's bundled `python.exe` under `Program Files\Microsoft SDKs\Azure\CLI2` running `azure.cli`, and the Google Cloud CLI's bundled `python.exe` running that SDK's `gcloud.py`.

ST-04 also looks at where the data went. When a validly signed reader outside Temp and Downloads (interpreters included) read only one provider's developer-tool stores (AWS, Azure CLI, Google Cloud SDK or Docker) and the connection goes, by DNS name, to that provider's own service endpoints (for example `s3.ap-southeast-1.amazonaws.com`, `login.microsoftonline.com`, `oauth2.googleapis.com`, `registry-1.docker.io`), ST-04 is a High Audit alert with no kill and no block. That is normal SDK and CLI use, but it would also fit an attacker using the stolen credentials, so review it. A connection to any other host, to an IP address without a resolved name, an unsigned reader, or a read of any other store (kubeconfig included) gets the full response.

When ST-04 sees the connection come from the reader's parent, and that parent is validly signed under Program Files by the same signer as the reader (for example Docker Desktop's `com.docker.backend.exe`), only the reader is killed: the parent, its process tree and the destination are left alone. A validly signed sender installed under Program Files gets a destination block for its own image, not for the whole host, so a shared CDN address is not cut for every program.

## Ransomware rules (RW)

| Id | Rule | Severity | Default |
|---|---|---|---|
| RW-01 | Shadow copy / backup catalog deletion | Critical | **Protect** |
| RW-02 | Boot recovery disabled | Critical | **Protect** |
| RW-03 | Safe-mode boot staging | Critical | **Protect** |
| RW-04 | Event log cleared or shrunk | Medium | Audit |
| RW-05 | Service / process kill spree | High | **Protect** |
| RW-06 | Mass file encryption behaviour | Critical | **Protect** |
| RW-07 | Ransomware canary tampered | Critical | **Protect** |
| RW-08 | Ransom-note fan-out | Critical | **Protect** |
| RW-12 | Ransomware kill-chain correlation | Critical | **Protect** |

## Credential dumping rules (CD)

| Id | Rule | Severity | Default |
|---|---|---|---|
| CD-01 | LSASS memory dump via comsvcs MiniDump | Critical | **Protect** |
| CD-02 | Known LSASS dumping tool | Critical | **Protect** |
| CD-03 | Suspicious LSASS handle request | High | Audit |
| CD-04 | LSASS handle followed by a dump file | Critical | **Protect** |
| CD-05 | Debug library dump helper reading LSASS | Critical | **Protect** |
| CD-06 | Blocked LSASS access attempt | High | Audit |
| CD-07 | LSASS dump preparation via SilentProcessExit / IFEO | Critical | **Protect** |
| CD-08 | LSASS dump via Windows Error Reporting | Critical | **Protect** |
| CD-09 | Malicious LSA security package | High | Audit |
| CD-10 | Credential hive save or copy | Critical | **Protect** |
| CD-11 | NTDS.dit extraction | High | Audit |
| CD-12 | WDigest cleartext credential downgrade | High | **Protect** |
| CD-13 | LSA protection / Credential Guard tamper | High | Audit |

## Persistence rules (PS)

| Id | Rule | Severity | Default |
|---|---|---|---|
| PS-01 | Run key to untrusted payload | Medium | Audit |
| PS-02 | Autorun via script host or LOLBin | High | **Protect** |
| PS-03 | Startup-folder drop | Medium | **Protect** |
| PS-04 | Startup folder redirection | High | Audit |
| PS-05 | Scheduled task with untrusted action | Medium | Audit |
| PS-07 | Suspicious service install | High | **Protect** |
| PS-08 | WMI permanent event subscription | Critical | **Protect** |
| PS-09 | IFEO / SilentProcessExit hijack | High | **Protect** |
| PS-10 | Winlogon / AppInit / AppCert / BootExecute change | Critical | **Protect** |
| PS-11 | COM hijack in user hive | Medium | Audit |
| PS-15 | Persistence rollback | High | **Protect** |

Persistence rules in Protect remove the autorun after backing up the original in the quarantine vault. They act on the writing process only when Kestrel knows exactly which process wrote it; when the writer is inferred, the alert says so and no process is touched.

## Tamper rules (TP)

| Id | Rule | Severity | Default |
|---|---|---|---|
| TP-01 | Telemetry session tampering | Critical | Audit |
| TP-02 | WFP filter tampering | Critical | Audit |
| TP-03 | AMSI tampering | Critical | Audit |
| TP-04 | Agent service or file tampering | Critical | Audit |
| TP-05 | Telemetry loss | High | Audit |
| TP-06 | Protection turned off on the device | Medium (High when completely off) | Audit |

Exclusions never apply to TP rules. The agent's watchdog restarts stopped ETW sessions.

`TP-06` is raised by the agent itself, never by an event: when someone turns protection off with the tray switch and the uninstall token (Medium for detection only, High for completely off), at Info level when protection comes back on or a policy change shortens the turn-off, and when a wrong uninstall token is entered (Medium, High when the switch locks). It never acts. See [Employee tray app](/guide/tray) and [Policies](/console/policies).

## Other rule ids

| Id | Source |
|---|---|
| `IOC-*` | Indicator hits (hash, IP, domain, URL, certificate). |
| `SIG-<uuid8>` | SigmaHQ pack rules (70, Audit by default, DRL 1.1 with authors shown) and your custom Sigma rules. |
| `TP-SRV-HEARTBEAT` | Server: more than 3 missed heartbeats on a live stream. |
| `TP-SRV-SEQ-RESET` | Server: outbox sequence went backwards (state wiped or cloned). |
| `TP-SRV-OUTBOX-RESET` | Server: the agent started a new outbox. |
| `TP-SRV-EVENTS-LOST` | Server: more than 500 ETW events lost between heartbeats. |
| `TP-SRV-ETW` | Server: the agent reports its ETW session down. |
| `TP-SRV-PAUSE-OVERDUE` | Server: the agent still reports protection turned off 10 minutes after the chosen end time. |
| `TP-SRV-DUP-ENROLL` | Server: a new enrollment reuses the hardware UUID of a recently active device. |

## False positives

* Each rule lists known false positives on the Rules page.
* Fix a false positive with the narrowest exclusion that works: SHA-256 or valid signer first, a path glob only when needed, scoped to the one rule. **Exclude...** on an alert previews what an exclusion would hide.
* Approving an employee's review request creates a SHA-256 or signer exclusion for that rule only, expiring after 90 days.
* A program blocked by mistake: **Lift network block**, and **Restore** it from quarantine.

## Rollout advice

1. Start with the defaults: the *safe on day one* rules in Protect, everything else in Audit.
2. Leave Audit rules running for **about two weeks** on a pilot group. Review the Alerts page and add exclusions for false positives.
3. Move rules to Protect one by one, per policy, starting with a small group.
4. Turn hardening on in Audit first to see which devices drift, then Enforce. Test LSA protection and the AppLocker controls on a few devices before the fleet.
5. Keep the SigmaHQ pack in Audit unless a rule has proven quiet in your environment.
