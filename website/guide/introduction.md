# What Kestrel is

Kestrel is a self-hosted endpoint detection and response (EDR) product for Windows. It was built first to catch **infostealers** (Lumma, Vidar, StealC, Rhadamanthys and similar malware) while they work. These programs read browser passwords, cookies, crypto wallets and messenger sessions, then upload them. Kestrel watches for that behaviour, contains the process, and gives IT one incident that says what was taken and what to rotate.

Since v1.1 it also covers the steps around a hands-on intrusion:

* **Ransomware** preparation and encryption (shadow copy deletion, boot recovery changes, service kill sprees, mass file encryption, ransom notes).
* **Credential dumping** (LSASS dumps, registry hive copies, NTDS.dit extraction, WDigest downgrade).
* **Persistence** (Run keys, Startup folder, scheduled tasks, services, WMI subscriptions, IFEO, Winlogon, COM hijacks).
* A curated pack of **70 SigmaHQ rules**, shipped in Audit mode.

It also includes admin **remote access** (remote desktop and a file manager), limited by a profile chosen when the agent is installed. See [Remote access](./remote-access).

## Components

<Shot src="img/diagrams/architecture.svg" alt="Kestrel architecture: agent, server, console and tray" />

| Part | What it is | Where it runs |
|---|---|---|
| **Agent** (`kestrel-agent.exe`) | Windows service written in Rust, runs as LocalSystem. Reads ETW sensors and the event log, runs the detection engine on the device, carries out response actions, keeps a local SQLite outbox and uploads over gRPC with mutual TLS. | Every Windows endpoint |
| **Scanner** (`kestrel-scan.exe`) | On-demand YARA-X scanner, started by the agent for the Scan action. Kept out of the always-running agent to keep it small. | Every Windows endpoint |
| **Server** (`kestrel-server`) | REST API, admin console, agent gRPC service, internal agent CA, incidents, RBAC, SSO, notifications, audit log. Stores the control plane in PostgreSQL 16 and telemetry in ClickHouse (or in PostgreSQL for small sites). | One Docker Compose stack per organisation |
| **Admin console** | React web app served by the server on port 443. | Admin browsers |
| **Tray app** (`kestrel-tray.exe`) | Small Tauri app for employees. Shows status, explains blocks in plain language, lets the employee ask IT for a review, shows the monitoring notice and remote-session notices. | Each signed-in user's session |

The agent and the tray talk over a local named pipe (`\\.\pipe\kestrel-tray`). The agent and the server talk over one long-lived gRPC stream on port 8443. The console talks only to the server's REST API (`/api`) and gets live updates through server-sent events.

## How detection works

The agent runs three real-time ETW sessions:

* `Kestrel-Core`: process start, stop and image load, process and thread access (Kernel-Audit-API-Calls), registry value writes and DPAPI unprotect events. Flushed every second.
* `Kestrel-IO`: file creates, network connections, DNS queries and PowerShell script blocks. Flushed every 5 seconds.
* `Kestrel-ProcCmd`: an optional session used only to get command lines of processes that exit quickly.

Event-log subscriptions add Windows Filtering Platform change events and, if Sysmon is installed, Sysmon events 8 and 10 as a cross-check. The engine runs on the device, so detection and containment keep working while the device is offline. Rules look at **behaviour** (which process opened which credential store, what it did next), not at malware family names or file hashes alone.

Each rule runs in one of three modes, set per policy:

* **Off**: the rule is not evaluated.
* **Audit**: the rule raises an alert, nothing else.
* **Protect**: the rule raises an alert and the agent acts (suspend, kill, quarantine, block, remove persistence, isolate).

A small set of rules is in Protect by default because their false-positive rate is low. They are marked *safe on day one*. Everything else starts in Audit. See the [detection rules reference](../reference/rules).

## What user mode can and cannot do

Kestrel v1 runs entirely in user mode. There is no kernel driver. Read this before you rely on it.

* **Detect fast, contain fast; no prevention guarantee.** Telemetry comes from ETW and the event log, so it arrives asynchronously: typically within about 1 second on the core session and up to about 5 seconds for file and network events. A fast stealer can read and send some data before the agent reacts. The incident checklist assumes the data may have left the device, and says so.
* **Suspend on suspicion narrows the gap.** When an untrusted process opens a credential store or decrypts browser secrets with DPAPI, the agent can freeze it for a short window (3 seconds by default) and kill it if a stronger rule confirms the theft. Otherwise the process is resumed.
* **An administrator can defeat a user-mode agent.** An attacker with administrator or SYSTEM rights can blind ETW, stop sessions or remove WFP filters. The tamper rules (`TP-01` to `TP-06`) and the agent's watchdog detect and repair much of this and make it loud, but cannot make it impossible.
* **Registry writer attribution is inferred.** Windows 11 omits the key name in the ETW registry event, so Kestrel joins ETW with a registry watcher. When more than one process could have written a value, Kestrel removes the autorun but does not act on any process, and the alert says the writer was inferred.
* **Ransomware from another computer over SMB** shows up as the System process. Kestrel alerts but cannot kill the remote encryptor.
* **Windows only.** The agent core and the simulator also run on Linux and macOS for development, but there is no real sensor layer for them.

## Status

* Version: **1.1 release candidate** (workspace version `1.1.2`).
* Validated on Windows 11 Enterprise (build 26100) in a disposable QEMU/KVM lab VM: install, all sensors, a benign emulation per rule, Protect actions, isolation and break-glass, upgrade and uninstall. It has not yet run on a fleet of physical machines or with Office and OneDrive heavy workloads.
* Two independent security reviews were done (v1.0 and v1.1), with the findings fixed and re-reviewed. Residual risks are listed in [Security model and limits](./security).
* **The binaries are not code-signed yet.** Microsoft Defender currently flags the unsigned agent (a heuristic on its credential-store path tables). Sign the binaries before production use (see [Code signing](../build/#code-signing)), and until then deploy with a Defender exclusion for `C:\Program Files\Kestrel`.
* Licence: Apache-2.0. Dependencies under GPL, AGPL, SSPL and ELv2 are rejected by the licence policy.

## Where to go next

* Try it end to end: [Quick start](./quick-start).
* Build every component yourself: [Build from source](../build/).
* Set up a production server: [Deploy the server](../deploy/server), then [Enroll devices](../deploy/enroll).
