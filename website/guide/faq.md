# FAQ

**Does Kestrel replace Microsoft Defender?**
No. Kestrel runs alongside Defender (the lab runs with Defender on) and focuses on behaviour antivirus often misses: stealers reading credential stores, ransomware preparation, credential dumping and persistence. Some hardening controls configure Defender attack-surface rules.

**Does it prevent infostealers from taking data?**
Not guaranteed. Kestrel is user mode only, so events arrive with a short delay. It suspends suspicious readers on suspicion and kills confirmed ones fast, and the incident tells you what to rotate on the assumption that data may have left.

**Does detection work when a laptop is offline?**
Yes. Rules and Protect actions run on the device. Alerts and events queue in the local outbox and upload when the device reconnects. Console actions for offline devices are queued for up to 7 days.

**Where is our data stored?**
On your own server: PostgreSQL for the control plane and ClickHouse (or PostgreSQL) for telemetry. There is no vendor cloud.

**Which Windows versions are supported?**
64-bit Windows 10, Windows 11 and Windows Server 2019 or later. It has been validated on Windows 11 Enterprise 26100 in a lab VM.

**Is there a macOS or Linux agent?**
No. The agent core and simulator run on Linux and macOS for development only.

**Why does Defender flag the agent?**
The binaries are not code-signed yet, and Defender detects the unsigned agent heuristically because of its credential-store path tables. Sign the binaries and submit them to Microsoft as a false positive; until then use a Defender exclusion for `C:\Program Files\Kestrel`.

**Can an employee or local administrator uninstall it?**
Not without the device's uninstall token, which only console users with `devices.write` can reveal (and each reveal is audited). An administrator can still defeat a user-mode agent in other ways; the tamper rules make that visible.

**Can admins watch employees' screens without them knowing?**
No. Every remote desktop and remote file-manager session shows a banner on the employee's screen and a tray notification, in every profile. Devices installed with *No remote access* (the default) cannot be opened remotely at all.

**How many rules are in Protect by default?**
The *safe on day one* set: ST-02, ST-04, ST-07, ST-16 and most ransomware, credential-dumping and persistence rules (see the [rule reference](../reference/rules)). Everything else, including the SigmaHQ pack, starts in Audit.

**How do we roll it out?**
Pilot on a few devices, keep the defaults, review Audit alerts for about two weeks, add exclusions for false positives, then move rules to Protect one by one. Turn on hardening in Audit first, then Enforce.

**How big a server do we need?**
About 2 vCPU and 4 GB RAM for up to 100 endpoints, 4 to 8 vCPU and 16 GB for 1,000. See [Sizing](../deploy/server#sizing).

**Can we use our own Sigma rules?**
Yes. Add them on the **Rules** page; the server compiles them and agents evaluate them on the device.
