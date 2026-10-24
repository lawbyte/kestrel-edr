# Evidence PCAP: capturing one process tree's connections for 60 s after an alert

Research notes, 2026-10-25. Scope: user-mode mechanism for a SYSTEM service on Windows 10 1809+ / Windows 11 to capture,
for 60 seconds after an alert, only the packets of the suspicious process tree's connections (tuples known from our ETW
`net_connect` events), bounded to 50 MB and saved as pcapng. Candidates: `pktmon.exe` vs the
`Microsoft-Windows-NDIS-PacketCapture` provider (`netsh trace capture=yes`).

Nothing here was tested on the owner's PC (no capture was run, per the safety rules). Every claim cites a source in
brackets; anything I could not source is in the "Unverified / needs lab check" list at the end.

---

## 1. `pktmon filter add`

**Syntax (Microsoft Learn [S2]):**

```
pktmon filter add <name> [-m <mac> [mac2]] [-v <vlan>] [-d { IPv4 | IPv6 | number }]
                         [-t { TCP [flags...] | UDP | ICMP | ICMPv6 | number }]
                         [-i <ip> [ip2]] [-p <port> [port2]] [-b] [-e [port]]
```

* `<name>`: "You may provide an optional name or description of the filter" [S2]. Examples use a bare word
  (`MyPing`, `MySmbSyn`, `MySubnet`) [S2]; [S9] uses `pktmon filter add SMB -p 445`. No documented character or length
  rules, so we use a fixed ASCII token (`KestrelEv01`...).
* `-i, --ip[-address]`: "Match source or destination IP address." **At most two IPs per filter** (`-i <ip> [ip2]`).
  CIDR is accepted: "To match by subnet, use CIDR notation with the prefix length" [S2].
* `-p, --port`: "Match source or destination port number." At most two ports (`-p <port> [port2]`) [S2].
* `-t, --transport[-protocol]`: TCP, UDP, ICMP, ICMPv6 or a protocol number; optional TCP flags FIN SYN RST PSH ACK URG
  ECE CWR [S2].
* `-d`: data-link protocol IPv4, IPv6, ARP or number [S2].
* **Direction:** "When two MACs (-m), IPs (-i), or ports (-p) are specified, the filter matches packets that contain
  both. It will not distinguish between source or destination for this purpose." [S2]; "Packet Monitor will not
  distinguish between source or destination when it comes to MAC address, IP address, or port filters." [S5]. So
  `-i A -p P` matches both directions (A as src or dst, P as src or dst port) [S2][S5][S13].
* **Semantics:** "For a packet to be reported, it must match all conditions specified in at least one filter" (AND
  within a filter, OR across filters) [S2][S5]; [S9] "every filter in the list is an OR statement".
* **Max filters:** "Up to 32 filters can be active at once." [S2][S5]
* **IPv6:** the syntax takes `<ip>` and `-d IPv6` / `-t ICMPv6` exist [S2], but no Microsoft example shows an IPv6
  literal in `-i`. -> lab check.
* **Remove:** `pktmon filter remove` = "Remove all packet filters." [S1]. [S13] warns it "removes ALL filters!", [S9]
  calls it "all or nothing". **No documented way to remove a single filter** on current builds. (A 2018-era article
  shows `PktMon filter remove -p 443` [S11] — 1809 syntax, not documented today.)
* **Persistence:** filters stay configured after a capture and "can affect new captures" until removed [S10]. Filters
  are machine-global state, shared with any admin using pktmon.
* **Runtime changes:** the overview lists "Flexible runtime packet filtering" [S4], but every how-to says to add
  filters *before* `pktmon start` [S5] and no source confirms that a filter added mid-capture takes effect. -> lab
  check. Our design does not depend on it (filter set is fixed before start).
* `pktmon filter list` displays active filters [S1]; `pktmon status` also shows "Packet Filters: ..." [S12].

## 2. `pktmon start` (Windows 10 2004 / build 19041+ syntax)

**Syntax (Microsoft Learn [S3]):**

```
pktmon start [--capture [--counters-only] [--comp <selector>] [--type <type>] [--pkt-size <bytes>] [--flags <mask>]]
             [--trace --provider <name> [--keywords <k>] [--level <n>] ...]
             [--file-name <name>] [--file-size <size>] [--log-mode <mode>]
```

* `-c, --capture`: enable packet capture and counters [S3].
* `--comp`: `all` (default), `nics`, or a list of component IDs [S3]. Component IDs "are not persistent and may change
  across reboots" [S5], so we use `nics`.
* `--type`: `all` (default), `flow`, `drop` [S3].
* `--pkt-size <bytes>`: bytes logged per packet; `0` = whole packet; default 128 [S3][S5].
* `--flags <mask>`: default `0x012` (0x002 component/counter/filter info appended to the log + 0x010 raw packet) [S3].
* `-f, --file-name`: default `PktMon.etl` [S3]. With no path it lands in the **current directory** of the caller
  ([S9]; [S12] example lands in `C:\Users\Administrator\PktMon.etl`; [S11][S7] "in the folder where you ran Pktmon").
  -> always pass an absolute path.
* `-s, --file-size <size>`: "Maximum log file size in megabytes. Default is 512 MB." [S3]
* `-m, --log-mode`: default `circular` [S3]:
  * `circular` — "New events overwrite the oldest ones when the log is full." [S3][S5]
  * `multi-file` — new numbered file each time full, unlimited [S3]
  * `real-time` — on screen only, no file, Ctrl+C to stop [S3]
  * `memory` — circular in-memory buffer of `--file-size`, written to file at stop [S3][S5]
* **No documented "stop when full" mode.** A 50 MB cap in circular mode means the *oldest* packets are dropped once
  50 MB is exceeded [S3]. During capture `pktmon status` shows the live file as `<name>_1.etl`; `pktmon stop` merges
  metadata into `<name>.etl` [S12] — convert only after stop.
* `pktmon start` returns and capture continues in the background until `pktmon stop` (examples run `start`, then
  `status`, then `stop` as separate commands [S12][S5]). "Use 'pktmon stop' to stop all data collection." [S5]

**1809/1903/1909 (pre-2004) syntax:** `pktmon start --etw -p 0 -c <componentId>` where `-p 0` = full packet size and
`-c` = component, default file `PktMon1.etl` [S11][S7][S15]; filter removal took options [S11]; the component list was
`pktmon comp list` [S11][S7]; conversion was `pktmon format` (text) and pcapng conversion arrived with Windows 10 2004
[S11][S7][S15]. Conflicting secondary sources: one course page says pktmon appeared in 2004 and has "native pcapng since
Windows 11" [S16]; Microsoft says in-box since Windows 10 / Server 2019 version 1809 [S5] and the current syntax is
documented "on Vibranium OS (build 19041)" [S4]. **Decision: require build >= 19041** (detect with `RtlGetVersion`,
then confirm with `PktMon.exe etl2pcap help` exit 0 / `PktMon.exe start help` mentioning `--capture`). On 1809-1909
(incl. Windows 10 Enterprise LTSC 2019 and Server 2019) report "PCAP evidence unsupported on this OS build".

## 3. `pktmon etl2pcap`

```
pktmon etl2pcap <file> [--out <name>] [--drop-only] [--component-id <id>]
```

* Output is **pcapng** ("Convert pktmon log file to pcapng format") [S6].
* "Dropped packets are not included by default." `--drop-only` converts only drops; `--component-id` restricts to one
  component [S6].
* pcapng loses drop reports and which component saw the packet [S6]. If capture is on all components, the same packet
  appears several times (one snapshot per component edge [S5]); converted captures "may show duplicate packets and
  misleading TCP retransmissions" [S10]. Using `--comp nics` at start limits this.
* Admin requirement for conversion is not documented (pktmon is run elevated in all sources [S9][S12]). We run it as
  SYSTEM anyway.
* Alternative converter: Microsoft `etl2pcapng` (MIT) supports pktmon ETL since v1.12.0 and preserves interfaces,
  packet IDs and drop verdicts [S17]. Not needed for v1.

## 4. `pktmon stop` / `status` / `list` / `unload` — singleton and ownership

* Commands: `filter`, `list`, `start`, `stop` ("Stop data collection"), `status` ("Query current status"), `unload`,
  `counters`, `reset`, `etl2txt`, `etl2pcap`, `hex2pkt`, `help` [S8].
* `pktmon status [--buffer-info]` [S18]. Example output while running [S12]:
  `Collected Data: Packet counters, packet capture` / `Capture Type: All packets` / `Monitored Components: All` /
  `Packet Filters: None` / `Logger name: PktMon` / `Logging mode: Circular` / `Log file: C:\...\pga_1.etl` /
  `Max file size: 512 MB` / `Memory used: 64 MB` / `Events lost: 0`. The not-running output exists (screenshot in
  [S9]) but its exact text is not in any source -> lab check.
* **Singleton:** there is one PktMon driver service ("Effectively equivalent to 'sc.exe stop PktMon'") with one global
  filter list and one ETW logger named `PktMon` [S19][S12]. `pktmon stop` stops "all data collection" [S5]. So a
  second capture cannot coexist with an admin's capture, and our `stop` / `filter remove` would destroy theirs.
  (Inference from the above; no source says "only one session" verbatim for pktmon. For `netsh trace`: "only one
  tracing session may be enabled at a time" [S20].)
* **Ownership check:** compare the `Log file:` line of `pktmon status` with our own evidence directory [S12]. If a
  capture is running whose log file is not ours, or `pktmon filter list` is non-empty and not ours, **skip** and record
  `pktmon_busy`.
* **Crash of the starter:** because `start` returns and the capture lives in the driver/ETW session until `stop`
  [S12][S5], a crash of our agent leaves the capture running (up to `--file-size` on disk, circular) and the filters
  installed [S10]. -> crash-recovery step below.
* `pktmon unload`: "Stop the PktMon driver service and unload PktMon.sys ... Measurement (if active) will immediately
  stop, and any state will be deleted (counters, filters, etc.)" [S19]. Heavy hammer; do not use routinely (it would
  also kill an admin capture).
* Exit codes: not documented in any source -> lab check (treat non-zero as failure, parse stdout defensively).
* No persistence across reboots ("PktMon doesn't support persistent captures across reboots") [S13], so a reboot also
  ends a stuck capture; filters after reboot -> lab check.

## 5. Coverage: loopback, encryption, VPN, other processes

* **No per-process filter.** Filter fields are MAC, VLAN, EtherType, transport protocol (+TCP flags), IP, port,
  heartbeat, encapsulation [S2][S5]. Any process talking to the same remote IP:port (CDN / Cloudflare shared IPs,
  browser to same host) will be captured too. Narrowing to the 4-tuple (`-i <local> <remote> -p <lport> <rport>`)
  [S2] reduces this but local ephemeral ports only exist for already-seen connections.
* PID annotations in converted captures are unreliable: "this PID often differs from the process that actually sent
  or received the packet, because capture often runs in a DPC" [S17].
* **Loopback:** pktmon intercepts at networking-stack components (NIC miniports, filter drivers, protocols) [S4][S5];
  localhost traffic "is processed internally by TCP/IP and never reach[es] NDIS" [S21]; a course comparison marks
  pktmon loopback capture "No" [S16]. Treat loopback as **not captured** (lab check).
* **Encryption:** pktmon sees wire packets; TLS payload stays encrypted (no key material). (General fact, no
  pktmon-specific source.) With a VPN, filtering on the remote IP matches the inner packet only on the VPN's virtual
  adapter; on the physical NIC the packets are encapsulated/encrypted to the VPN gateway. `-e` applies filters to inner
  headers only for VXLAN, GRE, NVGRE and IP-in-IP [S2] — not IPsec/SSTP/WireGuard. `--comp nics` covers "all active
  network interfaces" [S13]; whether VPN virtual adapters appear as NICs depends on the client -> lab check.

## 6. Requirements and side effects

* In-box at `C:\Windows\System32\PktMon.exe` [S12][S15]; Windows 10 / Server 2019 1809+ [S5], current syntax and
  pcapng on build 19041+ [S4][S11]; still present in Windows 11 and Server 2025 (per [S22]).
* Must run elevated ("must run in an administrative PowerShell or CMD window") [S9]; LocalSystem satisfies this.
* **Detection noise:** SigmaHQ rule *PktMon.EXE Execution* (`proc_creation_win_pktmon_execution`, id
  f956c7c1-0f60-4bc5-b7d7-b39ab3c08908, level medium, T1040 Network Sniffing) [S23]; FortiSIEM and ManageEngine ship
  equivalents [S23]. Customers' SIEM/other EDR may alert on our use -> document it, and add a Kestrel self-exclusion so
  our own Sigma engine does not fire on PktMon spawned by `kestrel-agent.exe` with our argument shape.
* Performance: netsh doc warns that heavy ETW capture can drop events due to buffer constraints [S20]; pktmon's
  `memory` mode exists "for very noisy scenarios" because "Using any other logging modes, some traffic might get lost"
  [S5]. `pktmon status` exposes `Events lost` [S12] — record it in the manifest.

## 7. Alternative: Microsoft-Windows-NDIS-PacketCapture (ndiscap) / `netsh trace`

* Provider GUID **{2ED6006E-4729-4609-B423-3EE7BCD678EF}**, message file `%SystemRoot%\system32\drivers\ndiscap.sys`
  [S24]; captures frames at the data-link layer as ETW events, Windows 8.1 / 2012 R2+ [S24][S25].
* Collection is documented via `netsh trace start capture=yes report=disabled` ... `netsh trace stop` [S17]; ndiscap
  "is implemented as an ETW trace provider" [S17]. No source documents enabling the provider in a private ETW session
  without netsh activating the NdisCap filter -> unverified, and a private-session route would be undocumented
  behaviour.
* Filters: `ipv4.address=x.x.x.x` matches source or destination [S20][S26]; `Ethernet.Type=IPv4`, `Protocol=TCP|UDP`
  [S27]; full list via `netsh trace show capturefilterHelp` [S20]. **No source shows a port filter** (CaptureInterface,
  IPv6.Address, PacketTruncateBytes recalled from memory -> unverified).
* Limits: `maxSize` in MB, `fileMode` circular, `persistent=yes` survives reboot [S16][S26]; "only one tracing session
  may be enabled at a time" [S20]; `netsh trace stop` also builds a `.cab` report by default [S20].
* Conversion needs the external `etl2pcapng.exe` (MIT) [S17] — an extra binary to ship and sign.
* **Why not preferred:** no port filter (CDN IPs would pull in all of a shared IP's traffic), extra binary for pcapng,
  `netsh trace` session is also a singleton and widely used by admins, stop is slower (cab/report). Its only advantage
  is availability on 1809-1909 / LTSC 2019; kept as a possible v2 fallback for those builds.

---

## Decision

**Use in-box `PktMon.exe` (build >= 19041 only), NIC components, full packets, circular 50 MB ETL, one filter per
(protocol, remote IP, remote port) tuple, fixed before start, max 32; stop after 60 s; convert with `etl2pcap`.**

### Preconditions (agent, before running anything)

1. OS build >= 19041 (`RtlGetVersion`), else `unsupported_os`.
2. Binary = `%SystemRoot%\System32\PktMon.exe` resolved via `GetSystemDirectoryW` (not PATH, not cwd); verify
   Authenticode Microsoft signature with the existing enrichment code.
3. Every IP parsed with `std::net::IpAddr` (re-serialise from the parsed value, never pass the raw string); ports
   parsed as `u16` 1..=65535; protocol from an enum {TCP, UDP}. Drop loopback (127.0.0.0/8, ::1), unspecified,
   multicast/broadcast, link-local, and the Kestrel server's own IPs. Deduplicate.
4. If >32 tuples: merge same remote IP into one filter without port (still <= 32), else take the 32 most recent and
   record `truncated_filters` in the manifest.
5. Disk: >= 200 MB free on the evidence volume.

All commands run with `std::process::Command` (CreateProcess, no shell, no `cmd /c`), working directory set to the
evidence directory, stdout/stderr captured, 30 s timeout each. Evidence dir:
`%ProgramData%\Kestrel\evidence\pcap\<alert_id>\` with SYSTEM/Administrators-only DACL. `<alert_id>` is our UUID,
validated `[0-9a-f-]{36}`.

### Command sequence

```
# 0. ownership / busy check
PktMon.exe status            -> if it reports an active capture: skip ("pktmon_busy") unless Log file is under our dir
PktMon.exe filter list       -> if any filters exist: skip ("pktmon_busy")

# 1. filters (one per tuple; names fixed by us)
PktMon.exe filter add KestrelEv01 -t TCP -i 203.0.113.7 -p 443
PktMon.exe filter add KestrelEv02 -t UDP -i 198.51.100.9 -p 53
PktMon.exe filter add KestrelEv03 -t TCP -i 2001:db8::5 -p 8443        # IPv6: lab check
PktMon.exe filter list       -> verify exactly our N filters are present

# 2. write marker %ProgramData%\Kestrel\evidence\pcap\active.json {alert_id, started_at, etl_path} BEFORE start

# 3. start
PktMon.exe start --capture --comp nics --pkt-size 0 --file-name C:\ProgramData\Kestrel\evidence\pcap\<alert_id>\capture.etl --file-size 50 --log-mode circular

# 4. after 60 s (timer in the agent; also on agent shutdown)
PktMon.exe status            -> record "Events lost", confirm Log file is ours
PktMon.exe stop
PktMon.exe filter remove     -> removes ALL filters (only reached when we verified they were ours)

# 5. convert
PktMon.exe etl2pcap C:\ProgramData\Kestrel\evidence\pcap\<alert_id>\capture.etl --out C:\ProgramData\Kestrel\evidence\pcap\<alert_id>\capture.pcapng

# 6. hash (SHA-256) pcapng, check size <= 50 MB (truncate/refuse upload otherwise), delete ETL, delete active.json
```

### Cleanup

* **Agent stop:** if `active.json` exists, run steps 4-6 (stop, filter remove, convert) before the service reports
  stopped (within the SCM stop timeout; skip conversion if short of time and keep the ETL for next start).
* **After a crash / at agent start:** if `active.json` exists: `PktMon.exe status`; if the `Log file:` is under our
  evidence dir -> `stop`, `filter remove`, convert, mark manifest `interrupted=true`. If a capture is running that is
  not ours, do nothing to it; if no capture is running, only `filter remove` when `filter list` shows exactly our
  `KestrelEvNN` names. Then delete the marker. Never call `pktmon unload` automatically.
* Only one evidence capture at a time per host (agent-level mutex); queued alerts are refused with `capture_in_progress`.

### Limitations to show in the UI and record in the manifest

* Matches by IP/port/protocol, **not by process**: other processes talking to the same remote IP:port (CDN, shared
  hosting) are included.
* TLS and other encrypted payloads remain encrypted; only metadata (IPs, ports, sizes, timing, SNI/certificates where
  in clear) is useful.
* Loopback (127.0.0.1/::1) traffic is not captured.
* With a VPN, traffic may be seen only as encrypted tunnel packets on the physical NIC.
* Connections to new IPs opened after the capture started are not included (filters fixed at start).
* 50 MB cap in circular mode: if exceeded, the **oldest** packets are overwritten; `Events lost` > 0 means gaps.
* Not available if an administrator is already using Packet Monitor (`pktmon_busy`) or on Windows builds < 19041.
* User-mode capture cannot be guaranteed complete; a privileged attacker can stop PktMon.

Manifest fields: `mechanism=pktmon`, `pktmon_version` (file version of PktMon.exe), `os_build`, `filters[]`
(exact argument lists), `started_at`, `stopped_at`, `duration_s`, `pkt_size=0`, `components=nics`,
`file_size_limit_mb=50`, `log_mode=circular`, `events_lost`, `truncated_filters`, `interrupted`, `etl_sha256`,
`pcapng_sha256`, `pcapng_bytes`, `skip_reason` (`unsupported_os` | `pktmon_busy` | `capture_in_progress` |
`no_eligible_tuples` | `disk_low` | `error`), plus the limitation strings above.

---

## Unverified / needs lab check (run in Windows Sandbox / Hyper-V only)

1. `-i` with an IPv6 literal (and IPv6 CIDR) is accepted and matches.
2. Whether `pktmon filter add` while a capture is running takes effect immediately (would allow adding new tuples
   during the 60 s window).
3. Exact `pktmon status` text when nothing is running, and its exit code; exit codes of all subcommands (success and
   failure); whether `pktmon start` fails or silently reconfigures when a capture is already running.
4. Whether filters survive `pktmon stop` and a reboot (sources say they persist across captures [S10]).
5. Capture continues after the starting `PktMon.exe`/agent process dies (strongly implied by [S12][S5], not stated).
6. Circular mode with `--file-size 50`: actual on-disk ETL size, and pcapng size after `etl2pcap` relative to ETL.
7. `--comp nics` yields one copy of each packet (no duplicates) on Wi-Fi, Ethernet and Hyper-V vSwitch hosts.
8. Loopback not captured; behaviour with common VPN clients (which adapter shows inner packets).
9. Whether `etl2pcap` works without elevation (irrelevant for SYSTEM, relevant for tooling).
10. Exact pre-2004 syntax on 1809/1903/1909 (`--etw`, `-p`, `-c`, `pktmon pcapng`) and whether etl2pcapng v1.12+
    converts those ETLs — only if we decide to support LTSC 2019 / Server 2019.
11. NDIS-PacketCapture: whether enabling the provider in a private ETW session captures packets without
    `netsh trace` binding NdisCap; full `netsh trace show capturefilterHelp` list (CaptureInterface, IPv6.Address,
    PacketTruncateBytes recalled from memory, port filter believed absent).
12. Whether Defender for Endpoint or other EDRs block (not just alert on) PktMon started by a service.

---

## Sources

* [S1] pktmon filter — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter
* [S2] pktmon filter add — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter-add
* [S3] pktmon start — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start
* [S4] Packet Monitor overview — https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon
* [S5] Pktmon command formatting — https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax
* [S6] pktmon etl2pcap — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-etl2pcap
* [S7] BleepingComputer, hands-on with pktmon — https://www.bleepingcomputer.com/news/microsoft/hands-on-with-windows-10s-built-in-pktmon-network-monitor/
* [S8] pktmon (command list) — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon
* [S9] Secure Ideas, Built-in network capture with Windows 11 (2025-04-02) — https://www.secureideas.com/blog/built-in-network-capture-with-windows-11
* [S10] Matrixpost, Mastering Packet Monitor — https://blog.matrixpost.net/mastering-packet-monitor-pktmon-on-windows/
* [S11] SANS ISC diary 26186, Windows 10 built-in packet sniffer PktMon — https://isc.sans.edu/diary/26186
* [S12] Cisco, collect packet captures on Windows clients (pktmon) — https://www.cisco.com/c/ko_kr/support/docs/contact-center/unified-intelligent-contact-management-enterprise/221945-collect-packet-captures-on-windows-clien.html
* [S13] Richard Hicks, Always On VPN troubleshooting with PktMon — https://directaccess.richardhicks.com/tag/command-line/
* [S15] Cellstream, packet capture with pktmon — https://www.cellstream.com/?p=1238
* [S16] PSU NetSec course, Windows packet capture — https://web.cecs.pdx.edu/~dmcgrath/courses/Su26/netsec/windows_capture.html
* [S17] microsoft/etl2pcapng (MIT) — https://github.com/microsoft/etl2pcapng
* [S18] pktmon status — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-status
* [S19] pktmon unload — https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-unload
* [S20] Using Netsh to manage traces — https://learn.microsoft.com/en-us/windows/win32/ndf/using-netsh-to-manage-traces
* [S21] NT Kernel (Npcap/WinpkFilter) on localhost not reaching NDIS — https://www.ntkernel.com/?p=5330 ; Packetbeat loopback note — https://www.elastic.co/guide/en/beats/packetbeat/8.19/packetbeat-loopback-interface.html
* [S22] IT-Connect, Windows Server 2025 pktmon — https://www.it-connect.fr/chapitres/windows-server-2025-capturer-le-trafic-reseau-avec-pktmon/
* [S23] SigmaHQ PktMon.EXE Execution — https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_pktmon_execution ; FortiSIEM — https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_1/rules/PH_RULE_Use_of_PktMon_exe.htm ; ManageEngine — https://www.manageengine.com/log-management/detection-rules/pktmon-exe-execution.html
* [S24] winevt-kb, Microsoft-Windows-NDIS-PacketCapture provider — https://winevt-kb.readthedocs.io/en/stable/sources/eventlog-providers/Provider-Microsoft-Windows-NDIS-PacketCapture.html
* [S25] Microsoft-Windows-NDIS-PacketCapture provider (Message Analyzer docs, retired tool) — https://learn.microsoft.com/de-de/message-analyzer/microsoft-windows-ndis-packetcapture-provider ; https://technet.microsoft.com/en-us/library/mt146753.aspx
* [S26] Concurrency, Netsh packet captures — https://concurrency.com/blog/netsh-packet-captures/
* [S27] SANS ISC diary 19409, No Wireshark? No TCPDump? No problem — https://isc.sans.edu/diary/19409
