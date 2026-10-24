# Endpoint resource budget (agent and tray)

Kestrel runs on employees' PCs; it has to stay out of their way. This page
sets the budget, explains what Kestrel does under load, how to measure it,
and records the 2026-10-25 footprint work (owner request) with its numbers.
Operator-facing version: `website/reference/performance.md`.

## Budget (idle office or developer PC)

| Resource | Target | How to measure |
|---|---|---|
| Agent CPU | < 0.1 % of the machine averaged over 10 min; short peaks during process storms | Task Manager Details "CPU", `Get-Counter '\Process(kestrel-agent)\% Processor Time'` (divide by the number of logical CPUs) |
| Agent private memory | <= 110 MB (target 100 MB) | Task Manager "Memory (active private working set)" / `(Get-Process kestrel-agent).PrivateMemorySize64` |
| Agent threads | <= 40 | `(Get-Process kestrel-agent).Threads.Count` |
| Agent disk | < 10 KB/s write idle | `Get-Counter '\Process(kestrel-agent)\IO Write Bytes/sec'` |
| Agent network | < 30 KB per minute of telemetry idle (compressed) | Device page, events per minute; server side `bytes` of `events` messages |
| Tray idle | < 20 MB private, 0 CPU, no `msedgewebview2.exe` children | Task Manager process tree under `kestrel-tray.exe` |
| Tray open | One WebView2 set (about 100 MB), gone 0 s after closing | same |
| Event loss | 0 high-value records; total loss < 1 % of events | Device page "Events lost" (split Windows / Kestrel), heartbeat `sensor_high_value_dropped` |

ETW session buffers live in kernel memory, not in the agent's private
bytes: Core 32-256, File 64-512, IO 128-256, Persist 8, ProcCmd 8 buffers
of 64 KB (15 MB reserved, 65 MB worst case under a burst; `consts::buffers`).

## What Kestrel does when the PC is busy

In order, from the source to the server:

1. **Source filters in the ETW callbacks.** Kernel-File opens of paths that
   can never be sensitive are not queued (`filters::kernel_file_candidate`);
   image loads from the system folders other than the interesting DLL list
   are not queued (`filters::image_load_candidate`, same rule as the
   translator); identical `OpenProcess` records (actor, target, access,
   status) within 2 s are coalesced (`pump::Coalescer`; a process start or
   stop of either pid ends the window). Terminations, thread opens, DPAPI
   and everything else are never coalesced.
2. **Raw queue (65,536 slots, at most 64 bytes each).** Under pressure it
   sheds by value (`pump::shed_early`): connection close, first-read and
   evidence-journal hints at half full; TCP / UDP send records (byte
   accounting) at 7/8; everything else (process start / stop, command
   lines, image loads that passed the source filter, DNS answers, handle
   opens, thread context, DPAPI, sensitive-file opens, network connects,
   registry, persistence, scripts, file-activity summaries, tamper signals)
   only when the queue is completely full. Those are counted as
   `high_value_dropped`.
3. **Translator to engine channel (65,536 events).** Every translated event
   is detection input: no early shedding; a full channel is a high-value
   loss.
4. **File-activity aggregator.** A process with more than 2,048 operations
   in its 10 s window keeps being summarised from its most recent 2,048
   (far above every RW threshold): counted as `file_agg_trimmed`, not as a
   loss. A process that cannot be tracked at all (256 at once) is a loss.
5. **Engine.** Sees every event that reached it. Detection is never fed
   the de-duplicated upload copy.
6. **Upload (`kestrel-agent/src/uploader.rs`).** Per (process instance,
   kind, target) the first event is uploaded at once; identical ones in the
   next 5 minutes become one summary row with `repeat_count` and
   `repeat_first_ts`. Batches are sealed at 500 rows or 5 s. JSON + zstd
   and the SQLite insert run on `kestrel-outbox` (below normal + EcoQoS);
   if it falls 64 batches behind, the engine thread writes itself (slower,
   never lost).
7. **Outbox.** Capped by `policy.telemetry.max_outbox_mb`; oldest event
   batches go first, alerts and action results never.
8. **Health.** A device is Degraded for an hour after a heartbeat whose
   loss includes an event Windows lost (ETW, unclassified), a high-value
   record, or exceeds 1 % of the events of that interval (agents 1.1.7+;
   older agents: any loss).

Priorities: detection, response, ETW consumers, the translator and the
first-run enrichment worker (a held process start waits for it) run at
normal priority. Enrichment of already running binaries runs below normal
+ EcoQoS; revocation checks in background mode; `kestrel-scan.exe` (YARA-X)
in process background mode + EcoQoS. Hashing is capped at 512 MB per file.
Tokio uses 2 to 4 worker threads (was one per logical CPU).

## How to measure on an installed endpoint

```powershell
# Snapshot (run in a normal PowerShell; reading process counters needs no elevation)
Get-Process kestrel-agent, kestrel-tray, msedgewebview2 -ErrorAction SilentlyContinue |
  Select-Object Name, Id, @{n='PrivateMB';e={[math]::Round($_.PrivateMemorySize64/1MB,1)}},
    @{n='Threads';e={$_.Threads.Count}}, Handles, CPU

# 10 minutes of samples every 10 s
Get-Counter -Counter '\Process(kestrel-agent)\% Processor Time',
  '\Process(kestrel-agent)\Private Bytes', '\Process(kestrel-agent)\Thread Count',
  '\Process(kestrel-agent)\IO Read Bytes/sec', '\Process(kestrel-agent)\IO Write Bytes/sec' `
  -SampleInterval 10 -MaxSamples 60 | Export-Counter -Path .\kestrel-agent.blg
```

`msedgewebview2.exe` children of the tray: in Task Manager expand
`kestrel-tray.exe`; with the window closed there must be none.

The device page shows events per minute, outbox depth, CPU and memory as
reported by the agent, and the loss split. The agent log writes a
`sensor health` line every 5 minutes with `raw_shed`, `raw_coalesced`,
`high_value_dropped`, `file_agg_trimmed`, `image_prefiltered` and
`file_prefiltered`; at stop it writes `telemetry upload totals`
(events, merged, summaries, rows, batches).

## 2026-10-25 footprint work: measurements

### Before (owner's PC, 32 logical CPUs, Windows 11, agent 1.1.6, idle developer workstation)

* Agent: 0.05 % of the machine CPU, 119-128 MB private, 605 handles,
  60 threads, disk 7 KB/s read and 14 KB/s write, 1,696 events/min
  uploaded, `sensor_internal_dropped: 7403`, `etw_kernel_events_lost: 0`,
  device Degraded.
* Tray: 9 MB, plus 6 `msedgewebview2.exe` children with 189 MB private;
  two of them used 20-28 s CPU in a day with the window closed.
* Owner's telemetry (ClickHouse, 2026-10-21 15:32 to 10-24 18:19, 4.76 M
  events, 1,061 per minute on average): `process_access` 59 %,
  `file_access` 21 %, `net_connect` 5 %, `dpapi_unprotect` 5 %. One storm:
  2026-10-24 07:06-07:10, OneDrive opening `explorer.exe` with access
  `0x40` up to 29,000 times per second (1.38 M events in 4 minutes). NordVPN
  calls DPAPI about 26,000 times in 3 days, `docker.exe` re-reads
  `config.json` and its context files about 165,000 times.

### Upload volume (test `uploader::tests::upload_budget_report`)

JSON + zstd as stored in the outbox and sent; "before" = 2 s / 500 batches
without de-duplication, "after" = this change (5 s / 500, 5-minute merge).
Event timestamps stand in for arrival times. The two large samples are
exports of the owner's own telemetry (not committed; set
`KESTREL_UPLOAD_SAMPLE=<file.jsonl>` to rerun).

| Sample | Events | Rows before / after | Bytes before / after | Per minute before / after |
|---|---|---|---|---|
| `replays/benign_workday.jsonl` | 36 | 36 / 36 | 5,669 / 5,333 | |
| `replays/lumma_clickfix.jsonl` | 34 | 34 / 34 | 2,298 / 2,014 | |
| `replays/vidar_smash_grab.jsonl` | 48 | 48 / 47 | 3,066 / 2,776 | |
| Owner PC, 3 idle hours (10-24 08:00-11:00) | 177,926 | 177,926 / 105,310 (-41 %) | 6.67 MB / 4.19 MB (-37 %) | 988 to 585 rows, 37.0 to 23.3 KB |
| Owner PC, storm hour (10-24 07:00-08:00) | 1,475,048 | 1,475,048 / 89,843 (-94 %) | 3.86 MB / 2.23 MB (-42 %) | 24,584 to 1,497 rows, 64.3 to 37.2 KB |

Not included above: source coalescing of the OneDrive storm (2 s windows
turn 25,000 identical opens per second into one record every 2 s before
they reach the engine), so the live storm volume is lower still. Server
storage (ClickHouse / Postgres rows) shrinks by the row reduction.

Bytes per uploaded event after compression: 23.6 B idle, 1.5 B in the storm
(mostly summaries); before 37.5 B and 2.6 B. Uncompressed JSON averages
about 280 bytes per event (`process_start` 800 B, `process_access` 270 B).

### Memory and threads (code-level, to be confirmed on an installed agent)

* Raw queue: `size_of::<Raw>()` was 224 bytes, so the 65,536 preallocated
  slots committed 15.2 MB at sensor start; large variants are now boxed and
  a compile-time check keeps the record at <= 64 bytes (<= 4.7 MB).
* Tokio worker threads: 32 on the owner's PC, now 4 (60 agent threads
  expected to drop to about 32).
* Upload de-duplication adds at most 8,192 open windows (one event each,
  about 3 MB worst case; typically 2,000-3,000 windows idle).
* Not changed: the enrichment cache (20,000 files), flow table (50,000),
  process tracker, Sigma / detection engine state. YARA-X is not in the
  agent: `kestrel-scan.exe` is a separate process started only for a scan.

### Tray (release builds in mock mode, separate identifier, measured on this PC)

| Phase | Tray private MB | WebView2 processes | WebView2 private MB |
|---|---|---|---|
| Before, idle 60 s (window never opened) | 7.9 | 6 | 161.3 |
| Before, closed 30 s after use | 8.0 | 6 | 162.8 |
| After, idle 60 s | 4.9 | 0 | 0 |
| After, window open (GPU off) | 7.9 | 6 | 100.0 |
| After, closed 30 s after use | 6.9 | 0 | 0 |

### Independent review (2026-10-25) and what changed after it

A hostile review of this change found, and the code now handles:

* **gRPC request compression was an unauthenticated memory bomb.** tonic
  0.12 inflates a compressed frame with no bound before any handler runs,
  and `Enroll` needs no client certificate. The server now only *sends*
  zstd (to agents that advertise it) and refuses compressed requests
  (Unimplemented); agent payloads stay zstd-compressed inside the envelope,
  bounded by `MAX_PAYLOAD`. Test: `kestrel-server/tests/transport_perf.rs`.
* **Kernel (ETW) loss could hide under the 1 % rule.** Any increase of
  `etw_kernel_events_lost` makes the device Degraded again.
* **Value classes put detection input in the sheddable classes.** Image
  loads that pass the source filter and DNS answers are high value; TCP
  sends are medium (they can report a flow whose connect was lost); the
  agent channel no longer sheds early.
* **Coalescer invalidation scanned the map per process start** on the Core
  callback thread (a lever to make ETW lose events with process churn): now
  O(1) with pid generations in the key.
* **Upload de-duplication merged different things:** the key now includes
  `dst_host` (a C2 host behind a shared CDN address), the DNS answers and
  the image signature.
* **Repeat summaries:** the server ignores duplicate indexes and more
  summaries than rows.

Accepted: the first coalesced open opens its 2 s window even if that record
is then lost to a full queue (counted as `high_value_dropped`, so the
device shows Degraded); the outbox writer and enrichment workers run below
normal priority (Windows' starvation boost bounds the delay); a process
that floods high-value records can still fill the queue, which is reported
as before. Per-process fairness in the queue is not implemented.

### Still to measure on an installed agent (lab VM, not the owner's PC)

* Private memory, threads, handles and CPU of `kestrel-agent.exe` idle for
  an hour and during a parallel Rust build (target: <= 110 MB, <= 40
  threads, no high-value drop).
* `sensor health` counters during the OneDrive-like storm (any process
  calling `OpenProcess` in a loop) and during `git checkout` of a large
  repository (`raw_coalesced`, `raw_shed`, `file_agg_trimmed`,
  `high_value_dropped = 0`).
* Disk write rate idle (target < 10 KB/s) and events per minute on the
  device page versus 1.1.6.
* `kestrel-scan.exe` priority in Process Explorer (Background, EcoQoS
  leaf icon in Task Manager) and scan duration of a 5,000-file folder.
* Tray: autostart with `--background`, tray click open / close on HiDPI,
  consent prompt arriving with no window.
