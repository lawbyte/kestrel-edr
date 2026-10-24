# Resource use on endpoints

Kestrel runs on your employees' PCs, so it is built to stay small and quiet. This page lists what to expect, how to check it yourself, and what Kestrel does when a PC gets busy.

Kestrel works in user mode. When a PC produces events faster than any user-mode sensor can read them, some can be lost; Kestrel tells you when that happens and which side lost them.

## What to expect

Targets for an idle office or developer PC with agent 1.1.7 or later:

| Resource | Target |
|---|---|
| Agent CPU | Under 0.1 % of the PC on average, short peaks while many programs start |
| Agent memory | About 100 MB private memory, at most 110 MB |
| Agent threads | 40 or fewer |
| Agent disk | Under 10 KB/s of writes when the PC is idle |
| Telemetry upload | Under 30 KB per minute when the PC is idle (compressed) |
| Tray app, closed | Under 20 MB, no CPU, no `msedgewebview2.exe` processes |
| Tray app, open | One WebView2 set of about 100 MB, gone as soon as the window closes |
| Lost events | None of the important kinds; fewer than 1 % in total |

From a developer workstation's own telemetry (three idle hours and one storm hour, replayed through the 1.1.6 and 1.1.7 upload paths) and the tray measured on the same PC:

| | 1.1.6 | 1.1.7 |
|---|---|---|
| Telemetry rows per minute, idle | 988 | 585 |
| Telemetry upload per minute, idle | 37 KB | 23 KB |
| Telemetry rows per minute, during a storm of repeated handle opens | 24,584 | 1,497 |
| Tray memory with the window closed | 8 MB + 161 MB of WebView2 | 5 MB, no WebView2 |

## Check it yourself

Task Manager: on the **Details** tab add the columns **Memory (active private working set)**, **Threads** and **Handles**, and look at `kestrel-agent.exe` and `kestrel-tray.exe`. On the **Processes** tab expand **Kestrel**: with the tray window closed there are no WebView2 processes under it.

PowerShell, no elevation needed:

```powershell
Get-Process kestrel-agent, kestrel-tray -ErrorAction SilentlyContinue |
  Select-Object Name, @{n='PrivateMB';e={[math]::Round($_.PrivateMemorySize64/1MB,1)}},
    @{n='Threads';e={$_.Threads.Count}}, Handles, CPU

# 10 minutes of samples every 10 seconds, saved for Performance Monitor
Get-Counter -Counter '\Process(kestrel-agent)\% Processor Time',
  '\Process(kestrel-agent)\Private Bytes', '\Process(kestrel-agent)\Thread Count',
  '\Process(kestrel-agent)\IO Write Bytes/sec' `
  -SampleInterval 10 -MaxSamples 60 | Export-Counter -Path .\kestrel-agent.blg
```

`% Processor Time` counts one CPU as 100 %; divide by the number of logical processors to compare with Task Manager.

In the console, the device page shows the agent's own CPU and memory, events per minute, the outbox depth and **Events lost**, split into events Windows lost and events Kestrel dropped.

## What Kestrel does when a PC is busy

Builds, large `git checkout`s and some background apps (we have seen a sync client open the same process 25,000 times a second) produce bursts of events. Kestrel handles them in this order:

1. **Noise is filtered where it is read.** File opens of paths that can never matter for detection and DLL loads from the Windows and Program Files folders (except a list of DLLs that do matter) are not queued at all. Identical handle opens (same program, same target, same access) within 2 seconds count once.
2. **Low-value records give way first.** When the agent's queue fills up, bookkeeping records go first (connection ends), then byte counts of network traffic. Process starts and stops, DLL loads that passed step 1, DNS answers, handle opens to other processes, browser data decryption (DPAPI), sensitive file opens, new network connections, registry and persistence changes are only lost if the queue is completely full, and that is reported separately.
3. **Detection sees everything that arrived.** The steps below only change what is uploaded for hunting.
4. **Repeats are uploaded once with a count.** The first time a program does something (opens a file, connects to an address, opens another process) it is uploaded right away. The same thing again within 5 minutes becomes one extra row with **repeat count** and the time of the first repeat. Process starts and stops, scripts, file-activity summaries, persistence changes and tamper signals are never merged.
5. **Uploads are batched and compressed.** Up to 500 rows or 5 seconds per batch, each batch compressed with zstd before it is stored and sent. Alerts never wait for a batch.
6. **Background work runs at low priority.** YARA scans (`kestrel-scan.exe`), signature checks of programs that are already running and revocation checks use Windows background priority and efficiency mode (EcoQoS), so they slow down instead of slowing the employee down. Detection and response stay at normal priority.
7. **The outbox has a size limit.** When the server is unreachable for long, the oldest telemetry batches are dropped first (**Policies**, `max_outbox_mb`). Alerts and action results are never dropped.

### When is a device "Degraded"?

The device status turns **Degraded** for an hour when the agent reports that its ETW sessions are not running, or when a heartbeat shows lost events that matter:

* any event Windows itself lost (the PC produced events faster than they could be read),
* any lost event of an important kind (step 2), or
* lost events of any kind above 1 % of the events of that interval.

A few bookkeeping records skipped during a build no longer make a device Degraded. Agents older than 1.1.7 do not report the split, so for them any loss still counts.
