# Devices

**Devices** lists every enrolled endpoint with its status, signed-in user, OS and build, agent version (versions older than the newest in the fleet are highlighted), last contact, group, policy and open incidents. Filter by hostname, user, IP, status or group, and export the list with **Export CSV**. **Install agent** opens the install wizard (see [Enroll devices](../deploy/enroll)).

<Shot name="console/devices" alt="Devices list" />

## Device status

| Status | Meaning |
|---|---|
| `online` | Connected and healthy. |
| `degraded` | ETW is unhealthy or events were lost in the last hour. |
| `offline` | No contact for 3 minutes. Detection and Protect actions still run on the device; results upload when it reconnects. |
| `isolated` | The agent reports network isolation. |
| `paused` | Shown as **Protection off**: someone turned protection off on the PC with the uninstall token. See [Protection turned off on the device](#protection-turned-off-on-the-device). |

When more than one applies, the first one in this order wins: isolated, offline, protection off, degraded, online.

## The device page

<Shot name="console/device" alt="Device page" />

The header shows hostname, status, OS, signed-in user, last contact and group. The toolbar below it holds device-wide actions: **Isolate host** or **Release host**, **Collect triage**, **Scan** and **Re-apply hardening** (with the number of drifted controls). See [Response actions](./response).

### Sensor health

| Row | Meaning | If it is not green |
|---|---|---|
| Kernel telemetry (ETW) | All ETW sessions running; events per minute | Check `logman query Kestrel-Core -ets` on the device and the agent logs in `C:\ProgramData\Kestrel\logs`. |
| Events lost (1 h) | ETW events or buffers lost | Heavy I/O can drop events. More than 500 lost between heartbeats raises `TP-SRV-EVENTS-LOST`. |
| Sysmon | Optional; adds handle-access detail | Not required. |
| DPAPI audit channel | Optional. Needed by rule ST-03 | Shown grey while off. To use ST-03, turn on the **DPAPI audit channel** hardening control in the policy. |
| AMSI provider | Not used in this version | Shown grey. Kestrel 1.1 reads script content from PowerShell script-block logging instead; an AMSI provider is on the roadmap. AMSI tampering is still detected by `TP-03`. |
| Outbox | Messages queued on the device | Should drain to about 0 while online. |

The card also shows agent CPU, memory, uptime and the antivirus product.

### Device card

Agent version, IP addresses, domain, policy and the policy version applied, enrollment time, **certificate expiry** (agents renew automatically 30 days before), tags, and the **uninstall token**:

* **Reveal** shows the token (written to the audit log). You need it for `msiexec /x`, `kestrel-agent uninstall` and the isolation break-glass.
* **Rotate** sends a new token to the agent. A pending marker shows until the agent confirms; the old token works until then.

If another device was enrolled with the same hardware UUID, a banner offers to **merge** the two (the other device is decommissioned) or **dismiss** the warning.

On devices with a remote-access profile, a summary card shows the install ceiling, what the policy allows and the effective result.

### Tabs

| Tab | Contents |
|---|---|
| Event timeline | Telemetry from the device in plain words (process starts, file access, network, DNS, registry, tasks, services, WMI), with the raw JSON one click away. Registry and persistence events show *writer inferred* or *writer unknown* when the writing process could not be pinned down exactly. Processes the agent itself started are labelled *started by Kestrel*. |
| Recent alerts | Alerts on this device. |
| Process tree | Running and recent processes with signer, hash and path class. |
| Effective settings | The policy as the device receives it, including exclusions, IOCs and branding. |
| Hardening | Each hardening control with what the policy wants, what is on the device, and the source (Kestrel, or a domain or MDM policy that Kestrel leaves alone). Controls that need a restart show *Pending reboot*. |
| Inventory | Installed software (name, version, publisher) and local administrators. |
| Actions | Process, file and network actions for this device, and the action history. |
| Remote desktop, Files | Only when the install profile and the policy both allow remote access. See [Remote access](../guide/remote-access). |

## Protection turned off on the device

An employee or on-site technician can turn Kestrel protection off for a while from the tray app, for example to install a tool that Kestrel blocks. It needs the device's uninstall token, and the policy decides whether it is allowed, which modes can be chosen and for how long (see [Local turn-off](./policies#local-turn-off)).

<Shot name="console/device-protection-off" alt="Device page with the protection off banner" />

While protection is off:

* The device shows the status **Protection off** (icon and label) in the devices list, on the device page and on incidents. Filter the devices list by status to find every such device; the Overview counts them too.

<Shot name="console/devices-paused" alt="Devices list with a device whose protection is off" />

* The device page shows a banner with the mode, the time protection comes back on by itself (or *until turned back on*), who turned it off and when.
  * **Detection only** (the default): sensors and alerts keep running, but Kestrel takes no automatic action (no suspend, kill, quarantine or block) and does not enforce hardening. Every alert from the device is recorded in Audit mode and carries the note *Protection was turned off on this PC (detection only): no automatic action was taken.* Actions you send from the console still run.
  * **Completely off** (only if the policy allows it): the sensors are stopped and the device only sends heartbeats, so nothing on it is detected.
* Every turn-off raises a `TP-06` alert (medium for detection only, high for completely off). Turning it back on raises an info `TP-06` alert, and wrong uninstall tokens raise a medium one. After 5 wrong tokens the tray locks the switch for a while, and the lockout grows with each further failure.

### Turning protection back on

Click **Turn protection back on** in the banner, give a reason and confirm. This sends the `resume_protection` action (privilege `response.collect`). It never needs the token. The device goes back to its policy at once; a device that is offline does it when it reconnects. The person at the PC can also turn it back on from the tray, and a timed turn-off ends by itself.

Turning protection off is not a substitute for an exclusion. If a business tool is blocked, add an [exclusion](./rules#exclusions) so the rest of the PC stays protected.

### Audit log

The agent reports every change, and the server writes it to the audit log with the actor *Kestrel (automatic)*:

| Action | When |
|---|---|
| `device.protection_off` | Protection was turned off (mode, start, end, Windows user). |
| `device.protection_on` | Protection came back on. `reason` is `manual` (tray), `expired`, `console` or `policy` (a policy change ended it). |
| `device.protection_off_denied` | A wrong uninstall token was entered (`failures`, `locked_until_ms`). |
| `device.protection_off_clamped` | A policy change shortened an active turn-off. |

Your own **Turn protection back on** request is also logged as `response.request`.

## Decommissioning

To decommission a device, open it and use **Decommission device** in the danger zone at the bottom of the page (needs the `devices.write` privilege; type the hostname to confirm). Decommissioning (or merging a duplicate into another device) revokes its certificates, drops its live connection at once and cancels queued commands. Its history is kept. The agent stays installed on the PC; to remove it, uninstall it with the uninstall token (see [Uninstall](../deploy/enroll#uninstall)).
