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

## Decommissioning

To decommission a device, open it and use **Decommission device** in the danger zone at the bottom of the page (needs the `devices.write` privilege; type the hostname to confirm). Decommissioning (or merging a duplicate into another device) revokes its certificates, drops its live connection at once and cancels queued commands. Its history is kept. The agent stays installed on the PC; to remove it, uninstall it with the uninstall token (see [Uninstall](../deploy/enroll#uninstall)).
