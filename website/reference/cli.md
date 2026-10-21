# Agent CLI

`kestrel-agent.exe` is installed in `C:\Program Files\Kestrel`. Most commands need an administrator shell. On a managed device you normally use only `status`, `uninstall` (through the MSI) and `release-isolation`.

```text
kestrel-agent [--state-dir <dir>] <command> [options]
kestrel-agent --version
kestrel-agent --help
```

Global option:

| Option | Meaning |
|---|---|
| `--state-dir <dir>` | Agent state folder. Default `C:\ProgramData\Kestrel` on Windows, `./kestrel-state` elsewhere. Environment: `KESTREL_STATE_DIR`. |

## Commands

| Command | Purpose |
|---|---|
| `status` | Print agent health as JSON (queries the running agent). |
| `run [--console]` | Run the agent. As a Windows service unless `--console` (foreground, logs on stderr). `service` is an alias used by the service registration. Disposable VMs only. |
| `install` | Write the config, enroll with the server and install the service. The MSI runs this; do not run it by hand on a real machine. |
| `enroll [--token <t>]` | Re-enroll this device (new key and certificate). |
| `uninstall` | Stop and remove the agent service. Requires the uninstall token. |
| `release-isolation --token <t>` | Break-glass: remove network isolation locally when the host cannot reach the server. Requires the uninstall token. |
| `simulate` | Run the full agent against recorded telemetry (any OS, touches nothing real). |

Hidden commands (not listed by `--help`):

| Command | Purpose |
|---|---|
| `sensors-test [--seconds N] [--events-out <file>] [--detect]` | Start only the ETW sensors for N seconds (default 20) and print event counts as JSON. No server, no response actions. `--detect` also runs the engine with every rule forced to Audit and prints alerts. Read-only; used by `scripts/windows-smoke.ps1` and `scripts/sensor-probe.ps1`. Needs an elevated shell. |
| `update-keygen --out <dir>` | Create the Ed25519 update signing key pair (`kestrel-update-signing.key`, `.pub`). Refuses to overwrite. Owner only, offline. |
| `update-sign --key <file> --version <v> --url <https url> --file <msi>` | Print the signed update manifest JSON to paste into **Agent updates > Register release**. |
| `desktop-helper --pipe <name> --parent <pid>` | Remote desktop helper started by the service in the user's session. Not for manual use. |

## install, simulate: server options

| Option | Environment | Meaning |
|---|---|---|
| `--server <host:port>` | `KESTREL_SERVER` | Server gRPC address. |
| `--ca <pem>` | `KESTREL_CA` | Server CA: a PEM file path, PEM text, or base64. |
| `--token <t>` | `KESTREL_ENROLL_TOKEN` | Enrollment token. Avoid on shared hosts: command lines are visible to process-creation sensors. |
| `--token-stdin` | | Read the enrollment token from the first line of stdin (what the MSI does). |
| `--server-name <name>` | | TLS name to verify on the server certificate (default: the host in `--server`). |

`install` also takes:

| Option | Meaning |
|---|---|
| `--group-tag <tag>` | Device tag reported to the server (repeatable). |
| `--uninstall-token <t>` | Only for old servers that do not issue a token at enrollment (environment `KESTREL_UNINSTALL_TOKEN`). |
| `--no-service` | Write the config and enroll, but do not register the service. |

`simulate` also takes:

| Option | Default | Meaning |
|---|---|---|
| `--replay <file>` | required | JSONL file of events to replay (see `crates/kestrel-agent/replays/`). |
| `--speed <x>` | `1.0` | Replay speed multiplier. |
| `--hostname <name>` | `SIM-WKS-01` | Hostname to report. |
| `--exit-after-replay <s>` | run until Ctrl+C | Exit N seconds after the replay finishes and uploads drain. |
| `--heartbeat-secs <s>` | 30 | Heartbeat interval. |
| `--sim-consent <allow\|deny\|ignore>` | `allow` | How the simulated employee answers remote-access consent prompts. |

## uninstall and release-isolation

| Option | Meaning |
|---|---|
| `--token <t>` | The device's uninstall token (from **Uninstall token > Reveal** on the device page). Environment: `KESTREL_UNINSTALL_TOKEN`. |
| `--token-stdin` | `uninstall` only: read the token from stdin (used by the MSI). |
| `--purge` | `uninstall` only: also delete the state folder (keys, outbox, logs). |

Prefer the MSI for uninstalling, so Windows Installer also removes the files:

```powershell
msiexec /x KestrelAgent.msi /qn UNINSTALL_TOKEN=<token>
```

Break-glass release of isolation:

```powershell
& 'C:\Program Files\Kestrel\kestrel-agent.exe' release-isolation --token <uninstall token>
```

## Examples

```powershell
# Health of the running agent
& 'C:\Program Files\Kestrel\kestrel-agent.exe' status

# Read-only ETW check (elevated; stop a running KestrelAgent service first)
& 'C:\Program Files\Kestrel\kestrel-agent.exe' sensors-test --seconds 30
```

```bash
# Simulated endpoint against a test server (any OS)
cargo run -p kestrel-agent -- --state-dir ./simstate simulate \
  --server 127.0.0.1:18444 --server-name localhost --ca ca.pem --token kte_... \
  --replay crates/kestrel-agent/replays/lumma_clickfix.jsonl --exit-after-replay 10
```

## Other binaries

* `kestrel-scan.exe --rules-dir <dir> --targets-file <file>`: the YARA-X scanner, started by the agent for the Scan action. Prints one JSON report. `--version` prints its version.
* `kestrel-tray.exe`: the employee tray app, started at sign-in with `--background`.
