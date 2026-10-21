# Troubleshooting

## Server

| Symptom | Check |
|---|---|
| `docker compose up` fails with "set POSTGRES_PASSWORD in .env" | Set `POSTGRES_PASSWORD` and `CLICKHOUSE_PASSWORD` in `deploy/.env`. |
| Server exits with `cannot decrypt stored secrets` | It was started with a different `KESTREL_MASTER_KEY` than the one that sealed the database. Restore the original key from your backup. |
| Cannot find the setup code | `docker compose logs kestrel-server \| grep "SETUP CODE"` (PowerShell: `Select-String "SETUP CODE"`). It is printed until the first administrator exists. Or set `KESTREL_SETUP_CODE`. |
| Browser warns about the certificate | The console uses a self-signed certificate until you set `TLS_CERT` and `TLS_KEY`. See [TLS](../deploy/server#tls). |
| Container not healthy | `docker compose ps`, `docker compose logs -f kestrel-server`, `curl -k https://localhost/api/healthz`. |
| Logins rate-limited behind a proxy | Set `KESTREL_TRUSTED_PROXIES` to the proxy's address so the real client address is used. |
| Webhook, Slack, Teams or OIDC to an internal host fails | Outbound requests reach only public addresses by default. Add the range to `KESTREL_OUTBOUND_ALLOW_CIDRS`. |
| Audit verify reports a break after a restore | Make sure the same master key is in use; the chain is keyed from it. |

## Enrollment and install

See [Troubleshooting enrollment](../deploy/enroll#troubleshooting-enrollment). The most common causes: the first name in `KESTREL_PUBLIC_HOSTNAME` is not reachable from endpoints, port 8443 is blocked or behind a TLS-terminating proxy, the token expired or is used up, or Defender removed the unsigned agent.

## Agent on a device

Run these in an administrator PowerShell on the device:

```powershell
Get-Service KestrelAgent                                   # Running
& 'C:\Program Files\Kestrel\kestrel-agent.exe' status      # JSON health from the running agent
logman query -ets | Select-String Kestrel                  # Kestrel-Core, Kestrel-IO (and Kestrel-ProcCmd)
Get-ChildItem C:\ProgramData\Kestrel\logs                  # agent logs
```

| Symptom | Check |
|---|---|
| Device `offline` | The agent has not contacted the server for 3 minutes. Check the service, network path to port 8443, and the agent logs. Detection and Protect actions keep working offline. |
| Device `degraded` | ETW is unhealthy or events were lost in the last hour. Check `logman query Kestrel-Core -ets` and `logman query Kestrel-IO -ets` (events lost, buffers lost). Another tool that stops all ETW sessions triggers `TP-01`. |
| `sc stop KestrelAgent` says access denied | Expected: the service DACL allows stop only to SYSTEM. Uninstall with the uninstall token instead. |
| DPAPI audit channel red, ST-03 never fires | Turn on the **DPAPI audit channel** hardening control (mode Enforce). |
| AppLocker controls show *skipped: domain policy present* | Expected: Kestrel never changes AppLocker policies managed by GPO or MDM. Add the rules in your own policy instead. Windows Home has no AppLocker. |
| LSA protection shows *Pending reboot* | It takes effect after the next restart, which Kestrel never forces. |
| A business app lost network access after an alert | An automatic image block (ST-02, ST-07, ST-16) or an IOC block. If it was a false positive, use **Lift network block** on the device or the incident checklist, and add an exclusion. |
| A file was quarantined by mistake | **Quarantine > Restore**. This also lifts its network blocks. |
| Host isolated and cannot reach the server | **Release host** if the server is reachable; otherwise run `kestrel-agent release-isolation --token <uninstall token>` locally as administrator. Isolation also releases itself after `isolation_auto_release_hours` (72 by default) without server contact. |
| Outbox keeps growing | The agent cannot upload. Check connectivity; when it exceeds the policy's outbox limit, the oldest events are dropped first, never alerts. |
| Certificate expired | Devices renew 30 days before expiry while online. An expired or revoked certificate cannot renew: uninstall and enroll again with a token. |
| Lost the uninstall token | Reveal it on the device page (**Uninstall token > Reveal**). Only an old server that issues none makes the agent write a local token to `C:\ProgramData\Kestrel\uninstall-token.txt` (administrators only). |

## Tray app

| Symptom | Check |
|---|---|
| No tray icon | It starts at sign-in from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. Sign out and in again, or start `C:\Program Files\Kestrel\kestrel-tray.exe`. |
| Tray says "Kestrel isn't running" | The service is stopped or the pipe is not available. Check `Get-Service KestrelAgent`. |
| Review request refused | One request per alert until IT decides, at most 5 per user per hour, and only for alerts the user can see. |

## Builds

| Symptom | Check |
|---|---|
| `protoc` not found | Install it (`winget install Google.Protobuf`) or set `PROTOC` to its path. |
| Linker errors on Windows | Install the Visual Studio 2022 Build Tools with the C++ workload, and use the MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`). |
| Agent fails on a clean PC with a missing `VCRUNTIME140.dll` | The static CRT setting in `.cargo/config.toml` was removed or not used. Build with the repository's cargo config. |
| `wix build` fails with an undefined variable | All five `-d` variables are required: `Version`, `AgentExe`, `ScanExe`, `CaDll`, `TrayExe`. |
| Built `.exe` files disappear or are locked | Defender flagged the unsigned build output. Add exclusions for the `target` folders only. |
| Disk full during a build | Run `cargo clean` in the repository and in `tray\src-tauri`. |
