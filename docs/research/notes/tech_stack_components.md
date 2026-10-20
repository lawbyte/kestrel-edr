# Tech Stack and Reusable Open-Source Components for a Small-Team Windows EDR (2025-2026)

Research date: 2026-10-20. Versions and statuses are as observed on that date.

## 1. Agent language and ETW consumption libraries (Rust vs C#/.NET vs Go vs C++)

### Takeaway
Rust is the strongest fit for a small team that develops on Linux. It offers memory safety, no runtime, a maintained ETW crate (ferrisetw, a krabsetw port), a native YARA-X engine, a mature Sigma evaluator (rsigma), a services crate from Mullvad, and cross-compilation via cargo-xwin. C#/.NET with TraceEvent is the most productive alternative but is weaker for Native AOT agents. Go is proven by Fibratus and Velociraptor, but its best ETW library is GPL-3.0. C++ with krabsetw is what kernel-heavy vendors use, at the cost of memory safety.

### Cited Findings
**Rust**
- ferrisetw provides "safe Rust abstractions over the ETW consumer APIs". It started as a Rust port of Microsoft's KrabsETW, uses windows-rs bindings, and has adapted its API to idiomatic Rust since 1.0. It still calls itself "WIP". — [ferrisetw GitHub](https://github.com/n4r1b/ferrisetw)
- ferrisetw is licensed MIT OR Apache-2.0. Its latest version is 1.2.0, last published 2024-06-27, with about 178.6k total downloads. **Note: there has been no release in over two years, so plan to vendor or fork it.** — [crates.io API: ferrisetw](https://crates.io/api/v1/crates/ferrisetw)
- windows-service (Mullvad) handles Windows service implementation (`define_windows_service!`, `service_control_handler::register`, `ServiceStatus`). It is MIT/Apache-2.0 and has about 620 stars. — [mullvad/windows-service-rs](https://github.com/mullvad/windows-service-rs)
- Rustinel is a 2025-26 open-source Rust endpoint detection tool that uses "ETW + Windows Event Log" on Windows, Sigma for behaviour, YARA for executables and process memory, and IOC lists. It writes alerts locally as ECS NDJSON and has capture/replay. It is Apache-2.0 with about 503 stars. Windows and Linux are "Stable", but the project says it has no anti-tamper, no pre-execution blocking and no management console. — [karib0u/rustinel](https://github.com/karib0u/rustinel)

**C++**
- krabsetw is a C++ library that wraps ETW consumption. Microsoft.O365.Security.Native.ETW is its C++/CLI .NET wrapper, nicknamed "Lobsters", "used in production by the Office 365 Security team". It supports only x64 and ARM64 (no x86) on Windows 7 / 2008 R2 and later. — [microsoft/krabsetw](https://github.com/microsoft/krabsetw)
- RedEdr, a research EDR in C++ under GPL-3.0, uses a kernel driver for process/thread/image callbacks. It consumes ETW-TI only from a PPL service started via an empty signed ELAM driver. — [dobin/RedEdr](https://github.com/dobin/RedEdr)

**C# / .NET**
- Microsoft.Diagnostics.Tracing.TraceEvent is MIT, at version 4.0.0 (updated 2026-10-14), targeting netstandard2.0 and so compatible with .NET 5-10. — [NuGet: TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent)
- TraceEvent works on .NET Framework 4.6.2+ and netstandard2.0. Its docs do not mention Native AOT or trimming. — [TraceEvent Library docs](https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventLibrary.md)
- Native AOT does not support dynamic loading, runtime code generation (Reflection.Emit) or **C++/CLI**. It has no built-in COM, requires trimming, and on Windows needs the VS "Desktop development with C++" workload. It applies to .NET 7+, and AOT analysis warnings need net8.0+. — [Microsoft Learn: Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)
- Implication from the line above: the krabsetw .NET wrapper (C++/CLI) cannot be used in a Native AOT agent. — [Microsoft Learn: Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/); [krabsetw](https://github.com/microsoft/krabsetw)

**Go**
- Fibratus is written in Go (go.mod), licensed Apache-2.0, has about 2.6k stars and 1,428 commits, and ships a "behavior-driven rule engine" and YARA memory scanner. — [rabbitstack/fibratus](https://github.com/rabbitstack/fibratus); [Fibratus LICENSE.MD](https://raw.githubusercontent.com/rabbitstack/fibratus/master/LICENSE.MD)
- Fibratus provides kernel-level ETW tracing, a rule language with YAML, sequences and filter expressions, YARA memory scanning, response actions such as killing a process, and MITRE ATT&CK mapping. — [fibratus.io](https://www.fibratus.io/)
- The Fibratus catalogue has about 134 rules. By ATT&CK category: defense evasion 49, credential access 26, privilege escalation 24, persistence 16, initial access 12, execution 5, lateral movement 2. — [fibratus.io/rules](https://www.fibratus.io/rules)
- golang-etw (0xrawsec) is a "Pure Golang (no need to enable CGO)" real-time ETW consumer licensed **GPL-3.0**. — [0xrawsec/golang-etw](https://github.com/0xrawsec/golang-etw)
- Velociraptor is written in Go. — [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor)
- Aurora (Nextron) is described as a "Sigma-based EDR agent", with a free "Aurora Lite". — [Nextron blog 2021](https://www.nextron-systems.com/2021/11/13/aurora-sigma-based-edr-agent-preview/)

**Privileged telemetry (all languages)**
- Running an antimalware service as PPL requires applying to Microsoft, signing legal agreements, passing tests, and building an ELAM driver that Microsoft signs. — [Elastic Security Labs](https://www.elastic.co/security-labs/sandboxing-antimalware-products)
- Artifact Signing's FAQ covers ELAM: the Authenticode certificate it issues for anti-malware binaries "is valid for three days". — [Artifact Signing FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq)

### Inferences
- **Recommendation: Rust for the agent.** Use ferrisetw (or a fork) on windows-rs, `windows-service` for the SCM, `tokio` + `tonic` for comms, `yara-x` for scanning, and `rsigma-eval` for Sigma. Every core component is permissive (MIT/Apache/BSD), and the whole agent cross-compiles from Linux.
- ferrisetw's stale release cadence is the main risk. Be ready to patch it, or to write a thin ETW layer directly on `windows-rs` (EnableTraceEx2/OpenTrace/ProcessTrace plus TDH parsing).
- If the team is C#-heavy, a .NET 8/9 self-contained (non-AOT) agent with TraceEvent is very productive. Use AOT only after testing TraceEvent trim-compatibility, which is undocumented.
- Avoid golang-etw if the agent must stay non-GPL. A Go agent would need Fibratus's internal ETW package (Apache-2.0) or its own syscall bindings.
- Expect to use only user-mode ETW (Kernel-Process/File/Network/Registry, Sysmon-like coverage) at first. ETW-TI and kernel callbacks need a signed driver or ELAM/PPL path, which is out of reach for a small team at v1.

### Gaps
- I found no independent head-to-head benchmark of ETW event throughput across ferrisetw, TraceEvent, krabsetw and Go libraries.
- Elastic Defend's implementation language could not be confirmed. The elastic/endpoint repo page lists no language. The brief's claim of "Elastic Defend = C++" is unverified here.
- Wazuh agent language: the repo's dependency list suggests C/C++, but this was not confirmed. Aurora's implementation language (assumed Go in the brief) is not confirmed by sources fetched.
- I did not measure Native AOT or Rust binary sizes. No source gave figures.

## 2. Rule engines usable in-agent (Sigma, YARA vs YARA-X, sequence correlation) and their licenses

### Takeaway
Use YARA-X (BSD-3, v1.21.0) for file and memory signatures, but note it **does not yet implement process scanning**. Use a Rust Sigma evaluator (rsigma-eval, MIT, all 8 correlation types) for behavioural rules. SigmaHQ rules (DRL 1.1) can be used commercially, but alert views must show the rule author. Do not ship Elastic's detection rules (ELv2) in your own product.

### Cited Findings
- YARA-X 1.0.0 was announced on 2025-06-04. About 99% of rules "work as-is", it is "often 5–10× faster" on regex and loops, and YARA 4.x is now "bug-fix only" while new features land in YARA-X. — [VirusTotal blog, June 2025](https://blog.virustotal.com/2025/06/)
- YARA-X is BSD-3-Clause, at 1.21.0 (updated 2026-09-29). — [crates.io API: yara-x](https://crates.io/api/v1/crates/yara-x)
- YARA-X has C (`capi`), Python and Go bindings. No .NET binding is listed. — [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x)
- YARA-X "is not a drop-in replacement" at the API level. **Process scanning is not implemented yet** and is low-priority. YARA can still beat YARA-X on some rules and files. — [YARA-X vs YARA docs](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/)
- rsigma-eval (MIT) compiles Sigma rules once and evaluates JSON events with "zero-allocation on the hot path". It supports "all 8 correlation types" (sliding windows, group-by, chaining), all 30 modifier combinations, and pySigma-compatible pipelines. One event against 1,000 rules takes about 30 µs. Latest release is 0.24.0 (2026-10-05). — [docs.rs rsigma-eval](https://docs.rs/crate/rsigma-eval/0.22.0)
- The rsigma toolkit lives in the `timescale` GitHub org and includes parser, eval, convert, runtime (hot-reload), CLI daemon, LSP and MCP server. Its linter is based on Sigma v2.1.0. Native converters exist for PostgreSQL/TimescaleDB and Fibratus, and it delegates to sigma-cli for 30+ pySigma backends. MIT, about 168 stars. — [timescale/rsigma](https://github.com/timescale/rsigma)
- sigma-rust (Apache-2.0/MIT) is "100% safe Rust" and supports all modifiers except `expand`. Version 0.7.0 shipped 2025-11-26. Correlation support was not mentioned. — [docs.rs sigma-rust](https://docs.rs/crate/sigma-rust/latest)
- sigma-go (MIT) "exposes the ability to check whether a rule matches a given event but not much else". Aggregators are toy implementations. — [bradleyjkemp/sigma-go](https://github.com/bradleyjkemp/sigma-go)
- The SigmaHQ repo has "more than 3000 detection rules" under DRL 1.1. — [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- DRL 1.1 is based on MIT and allows commercial use. Vendors "must include the author in views that show matches" (for example, a separate field or column), plus the license and copyright notice. SPDX: DRL-1.1. — [SigmaHQ/Detection-Rule-License](https://github.com/SigmaHQ/Detection-Rule-License)
- Fibratus's rule language supports YAML, event sequences and filter expressions. — [fibratus.io](https://www.fibratus.io/)
- Everything in elastic/detection-rules is under Elastic License v2. — [elastic/detection-rules](https://github.com/elastic/detection-rules)

### Inferences
- **Recommended in-agent engine:** `rsigma-eval` for single-event and correlation Sigma, plus a small custom stateful sequence layer (EQL-like, keyed by process GUID with maxspan) for behaviours Sigma correlation expresses poorly. Fibratus's open Apache-2.0 rules are a good model and source.
- For memory scanning, YARA-X can scan buffers you read yourself with ReadProcessMemory. It cannot do YARA's built-in `pid` scanning. Alternatively, keep libyara 4.x (BSD-3) for process scans.
- Sigma field mapping: use a pySigma-style pipeline to map Sysmon-style field names onto your ETW schema. That way the SigmaHQ `windows/process_creation` and related rules apply without changes.
- The admin console must show a "rule author" column for every Sigma match to comply with DRL 1.1.

### Gaps
- YARA's own license (BSD-3) was not re-verified this session.
- I did not compare the maturity of the newer Rust Sigma crates against pySigma test suites.

## 3. Agent-server communication (gRPC streaming, mTLS, enrollment, pinning, offline buffering)

### Takeaway
The reference designs all use: an enrollment secret or embedded config for bootstrap, then a per-host credential (node key or per-client keypair), a CA pinned in the client, batched messages, and a bounded local disk buffer. The modern equivalent is gRPC bidirectional streaming over TLS 1.3 with per-agent client certificates issued at enrollment (tonic + rustls).

### Cited Findings
**Velociraptor**
- Clients send HTTPS POST batches (protobuf MessageList) and receive queued server messages in the response. Each batch is encrypted with an AES-128-CBC session key, wrapped with the receiver's public key and signed by the sender, inside TLS (two layers). — [Velociraptor security docs](https://docs.velociraptor.app/docs/deployment/security)
- In self-signed mode the client requires server CN `VelociraptorServer` signed by the embedded CA, which "essentially pins the server's certificate in the client". The client ID is derived from the client's key, so it cannot be spoofed. Enrollment is "zero registration". Optional mTLS uses one shared client certificate valid for 1 year with no CRL. — [Velociraptor security docs](https://docs.velociraptor.app/docs/deployment/security)
- `Client.local_buffer` stores query results: memory_size default 50 MB, disk_size default 1 GB, Windows file `$TEMP/Velociraptor_Buffer.bin`. `max_poll` defaults to 60 s. WebSockets (`wss://`) have been supported since 0.72. — [Velociraptor config reference](https://docs.velociraptor.app/docs/deployment/references)
- Velociraptor can sit behind nginx terminating TLS. — [Velociraptor comms blog 2020](https://docs.velociraptor.app/blog/2020/2020-09-28-velociraptor-network-communications-30568624043a/)

**Fleet / osquery**
- All fleetd components use HTTPS. The enroll secret is used only for initial enrollment and is then moved to Windows Credential Manager. After that, orbit and osquery each authenticate with their own node key. The Fleet Desktop tray app gets a random token rotated hourly. Host identity is the hardware UUID. "The Fleet server does not provide support for mTLS", so a load balancer is needed for it. — [Fleet: fleetd authentication](https://fleetdm.com/guides/fleetd-authentication)
- Fleet's free version is MIT. A commercial license also exists. — [fleetdm/fleet](https://github.com/fleetdm/fleet)

**Wazuh**
- At enrollment the manager generates a unique client key per agent, used to encrypt agent-manager traffic. Optional password auth and manager/agent certificate verification are available. — [Wazuh enrollment](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html)
- Manager identity verification: the manager certificate is checked against `rootCA.pem` (`<server_ca_path>`) before enrollment. — [Wazuh manager verification](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/manager-identity-verification.html)
- The agent `client_buffer` holds a 5,000-event queue by default (max 100,000), sending at 500 EPS by default (max 1,000). — [Wazuh client_buffer](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client-buffer.html)

**gRPC in Rust**
- tonic is MIT, supports bidirectional streaming and "TLS backed by rustls". The 0.14.x branch is the current release line. — [hyperium/tonic](https://github.com/hyperium/tonic)

### Inferences
- **Recommended protocol:**
  1. MSI installs with a short-lived, scoped enrollment token.
  2. The agent generates a keypair (ideally non-exportable, stored with CNG/TPM), sends a CSR plus token over TLS to `/enroll` with the server CA pinned, and receives a per-agent client certificate (short-lived, e.g. 30 days, auto-renewed).
  3. Everything after that runs over one long-lived gRPC bidi stream with mTLS: agent→server for telemetry batches, heartbeats and alerts; server→agent for commands, rule/config updates and isolation.
  4. Use exponential-backoff reconnect.
  5. Run a local SQLite/WAL or append-only segment buffer capped at around 500 MB-1 GB, with priority (alerts before raw telemetry), echoing Velociraptor's 1 GB disk buffer.
- Unlike Velociraptor's shared mTLS certificate (no CRL) and Fleet's lack of server mTLS, per-agent certificates allow per-device revocation, which is a clear improvement.
- Terminate mTLS in the Go/Rust backend itself, or in Envoy/nginx with client-cert pass-through.

### Gaps
- I could not confirm Wazuh's port numbers (1514/1515) or cipher (AES) from the pages fetched.
- No source compared gRPC vs WebSocket vs HTTPS polling performance for agents at scale.

## 4. Backend and telemetry storage at "thousands of endpoints" scale

### Takeaway
For a small team, use PostgreSQL for control-plane state (devices, users, rules, alerts, cases) and ClickHouse (Apache-2.0) for raw telemetry and hunting. ClickHouse compresses an order of magnitude better than Elasticsearch and is much cheaper to run. Add NATS JetStream as a lightweight buffer and fan-out bus, not Kafka. Use TimescaleDB only if you want one database at modest volume, and note its TSL license nuance.

### Cited Findings
- ClickHouse is Apache-2.0, has about 49.2k stars, and is actively released (26.7, July 2026). — [ClickHouse GitHub](https://github.com/ClickHouse/ClickHouse)
- A 2026 comparison cites ClickHouse at 10-30x compression vs Elasticsearch at 1.5-3x, ingest at 1M+ rows/s vs 100-300K docs/s, and 1B-row aggregation at about 200 ms vs 2-5 s. Elasticsearch is faster for full-text and fuzzy search. **Caveat: no methodology is given, and the article's cost totals are arithmetically inconsistent.** — [OneUptime blog, Jan 2026](https://oneuptime.com/blog/post/2026-01-21-clickhouse-vs-elasticsearch/view)
- TimescaleDB has two editions. The Apache-2 Edition is open source. The Community Edition uses the Timescale License (TSL), which forbids offering it as DBaaS but allows a "Value Added Product or Service" if users cannot change the schema (DDL) and are notified of the TSL. — [Tiger Data licenses](https://www.tigerdata.com/legal/licenses)
- rsigma has a native Sigma→PostgreSQL/TimescaleDB converter, which allows server-side Sigma-as-SQL. — [timescale/rsigma](https://github.com/timescale/rsigma)
- NATS JetStream adds persistence and replay to NATS and runs as a single binary with no ZooKeeper/KRaft. A three-node cluster gives HA. It has built-in KV and object stores, explicit acks and dead-letter handling. Kafka remains better for multi-year replay, billions of events per day, or a heavy Kafka Connect ecosystem. — [CoderCops: NATS JetStream in production 2026](https://blog.codercops.com/blog/nats-jetstream-production-2026)

### Inferences
- **Sizing heuristic (assumed, not sourced):** 5,000 endpoints at about 1-5 KB/s each of filtered telemetry gives roughly 2-20 TB/month raw. That is well within a single ClickHouse node or a small cluster at 10x+ compression, and painful for Elasticsearch/OpenSearch.
- **Recommended pipeline:** agent → gRPC ingest service (Go or Rust, stateless) → NATS JetStream subject → (a) ClickHouse batch writer (async inserts, MergeTree partitioned by day, TTL 30-90 d), (b) server-side correlation/Sigma worker, (c) alert writer to Postgres.
- On the agent, use SQLite (WAL) for the offline queue, local rule cache and config.
- OpenSearch is worth adding only if analysts need Lucene-style free-text search across command lines. ClickHouse `ngrambf_v1`/`tokenbf_v1` skip indexes or the newer full-text index usually suffice.

### Gaps
- I found no rigorous, methodology-backed benchmark for EDR-shaped workloads. Figures above are indicative only.
- OpenSearch's license (Apache-2.0) was not re-verified this session.
- Redis Streams was not researched in depth.

## 5. UI frameworks: employee tray app and admin console

### Takeaway
For the employee tray app, the lowest-footprint good-looking options are **Tauri 2** (shared Rust code with the agent; a minimal app can be under 600 KB; WebView2 ships with Win10 1803+/Win11) or **WPF + WPF-UI** (MIT, Fluent/Mica, built-in tray). WinUI 3 looks the most native but adds Windows App SDK runtime and packaging friction. Electron is heavy. For the admin console, build a web app (React/Next.js + shadcn/ui + Tremor/Recharts), which is the norm for EDR consoles. Wrap it in Tauri later only if a desktop console is truly required.

### Cited Findings
- "A minimal Tauri app can be less than 600KB in size" because it uses the system webview. The backend is Rust. — [Tauri v2 docs](https://v2.tauri.app/start/)
- Tauri 2 tray: `tray-icon` feature, `TrayIconBuilder` (Rust) or `TrayIcon.new` (JS), menus, and click/double-click/enter/leave events. On Linux tray events are not emitted. — [Tauri system tray](https://v2.tauri.app/learn/system-tray/)
- Tauri Windows installers: MSI (WiX v3) "can only be created on Windows". NSIS can be cross-compiled from Linux with cargo-xwin and LLVM ("not tested as much"). WebView2 modes: downloadBootstrapper (+0 MB), embedBootstrapper (~1.8 MB), offlineInstaller (~127 MB), fixedVersion (~180 MB). WebView2 ships with Windows 10 April 2018+ and Windows 11. — [Tauri Windows installer docs](https://v2.tauri.app/distribute/windows-installer/)
- Typical ranges, with no methodology given: Electron installer 80-150 MB, idle 150-300 MB RAM, cold start 1-3 s. Tauri installer 2-10 MB, idle 30-50 MB, cold start 0.3-1 s. — [OpenReplay blog](https://blog.openreplay.com/comparing-electron-tauri-desktop-applications/)
- WPF UI (lepoco) is MIT with about 9.6k stars. It provides Fluent themes, navigation, new controls (NumberBox, Dialog, Snackbar), and "custom tray icon and menu built in pure WPF". — [lepoco/wpfui](https://github.com/lepoco/wpfui)
- WinUI 3 ships as part of the Windows App SDK (latest release notes: 1.8), runs on Windows 10 1809+, and is open source (microsoft-ui-xaml). — [Microsoft Learn: WinUI 3](https://learn.microsoft.com/en-us/windows/apps/winui/winui3/)
- WinUI 3 is MSIX-packaged by default. An unpackaged app "needs the Windows App SDK runtime installed with the app or bundled into it". WinUI has supported NativeAOT since WinAppSDK 1.6. Avalonia (MIT) is a plain .NET publish (self-contained possible), tested back to Windows 10 22H2. Both are MIT. *(Source is Avalonia's vendor comparison page and may be biased.)* — [Avalonia vs WinUI 3](https://avaloniaui.net/winui-compare)
- H.NotifyIcon.WinUI is the community NuGet package that adds a tray icon to WinUI 3. — [NuGet H.NotifyIcon.WinUI](https://www.nuget.org/packages/H.NotifyIcon.WinUI/2.5.0-dev.2)
- Vercel acquired Tremor on 2025-01-22. Tremor Blocks became free and MIT-licensed. — [Vercel blog](https://vercel.com/blog/vercel-acquires-tremor)
- Fleet's tray app (Fleet Desktop) authenticates using a random token from the agent, shared via a user-readable file and rotated hourly. — [Fleet: fleetd authentication](https://fleetdm.com/guides/fleetd-authentication)

### Inferences
- **Recommended tray app: Tauri 2.** It runs per-user, talks to the SYSTEM agent over a named pipe secured by an ACL (never over network ports), and stays UI-only with no privileges. It reuses the Rust types crate and the same React/shadcn design system as the web console, giving one visual language. It cross-compiles from Linux (NSIS), though the MSI must be built on a Windows runner.
- **Alternative if the team is .NET:** WPF + WPF-UI (MIT). It has the fastest path to a Fluent look with a tray, and builds on Linux with EnableWindowsTargeting (see section 7), but it needs the .NET runtime, or self-contained publishing at a larger size.
- WinUI 3 is not recommended for a small team because of the WinAppSDK runtime and MSIX friction, and because a tray icon needs a third-party package. Electron is not recommended because of its footprint on every employee machine.
- **Admin console:** Next.js (or Vite + React) + shadcn/ui (MIT) + Tremor/Recharts charts + TanStack Table for alert and event grids. Use a Go/Rust REST/gRPC-gateway API with OIDC SSO and RBAC.

### Gaps
- I found no rigorous measured footprint comparison (RAM/installer) of WinUI 3 vs WPF vs Avalonia vs Tauri on the same tray app.
- shadcn/ui's license (MIT) was not fetched this session.

## 6. Installer, code signing, auto-update

### Takeaway
Use WiX (v6, MS-RL, plus the OSMF fee for revenue-generating users of $10k+/year) on a Windows CI runner to build the agent MSI. **Azure Artifact Signing (formerly Trusted Signing) went GA in January 2026 and is now available to organizations in Singapore**, but individual developers must still be in the US or Canada, and there is no Indonesia support. An Indonesian-only entity would need a traditional OV/EV certificate from a CA.

### Cited Findings
- Trusted Signing was renamed **Azure Artifact Signing** and went GA in January 2026. Pricing: $9.99/month (5,000 signatures, 1 certificate profile) or $99.99/month (100,000 signatures, 10 profiles). Certificates are renewed daily, valid 24 h, and timestamped. No EV, with "no plans" to issue it. Works via signtool, GitHub Actions and Azure DevOps. — [DevClass, 2026-01-14](https://devclass.com/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/)
- **Current prerequisites (Microsoft Learn):** "Public Trust certificates are available to organizations in the United States, Canada, the European Union, the United Kingdom, Australia, New Zealand, Japan, South Korea, **Singapore**, Switzerland, Norway, and Israel. Individual developers must be located in the United States or Canada." — [Artifact Signing quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
- History: in April 2025 the preview was restricted to US/Canada organizations with 3+ years' history. On 2025-10-22 Microsoft said it had "no ETA" for other countries. — [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/2243504/trusted-signing-for-other-countries); in October 2025 it was opened to US/Canada individuals — [Electron docs commit](https://ayakael.net/mirrors/electron/commit/d1c2d06baebefda14fc1253b47a199435cb8baeb)
- SmartScreen reputation "builds automatically" with download history. Artifact Signing does not issue EV certificates. — [Artifact Signing FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq)
- WiX latest major is 6.0.0 (2025-04-07), licensed MS-RL. — [Wikipedia: WiX](https://en.wikipedia.org/wiki/WiX)
- The WiX Open Source Maintenance Fee "applies only to Users that use the Software as part of revenue-generating activities" with annual gross revenue of at least US$10,000. Non-payment "may result in suspending access to the Binary Release". — [WixToolset 7.0.0 license on NuGet](https://feed.nuget.org/packages/WixToolset.Versioning/7.0.0/License)
- WiX 7.0.0 packages exist on NuGet (WixToolset.Versioning 7.0.0). — [NuGet](https://feed.nuget.org/packages/WixToolset.Versioning/7.0.0/License)
- Fleet uses a TUF update server for fleetd updates, with custom root CA support. — [Fleet: fleetd authentication](https://fleetdm.com/guides/fleetd-authentication)

### Inferences
- For the user's context: a **Singapore-registered company** can use Artifact Signing for Public Trust certificates at $9.99/month, with signing done in GitHub Actions. An Indonesian entity or individual cannot (as of 2026-10), so would need a classic OV/EV certificate on an HSM or cloud KMS (e.g. DigiCert KeyLocker, SSL.com eSigner).
- A kernel or ELAM driver additionally requires Microsoft Hardware Dev Center attestation or WHQL signing with an EV certificate. Artifact Signing does not issue EV, so plan a separate EV certificate if drivers are ever in scope.
- **Auto-update recommendation:** a self-hosted, signed update manifest (TUF-style, like Fleet, or Ed25519-signed JSON), delivered over the existing gRPC channel, with staged rollout rings. The agent service verifies both Authenticode and the manifest signature before swapping binaries through a small updater service.
- Check whether WiX v7 is now the current major. NuGet shows 7.0.0 packages, while Wikipedia shows 6.0.0.

### Gaps
- I did not verify Artifact Signing's requirements for business history (the earlier "3+ years" rule) under GA.
- The latest WiX major version and its release date are not fully confirmed (v6 vs v7).

## 7. Building and testing Windows binaries from Linux CI

### Takeaway
Rust agent and Tauri NSIS builds cross-compile from Linux with `cargo-xwin` (MSVC target, Wine for tests). .NET WPF/WinForms projects build on Linux with `EnableWindowsTargeting=true`. However, MSI (WiX), Native AOT for Windows, real ETW integration tests and signing should run on GitHub-hosted `windows-2025` runners.

### Cited Findings
- cargo-xwin cross-compiles to Windows MSVC targets and downloads the CRT and SDK on demand. Using it means accepting Microsoft's license. C/C++ dependencies need clang. `cargo xwin test` runs tests under Wine, and a Docker image with Wine is available. — [PyPI cargo-xwin](https://pypi.org/project/cargo-xwin/0.14.8)
- Tauri lists cargo-xwin + LLVM/LLD + NSIS as the Linux cross-compile path. MSI must be built on Windows. — [Tauri Windows installer docs](https://v2.tauri.app/distribute/windows-installer/)
- `EnableWindowsTargeting` lets Windows-targeted TFMs (e.g. `net8.0-windows`) build on Linux and macOS, avoiding NETSDK1100. It can be set in Directory.Build.props. — [Microsoft Learn NETSDK1100](https://learn.microsoft.com/en-sg/dotnet/core/tools/sdk-errors/netsdk1100)
- Native AOT on Windows requires VS with "Desktop development with C++". Cross-OS AOT is not documented as supported. — [Microsoft Learn: Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)
- GitHub-hosted Windows runners: `windows-latest` = `windows-2025` (also `windows-2025-vs2026`), `windows-2022`, `windows-11-arm`. — [actions/runner-images](https://github.com/actions/runner-images)

### Inferences
- **CI layout:**
  - Linux jobs: fmt, clippy, unit tests, `cargo xwin build --target x86_64-pc-windows-msvc` for fast feedback, web console build, backend containers.
  - `windows-2025` jobs: release build, ETW integration tests (launch processes and assert events in an elevated runner), WiX MSI, Artifact Signing, Tauri MSI.
  - Optional: a self-hosted Windows VM with Atomic Red Team for detection regression tests.
- Prefer the MSVC target over GNU (`x86_64-pc-windows-gnu`) for the agent, for ABI parity with Windows SDK libraries and fewer MinGW runtime issues. This is a general-knowledge inference, not sourced.

### Gaps
- I did not verify whether GitHub-hosted Windows runners permit kernel ETW sessions (NT Kernel Logger) during tests. It is likely, since runners are admin, but unconfirmed.

## 8. Licensing pitfalls for reuse

### Takeaway
Safe to embed or reuse: Fibratus (Apache-2.0) code and rules, YARA-X and YARA (BSD-3), rsigma, sigma-rust and sigma-go (MIT), ferrisetw (MIT/Apache), tonic (MIT), ClickHouse (Apache-2.0), Tremor, WPF-UI and Avalonia (MIT), Fleet core (MIT). Use only as inspiration or as separate processes: Velociraptor (AGPL-3.0), Wazuh (GPLv2, with an AGPLv3 engine), golang-etw (GPL-3.0), RedEdr (GPL-3.0). SigmaHQ rules (DRL 1.1) are usable with attribution in match views. Elastic rules (ELv2) cannot be offered as a hosted or managed service.

### Cited Findings
- Velociraptor's license is the "GNU AFFERO GENERAL PUBLIC LICENSE Version 3". — [Velociraptor LICENSE](https://raw.githubusercontent.com/Velocidex/velociraptor/master/LICENSE)
- Wazuh is "Everything else is licensed under GPLv2". The engine (`src/engine/`) is AGPLv3+, and some shared modules are dual GPLv2/AGPLv3. — [wazuh/wazuh](https://github.com/wazuh/wazuh)
- Fibratus is Apache-2.0. — [Fibratus LICENSE.MD](https://raw.githubusercontent.com/rabbitstack/fibratus/master/LICENSE.MD)
- Elastic License 2.0 limitations: "You may not provide the software to third parties as a hosted or managed service". You also may not circumvent license-key functionality or remove notices. — [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license)
- elastic/detection-rules: rules and code are all under ELv2. — [elastic/detection-rules](https://github.com/elastic/detection-rules)
- DRL 1.1 allows commercial use, but the author must appear in match views. — [SigmaHQ DRL](https://github.com/SigmaHQ/Detection-Rule-License)
- TimescaleDB Community (TSL) restricts DBaaS use. — [Tiger Data licenses](https://www.tigerdata.com/legal/licenses)
- WiX: MS-RL plus the OSMF fee for revenue-generating users above $10k/year. — [Wikipedia: WiX](https://en.wikipedia.org/wiki/WiX); [WiX license](https://feed.nuget.org/packages/WixToolset.Versioning/7.0.0/License)
- golang-etw is GPL-3.0. — [0xrawsec/golang-etw](https://github.com/0xrawsec/golang-etw)

### Inferences
- If the EDR is sold as a SaaS or managed service (an MSSP model fits the user's consulting background), **do not ship Elastic rules**. Port detection ideas only, written in your own words.
- Embedding or modifying AGPL Velociraptor code inside a network-served backend would trigger source disclosure. Running an unmodified Velociraptor as a separate DFIR add-on is a common and lower-risk pattern, but get legal review.
- Keep a `THIRD_PARTY_NOTICES` file generated by `cargo-about` / `cargo-deny` (Rust) and license-checker (JS). Enforce a deny-list (GPL/AGPL/ELv2/SSPL) in CI.

### Gaps
- I did not obtain a legal opinion. The SSPL/BUSL status of other candidate components (e.g. Redis 7.4+ licensing) was not researched this session.
