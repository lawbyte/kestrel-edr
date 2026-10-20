# Building Kestrel

| Component | Where it builds | Output |
|---|---|---|
| `kestrel-server` | Linux (or any OS), Docker | `target/*/kestrel-server`, `kestrel-server` image |
| `kestrel-agent` | Windows (native, MSVC) for real use; Linux/macOS for the simulator; Linux → Windows cross-check | `kestrel-agent(.exe)` |
| console | Node 22 | `console/dist` (served by the server via `CONSOLE_DIR`) |
| tray | Windows (Tauri 2); its UI builds anywhere | `kestrel-tray.exe` |
| MSI | Windows, WiX v6 | `KestrelAgent.msi` |

The toolchain is **stable** Rust ≥ 1.96 (`rust-version` in `Cargo.toml`), plus Node 22 for the console and tray.

## Linux development

```bash
# prerequisites (Debian/Ubuntu)
sudo apt install build-essential pkg-config protobuf-compiler postgresql jq curl openssl
#   protoc: kestrel-server's build.rs uses the system protoc (kestrel-agent vendors its own)

cargo build -p kestrel-server -p kestrel-agent
cargo test --workspace            # server tests need DATABASE_URL (a Postgres where the user may CREATE DATABASE)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

cd console && npm ci && npm run build && npm test     # → console/dist
cd tray && npm ci && npm run build && npm test        # tray UI only (the Tauri shell needs Windows)
```

You don't need a Windows machine to run the product locally. `scripts/e2e.sh` builds the server and agent, starts a temporary PostgreSQL cluster, runs the server on ports 18443 (HTTPS) and 18444 (gRPC), and enrolls three simulated endpoints that replay recorded attacks. It then checks the results through the REST API.

```bash
./scripts/e2e.sh                     # PASS/FAIL summary
E2E_KEEP=1 ./scripts/e2e.sh          # leave the server running; log in with the printed credentials
E2E_KEEP=1 E2E_INFO_FILE=/tmp/e2e.json ./scripts/e2e.sh &
E2E_INFO_FILE=/tmp/e2e.json node console/scripts/screenshots-real.mjs   # docs/screenshots/real-*.png
```

The script takes these environment variables:

| Variable | Effect |
|---|---|
| `DATABASE_URL` | Use an existing Postgres server (CI service). A throwaway database is created on it and dropped afterwards. |
| `PG_BIN` | Where the PostgreSQL binaries are, if not `/usr/lib/postgresql/*/bin`. |
| `E2E_SKIP_BUILD=1` | Don't rebuild the binaries. |
| `E2E_SKIP_CONSOLE=1` | Don't build the console. |
| `E2E_HTTPS_PORT`, `E2E_GRPC_PORT` | Change the ports. |
| `E2E_KEEP_LOGS=1` | Keep the work directory after a failed run. |
| `CARGO_TARGET_DIR` | Honoured. |

To run the server by hand outside Docker, set these variables:

* `DATABASE_URL`
* `KESTREL_MASTER_KEY`, which must be at least 16 characters
* `KESTREL_PUBLIC_HOSTNAME`
* `KESTREL_HTTPS_ADDR` and `KESTREL_GRPC_ADDR` (bind addresses; defaults `0.0.0.0:443` and `0.0.0.0:8443`)
* `KESTREL_GRPC_PUBLIC_PORT`
* `CONSOLE_DIR`
* `AGENT_DIR` (MSI downloads)
* `CLICKHOUSE_URL` (optional; leave it unset to store events in Postgres)

To run a simulated agent against it:

```bash
cargo run -p kestrel-agent -- --state-dir ./simstate simulate \
  --server 127.0.0.1:18444 --server-name localhost --ca ca.pem --token kst_enr_… \
  --replay crates/kestrel-agent/replays/lumma_clickfix.jsonl --exit-after-replay 10
```

Get `ca.pem` from the `ca_pem` field of `GET /api/agent/installer`. The `--server-name` value must be one of the names in `KESTREL_PUBLIC_HOSTNAME`.

## Cross-checking the Windows code from Linux

`kestrel-win` and the Windows paths of `kestrel-agent` only compile for Windows. To catch type errors without a Windows box, cross-compile to `x86_64-pc-windows-gnu` with the aliases in `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"

[alias]
win      = "build -Zbuild-std=std,panic_abort --target x86_64-pc-windows-gnu"
wincheck = "check -Zbuild-std=std,panic_abort --target x86_64-pc-windows-gnu"
```

`-Zbuild-std` builds the Windows standard library from the `rust-src` component, so you don't need `rustup target add` (which may be unavailable offline). It is an unstable flag, so on stable Rust set `RUSTC_BOOTSTRAP=1`:

```bash
rustup component add rust-src                      # if $(rustc --print sysroot)/lib/rustlib/src is missing
sudo apt install gcc-mingw-w64-x86-64              # linker + C compiler for ring, zstd, sqlite, yara-x deps
RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=target-win cargo wincheck -p kestrel-agent   # type-check (fast)
RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=target-win cargo win -p kestrel-agent --release   # link a .exe (GNU ABI)
```

Notes:

* Use a separate `CARGO_TARGET_DIR`. Build-std artefacts are large, and keeping them apart avoids rebuilding the host target.
* `kestrel-agent` forces `indexmap` 1.x's `std` feature, because its autodetection probe fails under build-std.
* The GNU-ABI `.exe` is fine for smoke tests. **Release builds are made natively with MSVC on Windows**, as CI does.
* The tray app has its own workspace: `cd tray/src-tauri && RUSTC_BOOTSTRAP=1 cargo check -Zbuild-std=std,panic_abort --target x86_64-pc-windows-gnu`.

## Native Windows builds

You need:

* Windows 10/11 or Server 2019+, x64
* Visual Studio 2022 Build Tools with "Desktop development with C++"
* Rust stable with the MSVC toolchain
* Node 22
* `protoc` (`choco install protoc`) for the server proto build, if you build the whole workspace

```powershell
cargo test -p kestrel-common -p kestrel-detect -p kestrel-win -p kestrel-agent
$env:KESTREL_UPDATE_PUBKEY = '<base64 Ed25519 public key>'   # optional: enables signed auto-update
cargo build -p kestrel-agent --release                       # target\release\kestrel-agent.exe

# ETW smoke test (elevated shell): sensors only, no server
.\scripts\windows-smoke.ps1

# Tray app
cd tray; npm ci; npm run tauri build -- --no-bundle         # tray\src-tauri\target\release\kestrel-tray.exe
```

`scripts/windows-smoke.ps1` runs these checks:

1. `kestrel-agent.exe --version` works.
2. It starts the hidden `kestrel-agent sensors-test --seconds N` subcommand, which runs only `WindowsPlatform::start_sensors` and prints JSON counts by event kind and sensor stats.
3. While the sensors run, it executes `cmd /c echo hi` and `Resolve-DnsName example.com`.
4. It asserts that at least one `process_start` and at least one `dns_query` were observed, and that `etw_ok` is true.

It needs an elevated shell. Stop a running `KestrelAgent` service first, because the ETW session names (`Kestrel-Core`, `Kestrel-IO`, `Kestrel-ProcCmd`) are shared.

The agent embeds no update key unless `KESTREL_UPDATE_PUBKEY` is set at build time. Without the key, update manifests from the server are refused.

## MSI (WiX v6)

```powershell
dotnet tool install --global wix --version 6.*
wix extension add -g WixToolset.Util.wixext/6
$v = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages |
     Where-Object name -eq 'kestrel-agent' | Select-Object -ExpandProperty version
wix build installer/Kestrel.wxs -arch x64 -d Version=$v `
  -d AgentExe=target/release/kestrel-agent.exe -d ScanExe=target/release/kestrel-scan.exe `
  -d TrayExe=tray/src-tauri/target/release/kestrel-tray.exe `
  -ext WixToolset.Util.wixext -o KestrelAgent.msi
```

The MSI is per-machine and does the following:

* installs both executables to `C:\Program Files\Kestrel`
* creates `C:\ProgramData\Kestrel` with a SYSTEM + Administrators ACL
* adds the tray to `HKLM\…\Run`
* runs `kestrel-agent install --server [SERVER] --ca [CA_B64] --token [TOKEN]` as a deferred, elevated custom action. This command verifies the state directory, enrolls the device (the server issues the per-device uninstall token; only its hash is stored) and registers the service.

On uninstall, it runs `kestrel-agent uninstall --token [UNINSTALL_TOKEN]`, which fails without the right token (reveal it on the console's device page). `TOKEN`, `CA_B64`, `UNINSTALL_TOKEN` and the deferred custom-action data are hidden properties, so they never appear in the MSI log.

To publish the MSI, put `KestrelAgent.msi` (and optionally a `VERSION` file) in `deploy/installers/`. The server serves it at `/downloads/KestrelAgent.msi` and reports its SHA-256 in `GET /api/agent/installer`.

## Code signing (Azure Artifact Signing)

Kestrel is signed with **Azure Artifact Signing**, formerly Trusted Signing. You need an Artifact Signing account, a certificate profile (Public Trust) and an app registration with the *Artifact Signing Certificate Profile Signer* role.

**Order matters.** Sign `kestrel-agent.exe` and `kestrel-tray.exe` **before** building the MSI, because the MSI embeds the files as they are at build time. Then sign the MSI itself.

Locally, with SignTool and the Artifact Signing dlib (from the `Microsoft.ArtifactSigning.Client` / Trusted Signing client tools):

```powershell
# metadata.json
# { "Endpoint": "https://<region>.codesigning.azure.net", "CodeSigningAccountName": "<account>", "CertificateProfileName": "<profile>" }
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
  /dlib "<path>\Azure.CodeSigning.Dlib.dll" /dmdf metadata.json `
  target\release\kestrel-agent.exe tray\src-tauri\target\release\kestrel-tray.exe
# ...build the MSI, then:
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
  /dlib "<path>\Azure.CodeSigning.Dlib.dll" /dmdf metadata.json KestrelAgent.msi
```

In CI (`.github/workflows/ci.yml`), signing uses `azure/trusted-signing-action`. It runs on pushes when these secrets are set: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `ARTIFACT_SIGNING_ENDPOINT`, `ARTIFACT_SIGNING_ACCOUNT` and `ARTIFACT_SIGNING_PROFILE`. The workflow currently signs once, after the MSI is built, so the exes inside the MSI are unsigned. Split it into two signing steps as described above, or the installed binaries will not be signed.

Signing matters for an EDR. Defender SmartScreen, AppLocker publisher rules and Kestrel's own `signer` checks all trust a signature. Customers will also exclude your agent by signer.

## Server image

```bash
docker build -f deploy/Dockerfile -t kestrel-server:local .     # add --build-arg BUILD_CONSOLE=0 for an API-only image
```
