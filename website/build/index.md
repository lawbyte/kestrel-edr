# Build from source (Windows)

This page builds every Kestrel component on a Windows host, from a clean machine to a signed MSI and a server image. It follows what CI does (`.github/workflows/ci.yml`).

| Component | Builds on | Output |
|---|---|---|
| Agent `kestrel-agent` | Windows (MSVC) | `target\release\kestrel-agent.exe` |
| Scanner `kestrel-scan` | Windows (MSVC) | `target\release\kestrel-scan.exe` |
| MSI custom actions `kestrel-msica` | Windows (MSVC) | `target\release\kestrel_msica.dll` |
| Tray app | Windows (Tauri 2) | `tray\src-tauri\target\release\kestrel-tray.exe` |
| MSI | Windows, WiX v6 | `KestrelAgent.msi` |
| Console | Node 22, any OS | `console\dist` (served by the server) |
| Server | Linux or Docker (any OS) | `kestrel-server` binary or Docker image |

::: warning Build and test only on your workstation
Building, running unit tests, running the server in Docker, the console in mock mode and the read-only ETW smoke test are safe on a daily-use PC. Installing the MSI or the service, running `kestrel-agent run` or `install`, and any containment action belong in a disposable VM. See [Testing safely](../guide/testing).
:::

## 1. Prerequisites

Use an administrator PowerShell for the installs. Some need a new shell afterwards so that `PATH` is refreshed.

| Tool | Version | Install | Check |
|---|---|---|---|
| Windows | 10 or 11, or Server 2019+, x64 | | |
| Git | any recent | `winget install Git.Git` | `git --version` |
| Rust (MSVC toolchain) | stable, 1.96 or newer (`rust-version` in `Cargo.toml`) | `winget install Rustlang.Rustup` | `rustc --version` |
| Visual Studio 2022 Build Tools | "Desktop development with C++" workload | see below | `cl` in a Developer PowerShell |
| protoc | any recent (CI uses the Chocolatey package) | `winget install Google.Protobuf` or `choco install protoc` | `protoc --version` |
| Node.js | 22 (what CI uses) | installer from nodejs.org | `node --version` |
| .NET SDK | 8 | `winget install Microsoft.DotNet.SDK.8` | `dotnet --version` |
| WiX Toolset | 6.0.2 | `dotnet tool install --global wix --version 6.0.2` | `wix --version` |
| Docker Desktop | any recent | `winget install Docker.DockerDesktop` | `docker --version` |
| WSL2 (optional) | | `wsl --install` (needs a reboot) | `wsl -l -v` |

Set the Rust MSVC toolchain as the default:

```powershell
rustup default stable-x86_64-pc-windows-msvc
rustup component add clippy rustfmt
```

Install the Visual Studio Build Tools with the C++ workload:

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Add the WiX Util extension (once per machine; keep its version equal to the WiX tool version):

```powershell
wix extension add -g WixToolset.Util.wixext/6.0.2
```

If `protoc` is not on `PATH` (for example after a manual unzip), point the build at it:

```powershell
$env:PROTOC = 'C:\tools\protoc\bin\protoc.exe'
```

`protoc` is needed by `kestrel-server`'s build script, so any workspace-wide command (`cargo clippy --workspace`, `cargo test --workspace`) needs it. The agent vendors its own copy.

The release build was last verified with rustc 1.99.1, Node 24, libprotoc 36.0, .NET 8 and WiX 6.0.2.

### Disk space

Rust `target` folders grow by many gigabytes (a release build with thin LTO, the tray's own workspace, per-tool target folders). Check free space before a release build and remove stale target folders with `cargo clean` (and `cargo clean` inside `tray\src-tauri`).

### Microsoft Defender and build folders

Defender can flag or lock freshly built, unsigned agent binaries (it detects the unsigned agent heuristically because of its credential-store path tables). If builds fail with access denied or files vanish from `target`, add an exclusion for the build output folders only, never for the whole drive:

```powershell
Add-MpPreference -ExclusionPath 'D:\src\kestrel\target', 'D:\src\kestrel\tray\src-tauri\target'
```

Do not disable Defender, SmartScreen or the firewall.

## 2. Clone

```powershell
git clone https://github.com/lawbyte/kestrel-edr.git
cd kestrel-edr
```

## 3. Rust: format, lint and test

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p kestrel-common -p kestrel-detect -p kestrel-platform -p kestrel-win -p kestrel-agent -p kestrel-scan
```

The server's integration tests need a PostgreSQL server where the user may create databases. They are skipped when `DATABASE_URL` is unset:

```powershell
docker run -d --name kestrel-pg -e POSTGRES_USER=kestrel -e POSTGRES_PASSWORD=kestrel -p 5432:5432 postgres:16-alpine
$env:DATABASE_URL = 'postgres://kestrel:kestrel@localhost:5432/postgres'
cargo test -p kestrel-server
```

Set `KESTREL_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123` as well to test the ClickHouse path.

## 4. Release build of the agent, scanner and custom-action DLL

```powershell
cargo build -p kestrel-agent -p kestrel-scan -p kestrel-msica --release
```

This produces:

* `target\release\kestrel-agent.exe`
* `target\release\kestrel-scan.exe` (YARA-X, kept out of the always-running agent)
* `target\release\kestrel_msica.dll` (MSI custom actions; passes enrollment and uninstall tokens to the agent on stdin, never on a command line)

Optional build-time settings (read when the agent is compiled, not at run time):

| Variable | Effect |
|---|---|
| `KESTREL_UPDATE_PUBKEY` | Base64 Ed25519 public key for signed agent updates. Without it, agents refuse every update manifest. See [Agent updates](../console/updates). |
| `KESTREL_UPDATE_REQUIRE_SIGNED` | Part of the required Authenticode signer's subject (for example your company name). Update MSIs must then also carry a valid Authenticode signature from that signer. |

```powershell
$env:KESTREL_UPDATE_PUBKEY = Get-Content D:\kestrel-signing\kestrel-update-signing.pub
cargo build -p kestrel-agent -p kestrel-scan -p kestrel-msica --release
```

**Static CRT.** `.cargo/config.toml` links the C runtime statically for the `x86_64-pc-windows-msvc` target (`-C target-feature=+crt-static`). A clean Windows has no `VCRUNTIME140.dll`, and the agent must start without extra installs. Do not remove this setting.

The release profile strips symbols and uses thin LTO with one codegen unit, so release builds are slow. The agent is about 19 MB and the scanner about 18 MB.

### Read-only ETW smoke test (optional)

In an **elevated** PowerShell this starts only the sensors for a few seconds (no server, no detection, no response) and checks that process and DNS events arrive:

```powershell
.\scripts\windows-smoke.ps1
```

It runs `kestrel-agent sensors-test --seconds N`, starts `cmd /c echo hi` and `Resolve-DnsName example.com`, and checks that at least one `process_start` and one `dns_query` were seen and that ETW is healthy. If a `KestrelAgent` service is installed on the machine, stop it first, because the ETW session names are shared.

## 5. Console

```powershell
cd console
npm ci
npm run build      # console\dist
npm test
npm run lint
cd ..
```

The server serves `console\dist` (Docker images include it unless `BUILD_CONSOLE=0`). For UI work, `npm run dev` proxies `/api` to a running server, and `npm run dev:mock` runs the console on mock data without a server (its script uses POSIX environment syntax, so run it from WSL or Git Bash).

## 6. Tray app

```powershell
cd tray
npm ci
npm run build
npm test
npm run tauri build
cd ..
```

`npm run tauri build` builds the Tauri shell and also produces Tauri's own MSI and NSIS bundles, which Kestrel does not use. To build only the executable that goes into the Kestrel MSI, as CI does:

```powershell
cd tray
npm run tauri build -- --no-bundle     # tray\src-tauri\target\release\kestrel-tray.exe
```

The tray has its own Cargo workspace in `tray\src-tauri`. Run its Rust checks there:

```powershell
cd tray\src-tauri
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 7. MSI (WiX v6)

Sign the executables first if you sign at all (see [Code signing](#code-signing)): the MSI embeds the files as they are when it is built.

```powershell
$v = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages |
     Where-Object name -eq 'kestrel-agent' | Select-Object -ExpandProperty version
wix build installer/Kestrel.wxs -arch x64 -d Version=$v `
  -d AgentExe=target/release/kestrel-agent.exe `
  -d ScanExe=target/release/kestrel-scan.exe `
  -d CaDll=target/release/kestrel_msica.dll `
  -d TrayExe=tray/src-tauri/target/release/kestrel-tray.exe `
  -ext WixToolset.Util.wixext -o KestrelAgent.msi
```

All five `-d` variables are required by `installer/Kestrel.wxs`:

| Variable | Value |
|---|---|
| `Version` | Agent version, taken from the workspace `version` in `Cargo.toml`. Agents report this version, and updates compare against it. |
| `AgentExe` | Path to `kestrel-agent.exe` |
| `ScanExe` | Path to `kestrel-scan.exe` |
| `CaDll` | Path to `kestrel_msica.dll` |
| `TrayExe` | Path to `kestrel-tray.exe` |

The MSI is per-machine (about 14 MB). It installs the three files into `C:\Program Files\Kestrel`, creates `C:\ProgramData\Kestrel` with a SYSTEM and Administrators only ACL, adds the tray to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, and on a fresh install enrolls the device and registers the `KestrelAgent` service through a deferred custom action. How to install it is described in [Enroll devices](../deploy/enroll).

To publish it, copy it to `deploy\installers\` on the server (optionally with a `VERSION` file):

```powershell
Copy-Item KestrelAgent.msi deploy\installers\
```

## 8. Server image

With Docker Desktop running, build and start the full stack from `deploy\` (see [Deploy the server](../deploy/server) for `.env`):

```powershell
cd deploy
docker compose up -d --build
```

Or build only the image:

```powershell
docker build -f deploy/Dockerfile -t kestrel-server:local .
# API only, without the console:
docker build -f deploy/Dockerfile --build-arg BUILD_CONSOLE=0 -t kestrel-server:local .
```

## 9. Linux and WSL2 builds, end-to-end test

The server builds natively on Linux, and the agent core runs there in simulator mode. On Debian, Ubuntu or a WSL2 distro:

```bash
sudo apt install build-essential pkg-config protobuf-compiler postgresql jq curl openssl
cargo build -p kestrel-server -p kestrel-agent
cargo test --workspace            # server tests need DATABASE_URL
```

From WSL the repository is reachable under `/mnt/<drive>/...`. Builds on the Windows filesystem are slow; use a target folder on the Linux filesystem:

```bash
export CARGO_TARGET_DIR=$HOME/kestrel-target
```

`scripts/e2e.sh` builds the server and the agent, starts a temporary PostgreSQL cluster (or uses `DATABASE_URL`), runs the server on ports 18443 (HTTPS) and 18444 (gRPC), and enrolls simulated endpoints that replay recorded attacks (Lumma ClickFix, Vidar smash-and-grab, a benign workday). It then checks devices, incidents, priorities, data at risk, storyline, process tree, checklist, an offline-queued response action, the audit hash chain, a hunt query and remote access through the REST API.

```bash
./scripts/e2e.sh                     # PASS/FAIL summary
E2E_KEEP=1 ./scripts/e2e.sh          # leave the server running at https://127.0.0.1:18443 and print login details
```

| Variable | Effect |
|---|---|
| `DATABASE_URL` | Use an existing PostgreSQL server; a throwaway database is created and dropped. |
| `PG_BIN` | PostgreSQL binaries for the temporary cluster, if not under `/usr/lib/postgresql/*/bin`. |
| `E2E_SKIP_BUILD=1` | Use already built binaries. |
| `E2E_SKIP_CONSOLE=1` | Do not build the console. |
| `E2E_KEEP=1` | Leave the server running after the checks. |
| `E2E_HTTPS_PORT`, `E2E_GRPC_PORT` | Change the ports (defaults 18443 and 18444). |
| `CARGO_TARGET_DIR` | Honoured; binaries are taken from `$CARGO_TARGET_DIR/debug`. |

To type-check the Windows code from Linux without a Windows machine, the repository has `cargo wincheck` and `cargo win` aliases that cross-compile to `x86_64-pc-windows-gnu` with `-Zbuild-std` (needs `rust-src`, `gcc-mingw-w64-x86-64` and `RUSTC_BOOTSTRAP=1`):

```bash
RUSTC_BOOTSTRAP=1 CARGO_TARGET_DIR=target-win cargo wincheck -p kestrel-agent
```

The GNU-ABI build is for checks only. Release builds are made natively with MSVC on Windows.

## Code signing

Sign before you deploy. Defender SmartScreen, AppLocker publisher rules and Kestrel's own signer checks all trust a signature, and customers will exclude the agent by signer. Kestrel is set up for **Azure Artifact Signing** (formerly Trusted Signing). You need an Artifact Signing account, a certificate profile (Public Trust) and an app registration with the *Artifact Signing Certificate Profile Signer* role.

Order matters:

1. Sign `kestrel-agent.exe`, `kestrel-scan.exe`, `kestrel_msica.dll` and `kestrel-tray.exe`.
2. Build the MSI from the signed files.
3. Sign the MSI.

Locally, with SignTool and the Artifact Signing dlib:

```powershell
# metadata.json:
# { "Endpoint": "https://<region>.codesigning.azure.net", "CodeSigningAccountName": "<account>", "CertificateProfileName": "<profile>" }
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
  /dlib "<path>\Azure.CodeSigning.Dlib.dll" /dmdf metadata.json `
  target\release\kestrel-agent.exe target\release\kestrel-scan.exe target\release\kestrel_msica.dll `
  tray\src-tauri\target\release\kestrel-tray.exe
# build the MSI, then:
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
  /dlib "<path>\Azure.CodeSigning.Dlib.dll" /dmdf metadata.json KestrelAgent.msi
```

In CI, signing uses `azure/trusted-signing-action` on pushes when these repository secrets are set: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `ARTIFACT_SIGNING_ENDPOINT`, `ARTIFACT_SIGNING_ACCOUNT`, `ARTIFACT_SIGNING_PROFILE`. The workflow signs the executables before packaging and the MSI afterwards.

After signing, submit the signed binaries to Microsoft as a false positive (Microsoft Security Intelligence file submission) so that Defender stops flagging the agent.

Agent **update** signing (Ed25519) is separate from Authenticode; see [Agent updates](../console/updates).

## Verification checklist

| Check | Command | Expected |
|---|---|---|
| Formatting | `cargo fmt --all -- --check` | no output, exit 0 |
| Lints | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Unit tests | `cargo test -p kestrel-common -p kestrel-detect -p kestrel-platform -p kestrel-win -p kestrel-agent -p kestrel-scan` | 0 failed |
| Server tests | `cargo test -p kestrel-server` with `DATABASE_URL` set | 0 failed |
| Release binaries | `cargo build -p kestrel-agent -p kestrel-scan -p kestrel-msica --release` | three files in `target\release` |
| Agent version | `target\release\kestrel-agent.exe --version` | prints the workspace version |
| ETW smoke test | `.\scripts\windows-smoke.ps1` (elevated) | PASS lines, exit 0 |
| Console | `npm ci; npm run build; npm test; npm run lint` in `console` | all pass |
| Tray | `npm ci; npm run build; npm test; npm run tauri build -- --no-bundle` in `tray` | `kestrel-tray.exe` built |
| MSI | `wix build ...` (step 7) | `KestrelAgent.msi` |
| Signatures | `Get-AuthenticodeSignature .\KestrelAgent.msi` | `Valid` (once signed) |
| Server image | `docker compose up -d --build` in `deploy` | all services healthy, `/api/healthz` answers |
| End to end | `./scripts/e2e.sh` in Linux or WSL2 | all checks PASS |
| Licences | `cargo install cargo-deny --locked`, then `cargo deny check licenses` | no copyleft dependencies |
