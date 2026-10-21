# Quick start

This page gets a server running, enrolls one **test** Windows machine and shows it online in the console. It takes about 30 minutes once you have an MSI.

::: danger Use a disposable test machine
The agent kills processes, quarantines files, installs firewall (WFP) filters that can cut network access, changes AppLocker and plants decoy files in user profiles. Install it only on a test VM you can throw away, not on your own workstation. See [Testing safely](./testing).
:::

## What you need

* A Linux host or a Windows PC with Docker Desktop, reachable from the test machine on TCP 443 and 8443.
* A DNS name or IP address for the server that the test machine can reach.
* A Windows 10 or 11 (64-bit) test VM.
* `KestrelAgent.msi`. Build it with [Build from source](../build/), or take it from the `kestrel-windows` artifact of the Windows CI job.

## 1. Start the server

On Linux:

```bash
git clone <your-kestrel-repo> kestrel && cd kestrel/deploy
cp .env.example .env
sed -i "s|^KESTREL_MASTER_KEY=.*|KESTREL_MASTER_KEY=$(openssl rand -base64 32)|" .env
$EDITOR .env        # KESTREL_PUBLIC_HOSTNAME, POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD
```

On Windows (PowerShell, Docker Desktop running), generate the master key with .NET and paste it into `.env`:

```powershell
cd kestrel\deploy
Copy-Item .env.example .env
$b = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b)      # paste as KESTREL_MASTER_KEY=... in .env
notepad .env                       # also set KESTREL_PUBLIC_HOSTNAME, POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD
```

In `.env`, set at least:

| Variable | Value |
|---|---|
| `KESTREL_MASTER_KEY` | The random base64 key you generated. Back it up separately from the database. |
| `KESTREL_PUBLIC_HOSTNAME` | The name or IP the test machine uses to reach the server. The **first** name in the list is the one installers use. |
| `POSTGRES_PASSWORD`, `CLICKHOUSE_PASSWORD` | Long random values. |

Copy the MSI into `deploy/installers/` so the server can serve it and generate installer scripts:

```bash
cp /path/to/KestrelAgent.msi installers/
```

Start the stack and check it:

```bash
docker compose up -d --build
docker compose ps                                    # all services "healthy"
curl -k https://localhost/api/healthz
```

The first build compiles the server and the console inside Docker and takes several minutes.

## 2. First-run setup

1. Get the one-time setup code from the server log:

   ```bash
   docker compose logs kestrel-server | grep "SETUP CODE"
   ```

   In PowerShell use `docker compose logs kestrel-server | Select-String "SETUP CODE"`. You can also set your own code with `KESTREL_SETUP_CODE` in `.env` before the first start.
2. Open `https://<KESTREL_PUBLIC_HOSTNAME>/`. The certificate is self-signed until you install your own (see [TLS](../deploy/server#tls)).
3. Enter the setup code, the organisation name and the first administrator account.

## 3. Create an installer

1. In the console, open **Devices** and click **Install agent**.
2. Choose a remote-access profile. For a first test keep **No remote access**.
3. Pick the device group, how many days the token is valid (1 to 90) and the maximum number of devices (1 to 10,000).
4. Click through to **Installer ready**. Download `Install-Kestrel-none.cmd`, or copy the PowerShell one-liner. The token is shown only once.

## 4. Install on the test machine

Because the binaries are not signed yet, add a Defender exclusion on the **test VM** first, in an administrator PowerShell:

```powershell
Add-MpPreference -ExclusionPath 'C:\Program Files\Kestrel'
```

Then copy `Install-Kestrel-none.cmd` to the VM and double-click it. It asks for administrator rights, downloads the MSI from your server, checks the MSI's SHA-256 and runs `msiexec` silently.

Check the result in an administrator PowerShell:

```powershell
Get-Service KestrelAgent                                  # Running
& 'C:\Program Files\Kestrel\kestrel-agent.exe' status     # JSON health from the running agent
```

## 5. See it online

Open **Devices** in the console. The test machine appears within seconds. Open it to see sensor health (ETW, events lost, DPAPI audit channel, AMSI, outbox). The tray icon appears for the user at the next sign-in.

To see a detection without real malware, follow the benign emulations in [Testing safely](./testing).

## Next steps

* Production setup (TLS, backups, sizing): [Deploy the server](../deploy/server).
* Mass deployment, uninstall and upgrades: [Enroll devices](../deploy/enroll).
* Rollout advice: leave the default rule modes, keep everything else in Audit for about two weeks, then move rules to Protect one by one. See [Detection rules](../reference/rules#rollout-advice).
