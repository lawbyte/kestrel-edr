//! Per-profile installer script (`Install-Kestrel-<preset>.cmd`) returned once
//! when an enrollment token is created.
//!
//! WiX does not run on the Linux server, so instead of one MSI per
//! remote-access profile the server generates a small batch file (CRLF, inline
//! PowerShell, no external dependencies) that downloads the one signed MSI,
//! verifies its SHA-256 (embedded here at generation time) and runs
//! `msiexec /i … /qn SERVER= TOKEN= CA_B64=` — the same properties as
//! `groups::install_command`. The profile itself is bound to the token
//! server-side; the script only carries the token.
//!
//! Injection safety: every value written into the script is checked against a
//! strict character allow-list first (no `%`, `^`, `&`, `|`, `<`, `>`, `"`,
//! quotes or line breaks). The PowerShell part is passed as `-EncodedCommand`
//! (UTF-16LE base64) and reads the values from environment variables, so no
//! value is ever spliced into PowerShell source.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// Inputs of [`render`]. Every field is validated by [`render`].
pub struct ScriptParams<'a> {
    /// `host:port` the agent connects to.
    pub server_addr: &'a str,
    /// Full enrollment token (`kte_…`).
    pub token: &'a str,
    /// First characters of the token (header comment).
    pub token_prefix: &'a str,
    /// Expiry, ms since epoch.
    pub expires_at: i64,
    /// Agent CA PEM (passed to the MSI base64-encoded as `CA_B64`).
    pub ca_pem: &'a str,
    /// `https://…/KestrelAgent.msi`.
    pub msi_url: &'a str,
    /// SHA-256 (hex) of that MSI.
    pub msi_sha256: &'a str,
    /// `RemoteAccessProfile::summary()`.
    pub profile_summary: &'a str,
}

fn all(s: &str, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.chars().all(ok)
}

fn check(name: &str, v: &str, ok: impl Fn(char) -> bool) -> Result<(), String> {
    if all(v, ok) && v.len() <= 4096 {
        Ok(())
    } else {
        Err(format!(
            "{name} contains characters that cannot be placed in the installer script"
        ))
    }
}

/// Comment-safe copy of free text (letters, digits, a few punctuation marks).
fn comment_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " ,.()+-:/".contains(c) {
                c
            } else {
                ' '
            }
        })
        .take(300)
        .collect()
}

/// UTF-16LE base64 for `powershell -EncodedCommand`.
pub fn encode_ps(script: &str) -> String {
    let bytes: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    B64.encode(bytes)
}

/// The PowerShell part (reads `KESTREL_*` environment variables).
pub const PS_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $dir = Join-Path $env:ProgramData ('KestrelSetup-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $dir | Out-Null
  # Only SYSTEM and Administrators may touch the download (inheritance
  # removed), so no other user can swap the package.
  & (Join-Path $env:SystemRoot 'System32\icacls.exe') $dir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'could not restrict access to the download folder' }
  $msi = Join-Path $dir 'KestrelAgent.msi'
  $log = Join-Path $dir 'install.log'
  Write-Host ('Downloading ' + $env:KESTREL_MSI_URL)
  try {
    Invoke-WebRequest -UseBasicParsing -Uri $env:KESTREL_MSI_URL -OutFile $msi
  } catch [System.Net.WebException] {
    if ($_.Exception.Status -ne [System.Net.WebExceptionStatus]::TrustFailure) { throw }
    # The console may use a self-signed certificate. The package is pinned by
    # the SHA-256 below, so download it without certificate validation.
    Write-Host 'The server certificate is not trusted by Windows; relying on the SHA-256 check.'
    # A compiled callback: .NET invokes it on a worker thread, where a
    # PowerShell scriptblock fails with "There is no Runspace available".
    Add-Type -TypeDefinition 'public static class KestrelSetupTrust { public static bool AcceptAll(object s, System.Security.Cryptography.X509Certificates.X509Certificate c, System.Security.Cryptography.X509Certificates.X509Chain ch, System.Net.Security.SslPolicyErrors e) { return true; } }'
    [Net.ServicePointManager]::ServerCertificateValidationCallback = [System.Delegate]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback], [KestrelSetupTrust].GetMethod('AcceptAll'))
    Invoke-WebRequest -UseBasicParsing -Uri $env:KESTREL_MSI_URL -OutFile $msi
    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
  }
  # Hash through a handle that lets others read but never write or delete
  # the file; it stays open until msiexec has finished with the package.
  $fs = [System.IO.File]::Open($msi, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = ([System.BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '').ToLowerInvariant()
    if ($hash -ne $env:KESTREL_MSI_SHA256) {
      $fs.Dispose()
      Remove-Item -LiteralPath $msi -Force
      Write-Host ('SHA-256 mismatch (expected ' + $env:KESTREL_MSI_SHA256 + ', got ' + $hash + '). Nothing was installed.')
      exit 3
    }
    $msiArgs = @('/i', ('"' + $msi + '"'), '/qn', ('SERVER=' + $env:KESTREL_SERVER), ('TOKEN=' + $env:KESTREL_TOKEN), ('CA_B64=' + $env:KESTREL_CA_B64), '/l*v', ('"' + $log + '"'))
    Write-Host 'Running the Kestrel EDR installer (this can take a minute)...'
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $msiArgs -Wait -PassThru
  } finally {
    $fs.Dispose()
  }
  $code = $p.ExitCode
  if ($code -eq 0) { Write-Host 'Kestrel EDR agent installed.' }
  elseif ($code -eq 3010 -or $code -eq 1641) { Write-Host 'Kestrel EDR agent installed; Windows needs a restart to finish.' }
  else { Write-Host ('msiexec failed with exit code ' + $code + '. Log: ' + $log) }
  exit $code
} catch {
  Write-Host ('Installation failed: ' + $_.Exception.Message)
  exit 1
}
"#;

/// Render the `.cmd` (CRLF line endings).
pub fn render(p: &ScriptParams) -> Result<String, String> {
    let host_char = |c: char| c.is_ascii_alphanumeric() || ".-:[]".contains(c);
    check("server address", p.server_addr, host_char)?;
    check("enrollment token", p.token, |c| {
        c.is_ascii_alphanumeric() || "-_".contains(c)
    })?;
    check("token prefix", p.token_prefix, |c| {
        c.is_ascii_alphanumeric() || "-_".contains(c)
    })?;
    check("MSI SHA-256", p.msi_sha256, |c| c.is_ascii_hexdigit())?;
    if p.msi_sha256.len() != 64 {
        return Err("MSI SHA-256 must be 64 hex digits".into());
    }
    if !p.msi_url.starts_with("https://") {
        return Err("the MSI URL must be https://".into());
    }
    check("MSI URL", p.msi_url, |c| {
        c.is_ascii_alphanumeric() || ".-_~:/[]".contains(c)
    })?;
    let ca_b64 = B64.encode(p.ca_pem.as_bytes());
    let expires = chrono::DateTime::from_timestamp_millis(p.expires_at)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "unknown".into());
    let ps = "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    let lines: Vec<String> = vec![
        "@echo off".into(),
        "rem ======================================================================".into(),
        "rem  Kestrel EDR agent installer (generated by the Kestrel server)".into(),
        format!("rem  Remote access profile: {}", comment_text(p.profile_summary)),
        format!("rem  Server:                {}", p.server_addr),
        format!("rem  Enrollment token:      {}... (expires {expires})", p.token_prefix),
        format!("rem  MSI SHA-256:           {}", p.msi_sha256.to_ascii_lowercase()),
        "rem  The remote-access profile is bound to the enrollment token on the".into(),
        "rem  server and pinned on the device at enrollment. The token below is".into(),
        "rem  the only secret in this file: treat the file like a password.".into(),
        "rem  The banner and notification shown during remote sessions cannot be".into(),
        "rem  turned off by any profile.".into(),
        "rem  Silent deployment (GPO, Intune, RMM, run as SYSTEM or admin):".into(),
        "rem    Install-Kestrel.cmd /quiet".into(),
        "rem ======================================================================".into(),
        "setlocal".into(),
        "set \"KESTREL_SELF=%~f0\"".into(),
        "net session >nul 2>&1".into(),
        "if errorlevel 1 goto :elevate".into(),
        format!("set \"KESTREL_SERVER={}\"", p.server_addr),
        format!("set \"KESTREL_TOKEN={}\"", p.token),
        format!("set \"KESTREL_CA_B64={ca_b64}\""),
        format!("set \"KESTREL_MSI_URL={}\"", p.msi_url),
        format!("set \"KESTREL_MSI_SHA256={}\"", p.msi_sha256.to_ascii_lowercase()),
        "echo Installing the Kestrel EDR agent...".into(),
        format!(
            "\"{ps}\" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {}",
            encode_ps(PS_SCRIPT)
        ),
        "set \"KESTREL_RC=%ERRORLEVEL%\"".into(),
        "echo Installer finished with exit code %KESTREL_RC%.".into(),
        // Silent deployment (GPO, Intune, RMM): `/quiet` never waits for a key.
        "if /i not \"%~1\"==\"/quiet\" pause".into(),
        "exit /b %KESTREL_RC%".into(),
        ":elevate".into(),
        "echo Administrator rights are required. Asking Windows to elevate...".into(),
        format!(
            "\"{ps}\" -NoProfile -NonInteractive -Command \"Start-Process -FilePath $env:KESTREL_SELF -Verb RunAs\""
        ),
        "if errorlevel 1 goto :noadmin".into(),
        "exit /b 0".into(),
        ":noadmin".into(),
        "echo Could not get administrator rights. Right-click this file and choose Run as administrator.".into(),
        "if /i not \"%~1\"==\"/quiet\" pause".into(),
        "exit /b 1".into(),
    ];
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "abababababababababababababababababababababababababababababababab";

    fn params<'a>(server: &'a str, url: &'a str) -> ScriptParams<'a> {
        ScriptParams {
            server_addr: server,
            token: "kte_abcDEF-123_x",
            token_prefix: "kte_abcDEF",
            expires_at: 1_800_000_000_000,
            ca_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            msi_url: url,
            msi_sha256: SHA,
            profile_summary: "Remote control + full file manager (no guardrails) & calc|x",
        }
    }

    #[test]
    fn renders_crlf_and_values() {
        let s = render(&params(
            "edr.acme.sg:8443",
            "https://edr.acme.sg/downloads/KestrelAgent.msi",
        ))
        .unwrap();
        assert!(s.contains("\r\n"));
        assert!(!s.replace("\r\n", "").contains('\n'));
        assert!(s.contains("set \"KESTREL_SERVER=edr.acme.sg:8443\""));
        assert!(s.contains("set \"KESTREL_TOKEN=kte_abcDEF-123_x\""));
        assert!(s.contains(&"ab".repeat(32)));
        assert!(s.contains(&B64.encode(params("a", "https://a/x").ca_pem.as_bytes())));
        // Free text is reduced to safe characters.
        let summary = s
            .lines()
            .find(|l| l.contains("Remote access profile"))
            .unwrap();
        assert!(
            !summary.contains('&') && !summary.contains('|'),
            "{summary}"
        );
        // The PowerShell round-trips through -EncodedCommand.
        let enc = encode_ps(PS_SCRIPT);
        let raw = B64.decode(enc).unwrap();
        let utf16: Vec<u16> = raw
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&utf16).unwrap(), PS_SCRIPT);
        // M6: protected download folder, hash through a share-read handle.
        assert!(PS_SCRIPT.contains("'/inheritance:r'"));
        assert!(
            PS_SCRIPT.contains("*S-1-5-18:(OI)(CI)F")
                && PS_SCRIPT.contains("*S-1-5-32-544:(OI)(CI)F")
        );
        assert!(PS_SCRIPT.contains("[System.IO.FileShare]::Read)"));
        let open = PS_SCRIPT.find("File]::Open(").unwrap();
        let start = PS_SCRIPT.find("Start-Process").unwrap();
        let dispose = PS_SCRIPT.rfind("$fs.Dispose()").unwrap();
        assert!(
            open < start && start < dispose,
            "handle held across msiexec"
        );
    }

    #[test]
    fn refuses_unsafe_values() {
        assert!(render(&params("evil&calc", "https://a/x")).is_err());
        assert!(render(&params("a:1", "https://a/x%TEMP%")).is_err());
        assert!(render(&params("a:1", "http://a/x")).is_err());
        assert!(render(&params("a:1", "https://a/x\"&calc")).is_err());
        let mut p = params("a:1", "https://a/x");
        p.msi_sha256 = "zz";
        assert!(render(&p).is_err());
    }
}
