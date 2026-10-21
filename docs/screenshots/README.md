# Screenshots

## Website / README images (`website/public/img/`)

Taken 2026-10-21 from the **mock** console (`VITE_MOCK=1 vite`, `?autologin=1`) and the **mock** tray
(`vite --mode mock`) with Playwright + Edge. No agent was run. Mock data: fictional org
"Harbourline Logistics" (console) and "Nusantara Logistik" (tray).

### Console — `website/public/img/console/<name>-dark.png` and `<name>-light.png`

1440 px wide, deviceScaleFactor 1. Height 900 unless noted.

| Name | Screen |
|---|---|
| `login` | Sign-in page (no autologin) |
| `overview` | Overview dashboard (full page, 1550 px) |
| `incidents` | Incident queue |
| `incident` | Ransomware incident on OPS-DT-009: summary, kill-chain, process tree, remediation checklist, alerts (full page, 2704 px) |
| `alerts` | Alerts grouped by rule |
| `devices` | Device list |
| `device` | Device detail SAL-LT-022: sensor health, device card, remote-access summary, event timeline (full page) |
| `device-remote-desktop` | Remote desktop tab, connected in control to the mock frame stream (1000 px) |
| `device-files` | Files tab browsing `C:\Users\diana.chong\Documents` (1000 px) |
| `hunt` | Hunt query for dead-drop domains (r2.dev / telegram / steamcommunity / discord / ip-api), 6 results |
| `response` | Response action log |
| `policies` | Policy list |
| `policy` | Policy editor (Default), detection rules section |
| `agent-updates` | Signed update rings and releases |
| `rules` | Rule catalog |
| `rule` | Built-in rule detail (RW-06 mass file encryption, with false positives and references) |
| `rule-sigma` | SigmaHQ rule detail (SIG-646ea171) showing authors and DRL 1.1 attribution |
| `exclusions` | Exclusions & IOCs |
| `quarantine` | Quarantine vault |
| `review-requests` | Employee review requests |
| `settings` | Settings → Enrollment (MSI, tokens, device groups) |
| `settings-users` | Users & roles |
| `settings-tokens` | API tokens |
| `settings-notifications` | Email / Slack / Teams notifications |
| `settings-sso` | Single sign-on (OIDC) |
| `settings-organisation` | Branding, privacy notice & retention |
| `settings-audit` | Hash-chained audit log |
| `install-wizard-1` | Install agent wizard: remote-access profile |
| `install-wizard-2` | Install agent wizard: guardrails (1000 px) |
| `install-wizard-3` | Install agent wizard: installer ready |

### Tray — `website/public/img/tray/`

420x600 (the window size in `tray/src-tauri/tauri.conf.json`), deviceScaleFactor 1.
Light is `<state>.png`, dark is `<state>-dark.png`.

| Name | Mock URL params | Screen |
|---|---|---|
| `status` | `state=protected` | You're protected |
| `blocked` | `state=attention` | Kestrel stopped some apps |
| `activity` | `tab=activity` | Activity feed (stopped / blocked / waiting for IT) |
| `help` | `tab=help` | Contact IT + what Kestrel records (privacy) |
| `remote-session` | `remote=control` | Banner while IT controls the screen |
| `consent` | `consent=desktop` | Allow / Deny prompt for an IT remote session |
| `offline` | `state=offline` | Protected, but not connected to IT |
| `real-desktop.png` | — | Copy of `docs/screenshots/lab-tray-employee.png` (real lab VM) |
| `real-remote-banner.png` | — | Copy of `docs/screenshots/lab-remote-desktop-employee-banner.png` (real lab VM) |

### Notes

* The remote-desktop canvas shows the mock's synthetic test-pattern desktop (that is what the mock
  frame stream renders), not a real Windows desktop; `real-remote-banner.png` is the real one.
* Known UI rough edges visible in the images (not retouched): on `response` at 1440 px the Device
  and Requested-by columns wrap and the last column is cut off at the right edge; on
  `settings-notifications` the "High and above" select text is clipped.

## Other files in this folder

`lab-*` are from a live server holding lab-VM data (`console/scripts/screenshots-lab.mjs`),
`real-*` from a real server after `scripts/e2e.sh` (`console/scripts/screenshots-real.mjs`), and the
remaining files from the mock (`console/scripts/screenshots.mjs`, `screenshots-remote.mjs`).
