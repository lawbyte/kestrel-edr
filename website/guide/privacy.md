# Privacy (PDPA and UU PDP)

Kestrel is built to be deployable under Singapore's Personal Data Protection Act (PDPA) and Indonesia's Personal Data Protection Law (UU PDP). Both allow monitoring of company devices, but they expect notice, purpose limitation and data minimisation, and UU PDP expects a data protection impact assessment (DPIA) for systematic monitoring. This page lists the controls Kestrel gives you; it is not legal advice.

## Where data lives

All telemetry, alerts and audit records stay on your own server (PostgreSQL and ClickHouse in your Docker Compose stack). Nothing is sent to a vendor cloud.

## What the agent collects

Detection runs on the device on full-fidelity events. What it watches:

* Process starts and stops, image loads, command lines, signer and hash of programs.
* Opens of sensitive files (browser credential stores, wallets, messenger and cloud credential files, decoys), not their contents.
* Network connections and DNS queries.
* Registry writes to autorun and security-relevant keys, scheduled tasks, services, WMI subscriptions.
* PowerShell script blocks and AMSI content.

It never captures keystrokes, screenshots or browsing history. Admin remote access is the one deliberate exception to "no screen capture": it is interactive, admin-initiated, limited by the device's install profile, visible to the employee and audited, and frames and file contents are never stored. See [Remote access](./remote-access).

## Upload controls (per policy)

The filters apply to what **leaves** the device. Alerts and their evidence are always uploaded.

| Control | Effect |
|---|---|
| Upload raw events for hunting | Off: only alerts and their evidence are uploaded. |
| Upload full command lines | Off: command lines are cut to the program and its flags. |
| Replace user names with a hash | User names become a stable salted pseudonym. The server applies the same to the signed-in user in health reports, review requests and alert process users. |
| Upload DNS queries | Off: no DNS telemetry. |
| Upload script content | Off: PowerShell and AMSI content is replaced by `[redacted]`. |
| Never upload paths under | Path prefixes (for example personal folders) are never uploaded; the event keeps its type and process. |

## Retention

Set under **Settings > Branding, privacy & retention > Data retention**. Defaults: events 30 days (7 days on the PostgreSQL fallback), alerts 365 days, audit log 730 days.

## Notice and transparency

* The tray app's **Help & privacy** tab shows the organisation's monitoring notice (Markdown, set per policy under **Branding & notice**) and a plain list of what Kestrel records and does not record.
* Write the notice to cover what is collected, why, how long it is kept, who can see it and whom to contact. Mention remote access if any profile allows it.
* Remote sessions always show a banner and a tray notification.

## Accountability

* Every analyst hunt query is written to the audit log, because hunting reads employee activity.
* Uninstall token reveals, response actions, policy changes and every remote-access session and file operation are in the hash-chained audit log.
* Use roles to limit who can hunt and who can act (see [Settings](../console/settings#users-and-roles)).

## Breach notification

Ransomware incidents add a manual checklist step to assess breach notification (PDPC within 3 days under PDPA, 3 x 24 hours under UU PDP). For stealer incidents the checklist assumes data may have left the device and lists what to rotate per data category; decide on notification with your data protection officer.
